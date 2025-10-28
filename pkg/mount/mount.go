// borrowed from tracee
package mount

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rs/zerolog/log"
	"golang.org/x/exp/slices"

	errfmt "github.com/kubeshark/tracer/pkg/utils"
)

// Constants

const (
	procMounts      = "self/mountinfo"
	procFilesystems = "filesystems"
	tmpPathPrefix   = "kubeshark"
)

//
// MountHostOnce
//

// MountHostOnce will make sure a given source and filesystem type are mounted just
// once: it will check if given source and fs type are already mounted, and given
// from the host filesystem, and if not, it will mount it (in a temporary directory)
// and manage it (umounting at its destruction). If already mounted, the filesystem
// is left untouched at object's destruction.
type MountHostOnce struct {
	procfs  string
	source  string
	target  string
	fsType  string
	data    string
	managed bool
	mounted bool
}

func NewMountHostOnce(procfs, source, fstype, data, where string) (*MountHostOnce, error) {
	m := &MountHostOnce{
		procfs: procfs,
		source: source, // device and/or pseudo-filesystem to mount
		fsType: fstype, // fs type
		data:   data,   // extra data
	}

	// already mounted filesystems will be like mounted ones, but un-managed
	var alreadyMounted bool
	var err error
	alreadyMounted, err = m.isMountedByOS(where)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	if !alreadyMounted {
		err = m.Mount()
		if err != nil {
			return nil, errfmt.WrapError(err)
		}
		m.managed = true // managed by this object
	}

	m.mounted = true
	log.Info().Bool("managed", m.managed).Str("source", m.source).Str("target", m.target).Str("fstype", m.fsType).Str("data", m.data).Bool("already mounted", alreadyMounted).Msg("created mount object")

	return m, nil
}

func (m *MountHostOnce) Mount() error {
	path, err := os.MkdirTemp(os.TempDir(), tmpPathPrefix) // create temp dir
	if err != nil {
		return errfmt.WrapError(err)
	}
	// Ensure the temp directory has owner write permissions regardless of umask
	if fi, statErr := os.Stat(path); statErr != nil {
		log.Warn().Str("path", path).Msg("failed to stat temp directory")
	} else {
		mode := fi.Mode()
		newMode := mode | 0o200 // ensure owner write bit
		if newMode != mode {
			if chmodErr := os.Chmod(path, newMode); chmodErr != nil {
				log.Warn().Str("path", path).Msg("failed to chmod temp directory")
			}
		}
	}
	mp, err := filepath.Abs(path) // pick mountpoint path
	if err != nil {
		return errfmt.WrapError(err)
	}

	m.target = mp

	// mount the filesystem to the target dir
	err = syscall.Mount(m.fsType, m.target, m.fsType, 0, m.data)
	if err != nil {
		// remove created target directory on errors
		empty, _ := isDirEmpty(m.target)
		if empty {
			errRA := os.RemoveAll(m.target) // best effort for cleanup
			if errRA != nil {
				log.Error().Msg(fmt.Sprintf("Removing all error: %v", errRA))
			}
		}
	}

	return errfmt.WrapError(err)
}

func (m *MountHostOnce) Umount() error {
	if m.managed && m.mounted {
		// umount the filesystem from the target dir

		err := syscall.Unmount(m.target, 0)
		if err != nil {
			return errfmt.WrapError(err)
		}

		m.mounted = false
		m.managed = false

		// check if target dir is empty before removing it
		empty, err := isDirEmpty(m.target)
		if err != nil {
			return errfmt.WrapError(err)
		}
		if !empty {
			return UnmountedDirNotEmpty(m.target)
		}

		// remove target dir (cleanup)
		return os.RemoveAll(m.target)
	}

	return nil
}

func (m *MountHostOnce) IsMounted() bool {
	return m.mounted
}

func (m *MountHostOnce) GetMountpoint() string {
	return m.target
}

// private

func (m *MountHostOnce) isMountedByOS(where string) (bool, error) {
	var err error
	var mp string
	mp, err = SearchMountpointFromHost(m.procfs, m.fsType, m.data)
	if err != nil {
		return false, errfmt.WrapError(err)
	}
	if mp == "" {
		return false, nil
		// return false, fmt.Errorf("mount point not found")
	}
	if where != "" && !strings.Contains(mp, where) {
		return false, nil
	}

	m.target = mp // replace given target dir with existing mountpoint
	m.mounted = true
	m.managed = false // proforma

	return true, nil
}

//
// General
//

// IsFileSystemSupported checks if given fs is supported by the running kernel
func IsFileSystemSupported(procfs, fsType string) (bool, error) {
	file, err := os.Open(filepath.Join(procfs, procFilesystems))
	if err != nil {
		return false, CouldNotOpenFile(filepath.Join(procfs, procFilesystems), err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Error().Msg(fmt.Sprintf("Closing file: error: %v", err))
		}
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.Fields(scanner.Text())
		last := line[len(line)-1]
		if last == fsType {
			return true, nil
		}
	}

	return false, nil
}

// SearchMountpointFromHost returns the last mountpoint for a given filesystem type
// containing a searchable string. It confirms the mount originates from the root file
// system.
func SearchMountpointFromHost(procfs, fstype string, search string) (string, error) {
	mp := ""

	file, err := os.Open(filepath.Join(procfs, procMounts))
	if err != nil {
		return "", errfmt.WrapError(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Error().Msg(fmt.Sprintf("Closing file: error: %v", err))
		}
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.Split(scanner.Text(), " ")
		mountRoot := line[3]
		mountpoint := line[4]
		sepIndex := slices.Index(line, "-")
		fsTypeIndex := sepIndex + 1
		currFstype := line[fsTypeIndex]
		// Check for the following 3 conditions:
		// 1. The fs type is the one we search for
		// 2. The mountpoint contains the path we are searching
		// 3. The root path in the mounted filesystem is that of the host.
		//	  This means, that the root of the mounted filesystem is /.
		//    For example, if we are searching for /sys/fs/cgroup, we want to
		//    be sure that it is not actually .../sys/fs/cgroup, but strictly
		//    the searched path.
		if fstype == currFstype && strings.Contains(mountpoint, search) && mountRoot == "/" {
			mp = mountpoint
			break
		}
	}

	return mp, nil
}

func isDirEmpty(pathname string) (bool, error) {
	dir, err := os.Open(pathname)
	if err != nil {
		return false, errfmt.WrapError(err)
	}
	defer func() {
		if err := dir.Close(); err != nil {
			log.Error().Msg(fmt.Sprintf("Closing file: error: %v", err))
		}
	}()

	_, err = dir.Readdirnames(1)
	if err == io.EOF {
		return true, nil
	}

	return false, errfmt.WrapError(err)
}
