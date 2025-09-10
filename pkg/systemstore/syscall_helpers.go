package systemstore

import (
	raw "github.com/kubeshark/api2/pkg/proto/raw_capture"
	"google.golang.org/protobuf/proto"
)

// EnqueueSyscall marshals and enqueues a syscall event to the writer.
func EnqueueSyscall(ev *raw.SyscallEvent) {
	w := GetManager().Ensure("syscall_events", SyscallBaseDir(), true, 0, 0, 0, TTLPolicyUnspecified)

	b, err := proto.Marshal(ev)
	if err != nil {
		return
	}

	w.WriteProtoLengthPrefixed(b)
}
