package kubernetes

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"time"

	"errors"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/rs/zerolog/log"
	v1 "k8s.io/api/core/v1"
)

const (
	hubAddr                    = "http://kubeshark-hub:80"
	allTargetPodsEndpoint      = "/pods/all"
	selectedTargetPodsEndpoint = "/pods/targeted"
	requestJitterIntervalMs    = 2000
)

var (
	allTargetPods      []*v1.Pod // allTargetedPods
	selectedTargetPods []*v1.Pod // selectedTargetedPods
)

func GetSelectedTargetPods() []*v1.Pod {
	return selectedTargetPods
}

func GetAllTargetPods() []*v1.Pod {
	return allTargetPods
}

func SetAllTargetPods(pods []*v1.Pod) {
	allTargetPods = pods
}

func SetSelectedTargetPods(pods []*v1.Pod) {
	selectedTargetPods = pods
}

type callbackPodsChanged func(addPods []*v1.Pod, removePods []*v1.Pod, settings uint32) error

func getPodArrayDiff(oldPods []*v1.Pod, newPods []*v1.Pod) (added []*v1.Pod, removed []*v1.Pod) {
	added = getMissingPods(newPods, oldPods)
	removed = getMissingPods(oldPods, newPods)

	return added, removed
}

// returns pods present in pods1 array and missing in pods2 array
func getMissingPods(pods1 []*v1.Pod, pods2 []*v1.Pod) []*v1.Pod {
	missingPods := make([]*v1.Pod, 0)
	for _, pod1 := range pods1 {
		var found = false
		for _, pod2 := range pods2 {
			if pod1.UID == pod2.UID {
				found = true
				break
			}
		}
		if !found {
			missingPods = append(missingPods, pod1)
		}
	}
	return missingPods
}

func updateCurrentlyTargetedPods(
	callback callbackPodsChanged,
	settings uint32,
) (err error) {

	newAllTargetPods, noPods, err := getAllTargetPodsFromHub()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get all targeted pods")
	}

	if noPods {
		SetAllCgroupsOn(&settings)
	} else {
		SetAllCgroupsOff(&settings)
	}

	if noPods {
		log.Info().Msg("No pods found")
		err = callback(nil, nil, settings)
		return
	}

	newSelectedTargetPods, noPods, err := getSelectedTargetedPodsFromHub()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get selected targeted pods")
	}
	if noPods {
		err = errors.New("Received unexpected 'no targeted pods'")
		return
	}

	addedTargetedPods, removedTargetedPods := getPodArrayDiff(GetSelectedTargetPods(), newSelectedTargetPods)

	SetAllTargetPods(newAllTargetPods)
	SetSelectedTargetPods(newSelectedTargetPods)

	err = callback(addedTargetedPods, removedTargetedPods, settings)

	return
}

func getAllTargetPodsFromHub() (targetPods []*v1.Pod, noPods bool, err error) {
	return getTargetPodsFromHub(allTargetPodsEndpoint)
}

func getSelectedTargetedPodsFromHub() (targetPods []*v1.Pod, noPods bool, err error) {
	return getTargetPodsFromHub(selectedTargetPodsEndpoint)
}

func getTargetPodsFromHub(endpoint string) (targetPods []*v1.Pod, noPods bool, err error) {

	url := hubAddr + endpoint

	var content []byte

	jitter := time.Duration(rand.Intn(requestJitterIntervalMs)) * time.Millisecond
	time.Sleep(jitter)

	log.Debug().Str("url", url).Msg("Retrieving target pods from the hub")

	retryClient := retryablehttp.NewClient()
	req, err := retryablehttp.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, false, fmt.Errorf("failed to make GET build request on url=%s: %w",
			url, err)
	}
	req.Header.Set("X-Kubeshark-Capture", "ignore")

	res, err := retryClient.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("failed to make GET request on url=%s: %w",
			url, err)
	}

	defer res.Body.Close()
	content, err = io.ReadAll(res.Body)
	if err != nil {
		return nil, false, fmt.Errorf("failed reading the response body from url=%s: %w",
			url, err)
	}

	if content == nil {
		return nil, false, fmt.Errorf("failed to get response after retries on url=%s: %w",
			url, err)
	}

	type targetPodsResponse struct {
		NoPods     bool      `json:"nopods"`
		TargetPods []*v1.Pod `json:"targets"`
	}

	var data targetPodsResponse
	err = json.Unmarshal(content, &data)
	if err != nil {
		log.Warn().Str("url", url).Err(err).Msg("Failed unmarshalling list of target pods:")
		return nil, false, fmt.Errorf("failed unmarshalling list of target pod from url=%s: %w",
			url, err)
	}
	noPods = data.NoPods
	targetPods = data.TargetPods

	return
}
