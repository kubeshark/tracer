package kubernetes

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"time"

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

type callbackPodsChanged func(addPods []*v1.Pod, removePods []*v1.Pod, excludedPods []*v1.Pod, settings uint32) error

func getPodArrayDiff(oldPods []*v1.Pod, newPods []*v1.Pod) (added []*v1.Pod, removed []*v1.Pod) {
	added = getMissingPods(newPods, oldPods)
	removed = getMissingPods(oldPods, newPods)

	return added, removed
}

// returns pods present in pods1 array and missing in pods2 array
func getMissingPods(pods1 []*v1.Pod, pods2 []*v1.Pod) []*v1.Pod {
	missingPods := make([]*v1.Pod, 0)
	for _, pod1 := range pods1 {
		found := false
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

	newAllTargetPods, excludedPods, targetingEnabled, err := getAllTargetPodsFromHub()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get all targeted pods")
	}

	if !targetingEnabled {
		SetAllCgroupsOn(&settings)
	} else {
		SetAllCgroupsOff(&settings)
	}

	if !targetingEnabled {
		log.Info().Msg("Targeting is disabled, watch all pods")

		err = callback(nil, nil, excludedPods, settings)
		return err
	}

	newSelectedTargetPods, _, _, err := getSelectedTargetedPodsFromHub()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get selected targeted pods")
	}

	addedTargetedPods, removedTargetedPods := getPodArrayDiff(GetSelectedTargetPods(), newSelectedTargetPods)

	SetAllTargetPods(newAllTargetPods)
	SetSelectedTargetPods(newSelectedTargetPods)

	err = callback(addedTargetedPods, removedTargetedPods, excludedPods, settings)

	return err
}

func getAllTargetPodsFromHub() (targetPods, excludedPods []*v1.Pod, targetingEnabled bool, err error) {
	return getTargetPodsFromHub(allTargetPodsEndpoint)
}

func getSelectedTargetedPodsFromHub() (targetPods, excludedPods []*v1.Pod, targetingEnabled bool, err error) {
	return getTargetPodsFromHub(selectedTargetPodsEndpoint)
}

func getTargetPodsFromHub(endpoint string) (targetPods, excludedPods []*v1.Pod, targetingEnabled bool, err error) {
	url := hubAddr + endpoint

	var content []byte

	jitter := time.Duration(rand.Intn(requestJitterIntervalMs)) * time.Millisecond
	time.Sleep(jitter)

	log.Debug().Str("url", url).Msg("Retrieving target pods from the hub")

	retryClient := retryablehttp.NewClient()
	retryClient.Logger = nil
	req, err := retryablehttp.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, false, fmt.Errorf("failed to make GET build request on url=%s: %w",
			url, err)
	}
	req.Header.Set("X-Kubeshark-Capture", "ignore")

	log.Debug().Str("url", url).Msg("Retrieving target pods from the hub")

	res, err := retryClient.Do(req)
	if err != nil {
		return nil, nil, false, fmt.Errorf("failed to make GET request on url=%s: %w",
			url, err)
	}

	defer res.Body.Close()
	content, err = io.ReadAll(res.Body)
	if err != nil {
		return nil, nil, false, fmt.Errorf("failed reading the response body from url=%s: %w",
			url, err)
	}

	if content == nil {
		return nil, nil, false, fmt.Errorf("failed to get response after retries on url=%s: %w",
			url, err)
	}

	type targetPodsResponse struct {
		TargetingEnabled bool      `json:"targetingEnabled"`
		TargetPods       []*v1.Pod `json:"targets"`
		ExcludedPods     []*v1.Pod `json:"excluded"`
	}

	var data targetPodsResponse
	err = json.Unmarshal(content, &data)
	if err != nil {
		log.Warn().Str("url", url).Err(err).Msg("Failed unmarshalling list of target pods:")
		return nil, nil, false, fmt.Errorf("failed unmarshalling list of target pod from url=%s: %w",
			url, err)
	}
	targetingEnabled = data.TargetingEnabled
	targetPods = data.TargetPods
	excludedPods = data.ExcludedPods

	return targetPods, excludedPods, targetingEnabled, err
}
