package kubernetes

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/kubeshark/api"
	"github.com/rs/zerolog/log"
)

const (
	hubAddr                    = "http://kubeshark-hub:80"
	allTargetPodsEndpoint      = "/pods/all"
	selectedTargetPodsEndpoint = "/pods/targeted"
	requestJitterIntervalMs    = 2000
)

var (
	allTargetPods      []api.TargetPod // allTargetedPods
	selectedTargetPods []api.TargetPod // selectedTargetedPods
)

func GetSelectedTargetPods() []api.TargetPod {
	return selectedTargetPods
}

func GetAllTargetPods() []api.TargetPod {
	return allTargetPods
}

func SetAllTargetPods(pods []api.TargetPod) {
	allTargetPods = pods
}

func SetSelectedTargetPods(pods []api.TargetPod) {
	selectedTargetPods = pods
}

type callbackPodsChanged func(addedallTargetedPods []api.TargetPod, removedallTargetedPods []api.TargetPod, addedselectedTargetedPods []api.TargetPod, removedselectedTargetedPods []api.TargetPod, settings uint32) error

func getPodArrayDiff(oldPods []api.TargetPod, newPods []api.TargetPod) (added []api.TargetPod, removed []api.TargetPod) {
	added = getMissingPods(newPods, oldPods)
	removed = getMissingPods(oldPods, newPods)

	return added, removed
}

// returns pods present in pods1 array and missing in pods2 array
func getMissingPods(pods1 []api.TargetPod, pods2 []api.TargetPod) []api.TargetPod {
	missingPods := make([]api.TargetPod, 0)
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

	newAllTargetPods, err := getAllTargetPodsFromHub()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get all targeted pods")
	}

	newSelectedTargetPods, err := getSelectedTargetedPodsFromHub()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get selected targeted pods")
	}

	addedWatchedPods, removedWatchedPods := getPodArrayDiff(GetAllTargetPods(), newAllTargetPods)
	addedTargetedPods, removedTargetedPods := getPodArrayDiff(GetSelectedTargetPods(), newSelectedTargetPods)

	SetAllTargetPods(newAllTargetPods)
	SetSelectedTargetPods(newSelectedTargetPods)

	err = callback(addedWatchedPods, removedWatchedPods, addedTargetedPods, removedTargetedPods, settings)

	return
}

func getAllTargetPodsFromHub() (targetPods []api.TargetPod, err error) {
	return getTargetPodsFromHub(allTargetPodsEndpoint)
}

func getSelectedTargetedPodsFromHub() (targetPods []api.TargetPod, err error) {
	return getTargetPodsFromHub(selectedTargetPodsEndpoint)
}

func getTargetPodsFromHub(endpoint string) (targetPods []api.TargetPod, err error) {

	url := hubAddr + endpoint

	var content []byte

	jitter := time.Duration(rand.Intn(requestJitterIntervalMs)) * time.Millisecond
	time.Sleep(jitter)

	log.Debug().Str("url", url).Msg("Retrieving target pods from the hub")

	retryClient := retryablehttp.NewClient()
	req, err := retryablehttp.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make GET build request on url=%s: %w",
			url, err)
	}
	req.Header.Set("X-Kubeshark-Capture", "ignore")

	res, err := retryClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make GET request on url=%s: %w",
			url, err)
	}

	defer res.Body.Close()
	content, err = io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed reading the response body from url=%s: %w",
			url, err)
	}

	if content == nil {
		return nil, fmt.Errorf("failed to get response after retries on url=%s: %w",
			url, err)
	}

	type targetPodsResponse struct {
		TargetPods []api.TargetPod `json:"targets"`
	}

	var data targetPodsResponse
	err = json.Unmarshal(content, &data)
	if err != nil {
		log.Warn().Str("url", url).Err(err).Msg("Failed unmarshalling list of target pods:")
		return nil, fmt.Errorf("failed unmarshalling list of target pod from url=%s: %w",
			url, err)
	}

	return data.TargetPods, nil
}
