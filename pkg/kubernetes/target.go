package kubernetes

import (
	"context"
	"fmt"
	"regexp"

	"github.com/rs/zerolog/log"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var targetedPods []v1.Pod

var watchedPods []v1.Pod

func GetTargetedPods() []v1.Pod {
	return targetedPods
}

func GetWatchedPods() []v1.Pod {
	return watchedPods
}

func SetTargetedPods(pods []v1.Pod) {
	targetedPods = pods
}

func SetWatchedPods(pods []v1.Pod) {
	watchedPods = pods
}

type callbackPodsChanged func(addedWatchedPods []v1.Pod, removedWatchedPods []v1.Pod, addedTargetedPods []v1.Pod, removedTargetedPods []v1.Pod) error

func excludeSelfPods(pods []v1.Pod) []v1.Pod {
	kubesharkLabels := map[string]string{"app.kubernetes.io/name": "kubeshark"}

	nonSelfPods := make([]v1.Pod, 0)
	for _, pod := range pods {
		if mapsContain(pod.ObjectMeta.Labels, kubesharkLabels) {
			// ignore kubeshark pods
			continue
		}
		nonSelfPods = append(nonSelfPods, pod)
	}

	return nonSelfPods
}

func getPodArrayDiff(oldPods []v1.Pod, newPods []v1.Pod) (added []v1.Pod, removed []v1.Pod) {
	added = getMissingPods(newPods, oldPods)
	removed = getMissingPods(oldPods, newPods)

	return added, removed
}

// returns pods present in pods1 array and missing in pods2 array
func getMissingPods(pods1 []v1.Pod, pods2 []v1.Pod) []v1.Pod {
	missingPods := make([]v1.Pod, 0)
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

func IsPodRunning(pod *v1.Pod) bool {
	return pod.Status.Phase == v1.PodRunning
}

func listPodsImpl(ctx context.Context, clientSet *kubernetes.Clientset, regex *regexp.Regexp, namespaces []string, listOptions metav1.ListOptions) ([]v1.Pod, error) {
	var pods []v1.Pod
	for _, namespace := range namespaces {
		namespacePods, err := clientSet.CoreV1().Pods(namespace).List(ctx, listOptions)
		if err != nil {
			return nil, fmt.Errorf("failed to get pods in ns: [%s], %w", namespace, err)
		}

		pods = append(pods, namespacePods.Items...)
	}

	matchingPods := make([]v1.Pod, 0)
	for _, pod := range pods {
		if regex.MatchString(pod.Name) {
			matchingPods = append(matchingPods, pod)
		}
	}
	return matchingPods, nil
}

func listAllPodsMatchingRegex(ctx context.Context, clientSet *kubernetes.Clientset, regex *regexp.Regexp, namespaces []string) ([]v1.Pod, error) {
	return listPodsImpl(ctx, clientSet, regex, namespaces, metav1.ListOptions{})
}

func listAllRunningPodsMatchingRegex(ctx context.Context, clientSet *kubernetes.Clientset, regex *regexp.Regexp, namespaces []string) ([]v1.Pod, error) {
	pods, err := listAllPodsMatchingRegex(ctx, clientSet, regex, namespaces)
	if err != nil {
		return nil, err
	}

	matchingPods := make([]v1.Pod, 0)
	for _, pod := range pods {
		if IsPodRunning(&pod) {
			matchingPods = append(matchingPods, pod)
		}
	}
	return matchingPods, nil
}

var regexAllPods = regexp.MustCompile(`.*`)

func updateCurrentlyTargetedPods(
	ctx context.Context,
	clientSet *kubernetes.Clientset,
	regex *regexp.Regexp,
	namespaces []string,
	callback callbackPodsChanged,
) (err error) {

	var allPods []v1.Pod
	if allPods, err = listAllRunningPodsMatchingRegex(ctx, clientSet, regexAllPods, namespaces); err != nil {
		return
	}
	podsToWatch := excludeSelfPods(allPods)

	var matchingPods []v1.Pod
	if matchingPods, err = listAllRunningPodsMatchingRegex(ctx, clientSet, regex, namespaces); err != nil {
		return
	}

	podsToTarget := excludeSelfPods(matchingPods)
	addedTargetedPods, removedTargetedPods := getPodArrayDiff(GetTargetedPods(), podsToTarget)
	addedWatchedPods, removedWatchedPods := getPodArrayDiff(GetWatchedPods(), podsToWatch)

	for _, addedPod := range addedWatchedPods {
		log.Info().Msg(fmt.Sprintf("Watched pod: %s", fmt.Sprintf(Green, addedPod.Name)))
	}
	for _, removedPod := range removedWatchedPods {
		log.Info().Msg(fmt.Sprintf("Unwatchted pod: %s", fmt.Sprintf(Red, removedPod.Name)))
	}
	for _, addedPod := range addedTargetedPods {
		log.Info().Msg(fmt.Sprintf("Targeted pod: %s", fmt.Sprintf(Green, addedPod.Name)))
	}
	for _, removedPod := range removedTargetedPods {
		log.Info().Msg(fmt.Sprintf("Untargeted pod: %s", fmt.Sprintf(Red, removedPod.Name)))
	}

	SetTargetedPods(podsToTarget)
	SetWatchedPods(podsToWatch)
	err = callback(addedWatchedPods, removedWatchedPods, addedTargetedPods, removedTargetedPods)

	return
}
