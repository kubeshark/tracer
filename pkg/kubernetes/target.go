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

func GetTargetedPods() []v1.Pod {
	return targetedPods
}

func SetTargetedPods(pods []v1.Pod) {
	targetedPods = pods
}

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

//returns pods present in pods1 array and missing in pods2 array
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

func updateCurrentlyTargetedPods(
	ctx context.Context,
	clientSet *kubernetes.Clientset,
	regex *regexp.Regexp,
	namespaces []string,
	callback func(pods []v1.Pod) error,
) (err error) {
	var matchingPods []v1.Pod
	if matchingPods, err = listAllRunningPodsMatchingRegex(ctx, clientSet, regex, namespaces); err != nil {
		return
	}

	podsToTarget := excludeSelfPods(matchingPods)
	addedPods, removedPods := getPodArrayDiff(GetTargetedPods(), podsToTarget)
	for _, addedPod := range addedPods {
		log.Info().Msg(fmt.Sprintf("Targeted pod: %s", fmt.Sprintf(Green, addedPod.Name)))
	}
	for _, removedPod := range removedPods {
		log.Info().Msg(fmt.Sprintf("Untargeted pod: %s", fmt.Sprintf(Red, removedPod.Name)))
	}

	if len(addedPods) > 0 || len(removedPods) > 0 {
		SetTargetedPods(podsToTarget)
		err = callback(podsToTarget)
	}

	return
}
