package kubernetes

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	SUFFIX_CONFIG_MAP = "config-map"
	CONFIG_POD_REGEX  = "POD_REGEX"
	CONFIG_NAMESPACES = "NAMESPACES"
	CONFIG_BPF_OVERRIDE = "BPF_OVERRIDE"
)

func SyncConfig(configMap *v1.ConfigMap) (*regexp.Regexp, []string, string) {
	configPodRegex := configMap.Data[CONFIG_POD_REGEX]
	regex, err := regexp.Compile(configPodRegex)
	if err != nil {
		log.Error().Err(err).Str("config", CONFIG_POD_REGEX).Send()
	}

	configNamespaces := configMap.Data[CONFIG_NAMESPACES]
	namespaces := strings.Split(configNamespaces, ",")
	bpfOverride := configMap.Data[CONFIG_BPF_OVERRIDE]

	return regex, namespaces, bpfOverride
}

func GetThisNodeName(watcher *Watcher) (name string, err error) {
	if watcher.clientSet == nil {
		err = errors.New("K8s API is not available!")
		return
	}

	pod, err := watcher.clientSet.CoreV1().Pods(GetSelfNamespace()).Get(context.TODO(), GetSelfPodName(), metav1.GetOptions{})
	if err != nil {
		return
	}

	name = pod.Spec.NodeName
	return
}
