package kubernetes

import (
	"context"
	"errors"
	"strings"

	"github.com/dlclark/regexp2"
	"github.com/rs/zerolog/log"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	SUFFIX_CONFIG_MAP = "config-map"
	CONFIG_POD_REGEX  = "POD_REGEX"
	CONFIG_NAMESPACES = "NAMESPACES"
)

func SyncConfig(configMap *v1.ConfigMap) (*regexp2.Regexp, []string) {
	configPodRegex := configMap.Data[CONFIG_POD_REGEX]
	regex, err := regexp2.Compile(configPodRegex, regexp2.Multiline)
	if err != nil {
		log.Error().Err(err).Str("config", CONFIG_POD_REGEX).Send()
	}

	configNamespaces := configMap.Data[CONFIG_NAMESPACES]
	namespaces := strings.Split(configNamespaces, ",")

	return regex, namespaces
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
