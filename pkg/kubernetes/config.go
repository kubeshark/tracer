package kubernetes

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/dlclark/regexp2"
	"github.com/rs/zerolog/log"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	SUFFIX_CONFIG_MAP         = "config-map"
	CONFIG_POD_REGEX          = "POD_REGEX"
	CONFIG_NAMESPACES         = "NAMESPACES"
	CONFIG_DISSECTION_ENABLED = "DISSECTION_ENABLED"

	CONFIG_RAW_CAPTURE_ENABLED = "RAW_CAPTURE_ENABLED"
)

const (
	CONFIGURATION_FLAG_CAPTURE_ENABLED  = 1 << 0
	CONFIGURATION_FLAG_PASS_ALL_CGROUPS = 1 << 1
)

func SyncConfig(configMap *v1.ConfigMap) (*regexp2.Regexp, []string, uint32) {
	configPodRegex := configMap.Data[CONFIG_POD_REGEX]
	regex, err := regexp2.Compile(configPodRegex, regexp2.Multiline)
	if err != nil {
		log.Error().Err(err).Str("config", CONFIG_POD_REGEX).Send()
	}

	configNamespaces := configMap.Data[CONFIG_NAMESPACES]
	namespaces := strings.Split(configNamespaces, ",")

	var settings uint32
	dissectionEnabled := true
	rawCaptureEnabled := true
	if v, ok := configMap.Data[CONFIG_DISSECTION_ENABLED]; ok && v != "" {
		if parsed, err := strconv.ParseBool(v); err != nil {
			log.Warn().Err(err).Str("config", CONFIG_DISSECTION_ENABLED).Msg("invalid value, defaulting to true")
		} else {
			dissectionEnabled = parsed
		}
	} else {
		log.Warn().Str("config", CONFIG_DISSECTION_ENABLED).Msg("missing or empty, defaulting to true")
	}
	if v, ok := configMap.Data[CONFIG_RAW_CAPTURE_ENABLED]; ok && v != "" {
		if parsed, err := strconv.ParseBool(v); err != nil {
			log.Warn().Err(err).Str("config", CONFIG_RAW_CAPTURE_ENABLED).Msg("invalid value, defaulting to true")
		} else {
			rawCaptureEnabled = parsed
		}
	} else {
		log.Warn().Str("config", CONFIG_RAW_CAPTURE_ENABLED).Msg("missing or empty, defaulting to true")
	}
	if dissectionEnabled || rawCaptureEnabled {
		settings |= CONFIGURATION_FLAG_CAPTURE_ENABLED
	}

	return regex, namespaces, settings
}

func SetAllCgroupsOn(settings *uint32) {
	*settings |= CONFIGURATION_FLAG_PASS_ALL_CGROUPS
}

func SetAllCgroupsOff(settings *uint32) {
	*settings &^= CONFIGURATION_FLAG_PASS_ALL_CGROUPS
}

func GetThisNodeName(watcher *Watcher) (name string, err error) {
	if watcher.clientSet == nil {
		err = errors.New("K8s API is not available!")
		return name, err
	}

	pod, err := watcher.clientSet.CoreV1().Pods(GetSelfNamespace()).Get(context.TODO(), GetSelfPodName(), metav1.GetOptions{})
	if err != nil {
		return name, err
	}

	name = pod.Spec.NodeName
	return name, err
}
