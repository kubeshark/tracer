package kubernetes

import (
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
	v1 "k8s.io/api/core/v1"
)

const (
	SUFFIX_CONFIG_MAP = "config-map"
	CONFIG_POD_REGEX  = "POD_REGEX"
	CONFIG_NAMESPACES = "NAMESPACES"
)

func SyncConfig(configMap *v1.ConfigMap) (*regexp.Regexp, []string) {
	configPodRegex := configMap.Data[CONFIG_POD_REGEX]
	regex, err := regexp.Compile(configPodRegex)
	if err != nil {
		log.Error().Err(err).Str("config", CONFIG_POD_REGEX).Send()
	}

	configNamespaces := configMap.Data[CONFIG_NAMESPACES]
	namespaces := strings.Split(configNamespaces, ",")

	return regex, namespaces
}
