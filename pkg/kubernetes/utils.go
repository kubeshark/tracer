package kubernetes

import (
	"os"
	"strings"
)

const (
	SELF_RESOURCES_PREFIX = "kubeshark-"
	defaultNamespace      = "default"
	allNamespaces         = ""
)

func GetSelfNamespace() string {
	// This way assumes you've set the POD_NAMESPACE environment variable using the downward API.
	// This check has to be done first for backwards compatibility with the way InClusterConfig was originally set up
	if namespace, ok := os.LookupEnv("POD_NAMESPACE"); ok {
		return namespace
	}

	// Fall back to the namespace associated with the service account token, if available
	if data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		if namespace := strings.TrimSpace(string(data)); len(namespace) > 0 {
			return namespace
		}
	}

	return defaultNamespace
}

func GetSelfPodName() string {
	// This way assumes you've set the POD_NAME environment variable using the downward API.
	// This check has to be done first for backwards compatibility with the way InClusterConfig was originally set up
	if name, ok := os.LookupEnv("POD_NAME"); ok {
		return name
	}
	return ""
}

func mapsContain(m1, m2 map[string]string) bool {
	for key, value := range m2 {
		if m1Value, found := m1[key]; !found || m1Value != value {
			return false
		}
	}
	return true
}
