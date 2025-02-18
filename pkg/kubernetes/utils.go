package kubernetes

import (
	"context"
	"os"
	"strings"

	"github.com/kubeshark/utils/sentry"
	"github.com/rs/zerolog/log"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	SELF_RESOURCES_PREFIX = "kubeshark-"
	defaultNamespace      = "default"
	allNamespaces         = ""
)

var (
	SentryWriter *sentry.Writer
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

// GetClusterID returns the UID field of the `kube-system` namespace object
// This is used as a unique identifier for the cluster
func GetClusterID(watcher *Watcher) (string, error) {

	namespaceObj, err := watcher.clientSet.CoreV1().Namespaces().Get(context.Background(), "kube-system", metav1.GetOptions{})
	if err != nil {
		return "", err
	}

	return string(namespaceObj.GetUID()), nil
}

func ensureSentry(cm *v1.ConfigMap) {
	if SentryWriter.IsActive() {
		return
	}

	sentryActive, ok := cm.Data[sentry.SENTRY_ACTIVE]
	if !ok {
		return
	}

	if sentryActive == "true" {
		email, ok := cm.Data[sentry.SENTRY_EMAIL]
		if !ok {
			email = "unknown"
		}
		clusterId, ok := cm.Data[sentry.SENTRY_CLUSTER_ID]
		if !ok {
			clusterId = "unknown"
		}

		tags := map[string]string{
			"clusterID": clusterId,
			"email":     email,
		}

		sentry.AddTags(tags)

		log.Debug().Str("clusterID", clusterId).Str("email", email).Msg("Sentry tags added")

		log.Debug().Str(sentry.SENTRY_ACTIVE, "true").Str(sentry.SENTRY_EMAIL, email).Str(sentry.SENTRY_CLUSTER_ID, clusterId).
			Msg("Setting sentry configs")

		SentryWriter.Activate()
	}
}
