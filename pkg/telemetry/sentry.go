package telemetry

import (
	"github.com/kubeshark/utils/sentry"
	"github.com/rs/zerolog/log"
	v1 "k8s.io/api/core/v1"
)

var (
	SentryWriter *sentry.Writer
)

func EnsureSentry(cm *v1.ConfigMap) {
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
