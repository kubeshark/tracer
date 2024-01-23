package kubernetes

import (
	"context"
	"errors"
	"regexp"

	"github.com/rs/zerolog/log"
	v1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
)

const (
	kubesharkConfigmapName    = "kubeshark-config-map"
	resolverHistoryAnnotation = "resolver.kubeshark.io/history"
)

type Watcher struct {
	clientConfig  *restclient.Config
	clientSet     *kubernetes.Clientset
	regex         *regexp.Regexp
	namespaces    []string
	isStarted     bool
	lastUpdatedAt string
	errOut        chan error
	callback      func(pods []v1.Pod) error
}

func (watcher *Watcher) Start(ctx context.Context, clusterMode bool) {
	if !watcher.isStarted {
		watcher.isStarted = true

		if clusterMode {
			go watcher.infiniteErrorHandleRetryFunc(ctx, watcher.watchKubesharkConfigMap)
		}
	}
}

func (watcher *Watcher) watchKubesharkConfigMap(ctx context.Context) error {
	w, err := watcher.clientSet.CoreV1().ConfigMaps(GetSelfNamespace()).Watch(ctx, metav1.ListOptions{
		Watch:         true,
		FieldSelector: fields.OneTermEqualSelector(metav1.ObjectNameField, kubesharkConfigmapName).String(),
	})
	if err != nil {
		return err
	}

	for {
		select {
		case event := <-w.ResultChan():
			if event.Object == nil {
				return errors.New("error in kubeshark configmap watch")
			}
			if watcher.isHistoryUpdated(&event) {
				watcher.regex, watcher.namespaces = SyncConfig(event.Object.(*v1.ConfigMap))

				err = updateCurrentlyTargetedPods(ctx, watcher.clientSet, watcher.regex, watcher.namespaces, watcher.callback)
				if err != nil {
					log.Error().Err(err).Send()
				}
				watcher.lastUpdatedAt = event.Object.(*v1.ConfigMap).ObjectMeta.Annotations[resolverHistoryAnnotation]
			}
		case <-ctx.Done():
			w.Stop()
			return nil
		}
	}
}

func (watcher *Watcher) infiniteErrorHandleRetryFunc(ctx context.Context, fun func(ctx context.Context) error) {
	for {
		err := fun(ctx)
		if err != nil {
			watcher.errOut <- err

			var statusError *k8serrors.StatusError
			if errors.As(err, &statusError) {
				if statusError.ErrStatus.Reason == metav1.StatusReasonForbidden {
					log.Warn().Err(err).Msg("Watcher loop encountered permission error, aborting event listening...")
					return
				}
			}
		}
		if ctx.Err() != nil { // context was cancelled or errored
			return
		}
	}
}

func (watcher *Watcher) isHistoryUpdated(event *watch.Event) bool {
	cm := event.Object.(*v1.ConfigMap)
	currentUpdatedAt := cm.ObjectMeta.Annotations[resolverHistoryAnnotation]

	if watcher.lastUpdatedAt != currentUpdatedAt || currentUpdatedAt == "" {
		return true
	}

	return false
}
