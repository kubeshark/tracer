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
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
)

type Watcher struct {
	clientConfig *restclient.Config
	clientSet    *kubernetes.Clientset
	regex        *regexp.Regexp
	namespaces   []string
	isStarted    bool
	errOut       chan error
	callback     func(pods []v1.Pod) error
}

func (watcher *Watcher) Start(ctx context.Context, clusterMode bool) {
	if !watcher.isStarted {
		watcher.isStarted = true

		if clusterMode {
			go watcher.infiniteErrorHandleRetryFunc(ctx, watcher.watchConfigMap)
			go watcher.infiniteErrorHandleRetryFunc(ctx, watcher.watchPods)
		}
	}
}

func (watcher *Watcher) watchConfigMap(ctx context.Context) error {
	w, err := watcher.clientSet.CoreV1().ConfigMaps(GetSelfNamespace()).Watch(ctx, metav1.ListOptions{
		Watch:         true,
		FieldSelector: fields.OneTermEqualSelector(metav1.ObjectNameField, "kubeshark-config-map").String(),
	})
	if err != nil {
		return err
	}

	for {
		select {
		case event := <-w.ResultChan():
			if event.Object == nil {
				return errors.New("error in kubectl endpoint watch")
			}
			watcher.regex, watcher.namespaces = SyncConfig(event.Object.(*v1.ConfigMap))

			err, _ = updateCurrentlyTargetedPods(ctx, watcher.clientSet, watcher.regex, watcher.namespaces, watcher.callback)
			if err != nil {
				log.Error().Err(err).Send()
			}
		case <-ctx.Done():
			w.Stop()
			return nil
		}
	}
}

func (watcher *Watcher) watchPods(ctx context.Context) error {
	// empty namespace makes the client watch all namespaces
	kubesharkLabels := map[string]string{"app.kubernetes.io/name": "kubeshark"}
	w, err := watcher.clientSet.CoreV1().Pods(allNamespaces).Watch(ctx, metav1.ListOptions{Watch: true})
	if err != nil {
		w, err = watcher.clientSet.CoreV1().Pods(GetSelfNamespace()).Watch(ctx, metav1.ListOptions{Watch: true})
		if err != nil {
			return err
		}
	}
	if err != nil {
		return err
	}
	for {
		select {
		case event := <-w.ResultChan():
			if event.Object == nil {
				return errors.New("error in kubectl pod watch")
			}

			pod := event.Object.(*v1.Pod)
			if mapsContain(pod.ObjectMeta.Labels, kubesharkLabels) {
				// ignore kubeshark pods
				continue
			}

			log.Debug().Str("event", string(event.Type)).Str("pod-name", pod.Name).Str("namespace", pod.Namespace).Send()

			err, _ = updateCurrentlyTargetedPods(ctx, watcher.clientSet, watcher.regex, watcher.namespaces, watcher.callback)
			if err != nil {
				log.Error().Err(err).Send()
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
