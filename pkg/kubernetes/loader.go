package kubernetes

import (
	"github.com/rs/zerolog/log"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func NewFromInCluster(errOut chan error, callback func(pods []v1.Pod) error) *Watcher {
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Warn().Err(err).Send()
	}

	var clientSet *kubernetes.Clientset
	if config != nil {
		clientSet, err = kubernetes.NewForConfig(config)
		if err != nil {
			log.Warn().Err(err).Send()
		}
	}

	return &Watcher{
		clientConfig: config,
		clientSet:    clientSet,
		errOut:       errOut,
		callback:     callback,
	}
}
