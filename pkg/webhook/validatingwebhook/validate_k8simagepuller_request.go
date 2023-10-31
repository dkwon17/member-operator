package validatingwebhook

import (
	"io"
	"net/http"

	runtimeClient "sigs.k8s.io/controller-runtime/pkg/client"
)

type K8sImagePullerRequestValidator struct {
	Client runtimeClient.Client
}

func (v K8sImagePullerRequestValidator) HandleValidate(w http.ResponseWriter, r *http.Request) {
	var respBody []byte
	body, err := io.ReadAll(r.Body)
	defer func() {
		if err := r.Body.Close(); err != nil {
			log.Error(err, "unable to close the body")
		}
	}()
	if err != nil {
		log.Error(err, "unable to read the body of the request")
		w.WriteHeader(http.StatusInternalServerError)
		respBody = []byte("unable to read the body of the request")
	} else {
		// validate the request
		respBody = v.validate(body)
		w.WriteHeader(http.StatusOK)
	}
	if _, err := io.WriteString(w, string(respBody)); err != nil {
		log.Error(err, "unable to write response")
	}
}

func (v K8sImagePullerRequestValidator) validate(body []byte) []byte {
	log.Info("incoming request", "body", string(body))
	return allowIfNonSandboxUser(body, &v.Client)
}
