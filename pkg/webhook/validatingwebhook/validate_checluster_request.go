package validatingwebhook

import (
	"context"
	"html"
	"io"
	"net/http"
	"strings"

	toolchainv1alpha1 "github.com/codeready-toolchain/api/api/v1alpha1"

	userv1 "github.com/openshift/api/user/v1"
	"github.com/pkg/errors"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/types"
	runtimeClient "sigs.k8s.io/controller-runtime/pkg/client"
)

type CheClusterRequestValidator struct {
	Client runtimeClient.Client
}

func (v CheClusterRequestValidator) HandleValidate(w http.ResponseWriter, r *http.Request) {
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

func (v CheClusterRequestValidator) validate(body []byte) []byte {
	log.Info("incoming request", "body", string(body))
	admReview := admissionv1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, &admReview); err != nil {
		// sanitize the body
		escapedBody := html.EscapeString(string(body))
		log.Error(err, "unable to deserialize the admission review object", "body", escapedBody)
		return denyAdmissionRequest(admReview, errors.Wrapf(err, "unable to deserialize the admission review object - body: %v", escapedBody))
	}
	requestingUsername := admReview.Request.UserInfo.Username
	// allow admission request if the user is a system user
	if strings.HasPrefix(requestingUsername, "system:") {
		return allowAdmissionRequest(admReview)
	}
	//check if the requesting user is a sandbox user
	requestingUser := &userv1.User{}
	err := v.Client.Get(context.TODO(), types.NamespacedName{
		Name: admReview.Request.UserInfo.Username,
	}, requestingUser)

	if err != nil {
		log.Error(err, "unable to find the user requesting creation of the"+admReview.Request.Kind.Kind+"resource", "username", admReview.Request.UserInfo.Username)
		return denyAdmissionRequest(admReview, errors.Errorf("unable to find the user requesting the  creation of the %s resource", admReview.Request.Kind.Kind))
	}
	if requestingUser.GetLabels()[toolchainv1alpha1.ProviderLabelKey] == toolchainv1alpha1.ProviderLabelValue {
		log.Info("sandbox user is trying to create a "+admReview.Request.Kind.Kind, "AdmissionReview", admReview)
		return denyAdmissionRequest(admReview, errors.Errorf("this is a Dev Sandbox enforced restriction. you are trying to create a %s resource, which is not allowed", admReview.Request.Kind.Kind))
	}
	// at this point, it is clear the user isn't a sandbox user, allow request
	return allowAdmissionRequest(admReview)
}
