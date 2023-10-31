package validatingwebhook

import (
	"context"
	"encoding/json"
	"html"
	"strings"

	toolchainv1alpha1 "github.com/codeready-toolchain/api/api/v1alpha1"
	userv1 "github.com/openshift/api/user/v1"
	"github.com/pkg/errors"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	runtimeClient "sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecs.UniversalDeserializer()

	log = logf.Log.WithName("validating_webhook")
)

func allowIfNonSandboxUser(body []byte, client *runtimeClient.Client) []byte {
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
	err := (*client).Get(context.TODO(), types.NamespacedName{
		Name: admReview.Request.UserInfo.Username,
	}, requestingUser)

	if err != nil {
		log.Error(err, "unable to find the user requesting creation of the", admReview.Request.Kind.Kind, "resource", "username", admReview.Request.UserInfo.Username)
		return denyAdmissionRequest(admReview, errors.Errorf("unable to find the user requesting the creation of the %s resource", admReview.Request.Kind.Kind))
	}
	if requestingUser.GetLabels()[toolchainv1alpha1.ProviderLabelKey] == toolchainv1alpha1.ProviderLabelValue {
		log.Info("sandbox user is trying to create a", admReview.Request.Kind.Kind, "AdmissionReview", admReview)
		return denyAdmissionRequest(admReview, errors.Errorf("this is a Dev Sandbox enforced restriction. you are trying to create a %s resource, which is not allowed", admReview.Request.Kind.Kind))
	}
	// at this point, it is clear the user isn't a sandbox user, allow request
	return allowAdmissionRequest(admReview)
}

func denyAdmissionRequest(admReview admissionv1.AdmissionReview, err error) []byte {
	response := &admissionv1.AdmissionResponse{
		Allowed: false,
		Result: &metav1.Status{
			Message: err.Error(),
		},
	}
	if admReview.Request != nil {
		response.UID = admReview.Request.UID
	}
	admReview.Response = response
	responseBody, err := json.Marshal(admReview)
	if err != nil {
		log.Error(err, "unable to marshal the admission review with response", "admissionReview", admReview)
		return []byte("unable to marshal the admission review with response")
	}
	return responseBody
}

func allowAdmissionRequest(admReview admissionv1.AdmissionReview) []byte {
	resp := &admissionv1.AdmissionResponse{
		Allowed: true,
		UID:     admReview.Request.UID,
	}
	admReview.Response = resp
	responseBody, err := json.Marshal(admReview)
	if err != nil {
		log.Error(err, "unable to marshal the admission review with response", "admissionReview", admReview)
		return []byte("unable to marshal the admission review with response")
	}
	return responseBody
}
