/*
Copyright © The ESO Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"

// ThalassaAuth configures authentication with the Thalassa API.
// +kubebuilder:validation:MinProperties=1
// +kubebuilder:validation:MaxProperties=1
type ThalassaAuth struct {
	// AccessCredentials authenticates with Thalassa access credentials.
	// +optional
	AccessCredentials *ThalassaAccessCredentialsAuth `json:"accessCredentials,omitempty"`

	// JWT authenticates by exchanging a Kubernetes ServiceAccount token for a Thalassa access token.
	// +optional
	JWT *ThalassaJWTAuth `json:"jwt,omitempty"`
}

// ThalassaAccessCredentialsAuth authenticates with Thalassa access credentials.
type ThalassaAccessCredentialsAuth struct {
	// AccessKey is the access key identifier.
	AccessKey string `json:"accessKey"`

	// AccessSecretRef references the access secret.
	AccessSecretRef esmeta.SecretKeySelector `json:"accessSecretRef"`
}

// ThalassaJWTAuth authenticates using a Kubernetes ServiceAccount JWT token.
type ThalassaJWTAuth struct {
	// ThalassaServiceAccountID is the ID of the Thalassa service account to impersonate.
	ThalassaServiceAccountID string `json:"thalassaServiceAccountId"`

	// ServiceAccountRef specifies the Kubernetes ServiceAccount to use for authentication.
	ServiceAccountRef *esmeta.ServiceAccountSelector `json:"serviceAccountRef,omitempty"`
}

// ThalassaProvider defines the configuration for the Thalassa Secrets Manager provider.
type ThalassaProvider struct {
	// APIURL is the Thalassa API base URL. Defaults to https://api.thalassa.cloud
	// +optional
	APIURL string `json:"apiUrl,omitempty"`

	// Region where secrets are stored
	Region string `json:"region"`

	// OrganisationID is the Thalassa organisation ID.
	OrganisationID string `json:"organisationId"`

	// ProjectID is an optional Thalassa project scope. If not provided, will use organisation root.
	// +optional
	ProjectID string `json:"projectId,omitempty"`

	// KmsKeyID is the KMS key used when creating secrets via PushSecret.
	// +optional
	KmsKeyID string `json:"kmsKeyId,omitempty"`

	// Auth configures how the provider authenticates with Thalassa.
	Auth ThalassaAuth `json:"auth"`
}
