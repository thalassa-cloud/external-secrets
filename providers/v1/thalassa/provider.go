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

package thalassa

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	ctrl "sigs.k8s.io/controller-runtime"
	kubeClient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/runtime/esutils"
)

var (
	defaultAPIURL = "https://api.thalassa.cloud"
	log           = ctrl.Log.WithName("provider").WithName("thalassa")
)

var _ esv1.Provider = &Provider{}

// Provider is a Thalassa Cloud provider implementation that satisfies the esv1.Provider interface.
type Provider struct{}

// NewProvider creates a new Provider instance.
func NewProvider() esv1.Provider {
	return &Provider{}
}

// ProviderSpec returns the provider specification for registration.
func ProviderSpec() *esv1.SecretStoreProvider {
	return &esv1.SecretStoreProvider{
		Thalassa: &esv1.ThalassaProvider{},
	}
}

// MaintenanceStatus returns the maintenance status of the provider.
func MaintenanceStatus() esv1.MaintenanceStatus {
	return esv1.MaintenanceStatusMaintained
}

// Capabilities return the provider supported capabilities (ReadOnly, WriteOnly, ReadWrite).
func (p *Provider) Capabilities() esv1.SecretStoreCapabilities {
	return esv1.SecretStoreReadWrite
}

// NewClient creates a new secrets client based on provided store.
func (p *Provider) NewClient(ctx context.Context, store esv1.GenericStore, kube kubeClient.Client, namespace string) (esv1.SecretsClient, error) {
	cfg, err := getConfig(store)
	if err != nil {
		return nil, err
	}

	if store.GetKind() == esv1.ClusterSecretStoreKind && doesConfigDependOnNamespace(cfg) {
		return nil, errors.New("when using a ClusterSecretStore, namespaces must be explicitly set")
	}

	tc, err := newThalassaClient(ctx, cfg, store, kube, namespace, store.GetKind())
	if err != nil {
		return nil, err
	}

	return &client{
		api:      tc.Secrets(),
		region:   cfg.Region,
		kmsKeyId: cfg.KmsKeyID,
		cache:    newCache(),
	}, nil
}

func doesConfigDependOnNamespace(cfg *esv1.ThalassaProvider) bool {
	if cfg.Auth.AccessCredentials != nil {
		if cfg.Auth.AccessCredentials.AccessSecretRef.Namespace == nil {
			return true
		}
	}

	if cfg.Auth.JWT != nil {
		if cfg.Auth.JWT.ServiceAccountRef != nil && cfg.Auth.JWT.ServiceAccountRef.Namespace == nil {
			return true
		}
	}

	return false
}

func getConfig(store esv1.GenericStore) (*esv1.ThalassaProvider, error) {
	if store == nil {
		return nil, errors.New("missing store specification")
	}
	storeSpec := store.GetSpec()

	if storeSpec == nil || storeSpec.Provider == nil || storeSpec.Provider.Thalassa == nil {
		return nil, errors.New("invalid specification for thalassa provider")
	}
	cfg := storeSpec.Provider.Thalassa

	if cfg.APIURL == "" {
		cfg.APIURL = defaultAPIURL
	} else if _, err := url.ParseRequestURI(cfg.APIURL); err != nil {
		return nil, fmt.Errorf("invalid api url: %q", cfg.APIURL)
	}

	if strings.TrimSpace(cfg.Region) == "" {
		return nil, errors.New("region is required")
	}

	if strings.TrimSpace(cfg.OrganisationID) == "" {
		return nil, errors.New("organisationId is required")
	}

	switch {
	case cfg.Auth.AccessCredentials != nil:
		if strings.TrimSpace(cfg.Auth.AccessCredentials.AccessKey) == "" {
			return nil, errors.New("accessCredentials.accessKey is required")
		}
		if err := esutils.ValidateReferentSecretSelector(store, cfg.Auth.AccessCredentials.AccessSecretRef); err != nil {
			return nil, err
		}
	case cfg.Auth.JWT != nil:
		jwtAuth := cfg.Auth.JWT
		if strings.TrimSpace(jwtAuth.ThalassaServiceAccountID) == "" {
			return nil, errors.New("jwt.thalassaServiceAccountId is required")
		}
		if jwtAuth.ServiceAccountRef == nil {
			return nil, errors.New("jwt.serviceAccountRef is required")
		}
		if err := esutils.ValidateServiceAccountSelector(store, *jwtAuth.ServiceAccountRef); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("missing or invalid auth method")
	}
	return cfg, nil
}

// ValidateStore validates the store's configuration.
func (p *Provider) ValidateStore(store esv1.GenericStore) (admission.Warnings, error) {
	_, err := getConfig(store)
	return nil, err
}
