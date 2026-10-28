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
	"fmt"
	"strings"

	tclient "github.com/thalassa-cloud/client-go/pkg/client"
	tapi "github.com/thalassa-cloud/client-go/thalassa"
	kubeClient "sigs.k8s.io/controller-runtime/pkg/client"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
	"github.com/external-secrets/external-secrets/runtime/esutils"
	"github.com/external-secrets/external-secrets/runtime/esutils/resolvers"
)

const (
	userAgent = "external-secrets"
)

func defaultOIDCTokenURL(baseURL string) string {
	return strings.TrimSuffix(strings.TrimSpace(baseURL), "/") + "/oidc/token"
}

type authConfig struct {
	subjectToken string
}

func buildClientOptions(ctx context.Context, cfg *esv1.ThalassaProvider, kube kubeClient.Client, namespace, storeKind string, auth authConfig) ([]tclient.Option, error) {
	baseURL := cfg.APIURL
	if baseURL == "" {
		baseURL = defaultAPIURL
	}

	opts := []tclient.Option{
		tclient.WithBaseURL(baseURL),
		tclient.WithOrganisation(strings.TrimSpace(cfg.OrganisationID)),
		tclient.WithUserAgent(userAgent),
	}
	if project := strings.TrimSpace(cfg.ProjectID); project != "" {
		opts = append(opts, tclient.WithProject(project))
	}

	tokenURL := defaultOIDCTokenURL(baseURL)

	switch {
	case cfg.Auth.JWT != nil:
		jwtAuth := cfg.Auth.JWT
		subjectToken := auth.subjectToken
		if subjectToken == "" {
			return nil, fmt.Errorf("jwt auth requires a subject token")
		}
		opts = append(opts, tclient.WithAuthOIDCTokenExchange(tclient.OIDCTokenExchangeConfig{
			TokenURL:         tokenURL,
			SubjectToken:     subjectToken,
			OrganisationID:   strings.TrimSpace(cfg.OrganisationID),
			ServiceAccountID: strings.TrimSpace(jwtAuth.ThalassaServiceAccountID),
		}))
	case cfg.Auth.AccessCredentials != nil:
		creds := cfg.Auth.AccessCredentials
		secret, err := resolvers.SecretKeyRef(ctx, kube, storeKind, namespace, &creds.AccessSecretRef)
		if err != nil {
			return nil, err
		}
		opts = append(opts, tclient.WithAuthOIDC(creds.AccessKey, secret, tokenURL))
	default:
		return nil, fmt.Errorf("thalassa auth requires accessCredentials or jwt")
	}

	return opts, nil
}

func resolveAuthConfig(ctx context.Context, cfg *esv1.ThalassaProvider, store esv1.GenericStore, namespace string) (authConfig, error) {
	if cfg.Auth.JWT == nil {
		return authConfig{}, nil
	}

	jwtAuth := cfg.Auth.JWT
	if jwtAuth.ServiceAccountRef == nil {
		return authConfig{}, fmt.Errorf("jwt requires serviceAccountRef")
	}
	if err := esutils.ValidateServiceAccountSelector(store, *jwtAuth.ServiceAccountRef); err != nil {
		return authConfig{}, err
	}

	tokenNamespace := serviceAccountTokenNamespace(store.GetKind(), *jwtAuth.ServiceAccountRef, namespace)
	token, err := esutils.FetchServiceAccountToken(ctx, *jwtAuth.ServiceAccountRef, tokenNamespace)
	if err != nil {
		return authConfig{}, err
	}
	return authConfig{subjectToken: token}, nil
}

// serviceAccountTokenNamespace resolves which namespace to mint the ServiceAccount
// token in. For ClusterSecretStore, an explicit serviceAccountRef.namespace takes
// precedence over the ExternalSecret namespace (same pattern as AWS/OIDC helpers).
func serviceAccountTokenNamespace(storeKind string, saRef esmeta.ServiceAccountSelector, esNamespace string) string {
	if storeKind == esv1.ClusterSecretStoreKind && saRef.Namespace != nil {
		return *saRef.Namespace
	}
	return esNamespace
}

func newThalassaClient(ctx context.Context, cfg *esv1.ThalassaProvider, store esv1.GenericStore, kube kubeClient.Client, namespace, storeKind string) (tapi.Client, error) {
	auth, err := resolveAuthConfig(ctx, cfg, store, namespace)
	if err != nil {
		return nil, err
	}

	opts, err := buildClientOptions(ctx, cfg, kube, namespace, storeKind, auth)
	if err != nil {
		return nil, err
	}

	return tapi.NewClient(opts...)
}
