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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
)

func TestProviderCapabilities(t *testing.T) {
	p := &Provider{}
	assert.Equal(t, esv1.SecretStoreReadWrite, p.Capabilities())
}

func TestValidateStore(t *testing.T) {
	validAccessCredentialsAuth := esv1.ThalassaAuth{
		AccessCredentials: &esv1.ThalassaAccessCredentialsAuth{
			AccessKey: "access-key",
			AccessSecretRef: esmeta.SecretKeySelector{
				Name: "creds",
				Key:  "accessSecret",
			},
		},
	}

	tests := map[string]struct {
		store esv1.GenericStore
		want  error
	}{
		"missing provider": {
			store: &esv1.SecretStore{
				Spec: esv1.SecretStoreSpec{
					Provider: &esv1.SecretStoreProvider{},
				},
			},
			want: errors.New("invalid specification for thalassa provider"),
		},
		"missing region": {
			store: newTestStore(esv1.ThalassaProvider{
				OrganisationID: "o-abc1234",
				Auth:           validAccessCredentialsAuth,
			}),
			want: errors.New("region is required"),
		},
		"missing organisation": {
			store: newTestStore(esv1.ThalassaProvider{
				Region: "nl-01",
				Auth:   validAccessCredentialsAuth,
			}),
			want: errors.New("organisationId is required"),
		},
		"missing auth method": {
			store: newTestStore(esv1.ThalassaProvider{
				Region:         "nl-01",
				OrganisationID: "o-abc1234",
			}),
			want: errors.New("missing or invalid auth method"),
		},
		"access credentials missing access key": {
			store: newTestStore(esv1.ThalassaProvider{
				Region:         "nl-01",
				OrganisationID: "o-abc1234",
				Auth: esv1.ThalassaAuth{
					AccessCredentials: &esv1.ThalassaAccessCredentialsAuth{
						AccessSecretRef: esmeta.SecretKeySelector{
							Name: "secret",
							Key:  "key",
						},
					},
				},
			}),
			want: errors.New("accessCredentials.accessKey is required"),
		},
		"jwt missing service account ref": {
			store: newTestStore(esv1.ThalassaProvider{
				Region:         "nl-01",
				OrganisationID: "o-abc1234",
				Auth: esv1.ThalassaAuth{
					JWT: &esv1.ThalassaJWTAuth{
						ThalassaServiceAccountID: "sa-abc1234",
					},
				},
			}),
			want: errors.New("jwt.serviceAccountRef is required"),
		},
		"jwt missing thalassa service account id": {
			store: newTestStore(esv1.ThalassaProvider{
				Region:         "nl-01",
				OrganisationID: "o-abc1234",
				Auth: esv1.ThalassaAuth{
					JWT: &esv1.ThalassaJWTAuth{
						ServiceAccountRef: &esmeta.ServiceAccountSelector{
							Name: "external-secrets",
						},
					},
				},
			}),
			want: errors.New("jwt.thalassaServiceAccountId is required"),
		},
		"disallowed namespace in secret store ref": {
			store: newTestStore(esv1.ThalassaProvider{
				Region:         "nl-01",
				OrganisationID: "o-abc1234",
				Auth: esv1.ThalassaAuth{
					AccessCredentials: &esv1.ThalassaAccessCredentialsAuth{
						AccessKey: "access-key",
						AccessSecretRef: esmeta.SecretKeySelector{
							Name:      "creds",
							Key:       "accessSecret",
							Namespace: new("other"),
						},
					},
				},
			}),
			want: errors.New("namespace should either be empty or match the namespace of the SecretStore for a namespaced SecretStore"),
		},
		"valid access credentials auth": {
			store: newTestStore(esv1.ThalassaProvider{
				Region:         "nl-01",
				OrganisationID: "o-abc1234",
				Auth:           validAccessCredentialsAuth,
			}),
			want: nil,
		},
		"cluster secret store jwt without namespace": {
			store: newTestClusterStore(esv1.ThalassaProvider{
				Region:         "nl-01",
				OrganisationID: "o-abc1234",
				Auth: esv1.ThalassaAuth{
					JWT: &esv1.ThalassaJWTAuth{
						ThalassaServiceAccountID: "sa-abc1234",
						ServiceAccountRef: &esmeta.ServiceAccountSelector{
							Name: "external-secrets",
						},
					},
				},
			}),
			want: errors.New("cluster scope requires namespace"),
		},
		"cluster secret store jwt with namespace": {
			store: newTestClusterStore(esv1.ThalassaProvider{
				Region:         "nl-01",
				OrganisationID: "o-abc1234",
				Auth: esv1.ThalassaAuth{
					JWT: &esv1.ThalassaJWTAuth{
						ThalassaServiceAccountID: "sa-abc1234",
						ServiceAccountRef: &esmeta.ServiceAccountSelector{
							Name:      "external-secrets",
							Namespace: new("external-secrets"),
						},
					},
				},
			}),
			want: nil,
		},
		"cluster secret store access credentials without namespace is valid at admission": {
			store: newTestClusterStore(esv1.ThalassaProvider{
				Region:         "nl-01",
				OrganisationID: "o-abc1234",
				Auth: esv1.ThalassaAuth{
					AccessCredentials: &esv1.ThalassaAccessCredentialsAuth{
						AccessKey: "access-key",
						AccessSecretRef: esmeta.SecretKeySelector{
							Name: "creds",
							Key:  "accessSecret",
						},
					},
				},
			}),
			want: nil,
		},
		"cluster secret store access credentials with namespace": {
			store: newTestClusterStore(esv1.ThalassaProvider{
				Region:         "nl-01",
				OrganisationID: "o-abc1234",
				Auth: esv1.ThalassaAuth{
					AccessCredentials: &esv1.ThalassaAccessCredentialsAuth{
						AccessKey: "access-key",
						AccessSecretRef: esmeta.SecretKeySelector{
							Name:      "creds",
							Key:       "accessSecret",
							Namespace: new("external-secrets"),
						},
					},
				},
			}),
			want: nil,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			p := &Provider{}
			_, got := p.ValidateStore(tc.store)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestDoesConfigDependOnNamespace(t *testing.T) {
	tests := map[string]struct {
		cfg  esv1.ThalassaProvider
		want bool
	}{
		"access credentials without namespace": {
			cfg: esv1.ThalassaProvider{
				Auth: esv1.ThalassaAuth{
					AccessCredentials: &esv1.ThalassaAccessCredentialsAuth{
						AccessKey: "key",
						AccessSecretRef: esmeta.SecretKeySelector{
							Name: "creds",
							Key:  "accessSecret",
						},
					},
				},
			},
			want: true,
		},
		"access credentials with namespace": {
			cfg: esv1.ThalassaProvider{
				Auth: esv1.ThalassaAuth{
					AccessCredentials: &esv1.ThalassaAccessCredentialsAuth{
						AccessKey: "key",
						AccessSecretRef: esmeta.SecretKeySelector{
							Name:      "creds",
							Key:       "accessSecret",
							Namespace: new("external-secrets"),
						},
					},
				},
			},
			want: false,
		},
		"jwt without namespace": {
			cfg: esv1.ThalassaProvider{
				Auth: esv1.ThalassaAuth{
					JWT: &esv1.ThalassaJWTAuth{
						ThalassaServiceAccountID: "sa-1",
						ServiceAccountRef: &esmeta.ServiceAccountSelector{
							Name: "external-secrets",
						},
					},
				},
			},
			want: true,
		},
		"jwt with namespace": {
			cfg: esv1.ThalassaProvider{
				Auth: esv1.ThalassaAuth{
					JWT: &esv1.ThalassaJWTAuth{
						ThalassaServiceAccountID: "sa-1",
						ServiceAccountRef: &esmeta.ServiceAccountSelector{
							Name:      "external-secrets",
							Namespace: new("external-secrets"),
						},
					},
				},
			},
			want: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, doesConfigDependOnNamespace(&tc.cfg))
		})
	}
}

func TestNewClientClusterSecretStoreRequiresNamespace(t *testing.T) {
	p := &Provider{}
	store := newTestClusterStore(esv1.ThalassaProvider{
		Region:         "nl-01",
		OrganisationID: "o-abc1234",
		Auth: esv1.ThalassaAuth{
			AccessCredentials: &esv1.ThalassaAccessCredentialsAuth{
				AccessKey: "key",
				AccessSecretRef: esmeta.SecretKeySelector{
					Name: "creds",
					Key:  "accessSecret",
				},
			},
		},
	})

	_, err := p.NewClient(context.Background(), store, nil, "app")
	require.Error(t, err)
	assert.Equal(t, "when using a ClusterSecretStore, namespaces must be explicitly set", err.Error())
}

func TestServiceAccountTokenNamespace(t *testing.T) {
	tests := map[string]struct {
		storeKind   string
		saRef       esmeta.ServiceAccountSelector
		esNamespace string
		want        string
	}{
		"secret store uses external secret namespace": {
			storeKind:   esv1.SecretStoreKind,
			saRef:       esmeta.ServiceAccountSelector{Name: "sa"},
			esNamespace: "app",
			want:        "app",
		},
		"secret store ignores explicit namespace on ref for token minting input": {
			storeKind: esv1.SecretStoreKind,
			saRef: esmeta.ServiceAccountSelector{
				Name:      "sa",
				Namespace: new("other"),
			},
			esNamespace: "app",
			want:        "app",
		},
		"cluster secret store uses service account namespace": {
			storeKind: esv1.ClusterSecretStoreKind,
			saRef: esmeta.ServiceAccountSelector{
				Name:      "sa",
				Namespace: new("external-secrets"),
			},
			esNamespace: "app",
			want:        "external-secrets",
		},
		"cluster secret store without namespace falls back to external secret namespace": {
			storeKind:   esv1.ClusterSecretStoreKind,
			saRef:       esmeta.ServiceAccountSelector{Name: "sa"},
			esNamespace: "app",
			want:        "app",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := serviceAccountTokenNamespace(tc.storeKind, tc.saRef, tc.esNamespace)
			assert.Equal(t, tc.want, got)
		})
	}
}

func newTestStore(cfg esv1.ThalassaProvider) esv1.GenericStore {
	return &esv1.SecretStore{
		TypeMeta: metav1.TypeMeta{
			Kind: esv1.SecretStoreKind,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "thalassa-store",
			Namespace: "default",
		},
		Spec: esv1.SecretStoreSpec{
			Provider: &esv1.SecretStoreProvider{
				Thalassa: &cfg,
			},
		},
	}
}

func newTestClusterStore(cfg esv1.ThalassaProvider) esv1.GenericStore {
	return &esv1.ClusterSecretStore{
		TypeMeta: metav1.TypeMeta{
			Kind: esv1.ClusterSecretStoreKind,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "thalassa-cluster-store",
		},
		Spec: esv1.SecretStoreSpec{
			Provider: &esv1.SecretStoreProvider{
				Thalassa: &cfg,
			},
		},
	}
}
