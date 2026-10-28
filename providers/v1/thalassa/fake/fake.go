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

// Package fake provides an in-memory Thalassa secrets API for testing.
package fake

import (
	"context"
	"fmt"
	"sort"
	"strings"

	tclient "github.com/thalassa-cloud/client-go/pkg/client"
	"github.com/thalassa-cloud/client-go/secrets"
)

// Version holds a single secret version in the fake store.
type Version struct {
	Version int
	Data    []byte
	Status  string
}

// Secret holds a secret and its versions in the fake store.
type Secret struct {
	Path     string
	Labels   map[string]string
	Versions []*Version
}

// SecretStore implements the Thalassa secrets API backed by an in-memory store.
type SecretStore struct {
	secrets       []*Secret
	secretsByPath map[string]*Secret
}

// New builds a SecretStore from the given secrets, normalizing paths and filling defaults.
func New(fixtureSecrets []*Secret) *SecretStore {
	store := &SecretStore{
		secrets:       fixtureSecrets,
		secretsByPath: map[string]*Secret{},
	}

	for _, secret := range store.secrets {
		normalized, err := secrets.NormalizePath(secret.Path)
		if err != nil {
			panic(err)
		}
		secret.Path = normalized

		sort.Slice(secret.Versions, func(i, j int) bool {
			return secret.Versions[i].Version < secret.Versions[j].Version
		})

		for index, version := range secret.Versions {
			if version.Version != index+1 {
				panic("bad version number in fixtures")
			}
			if version.Status == "" {
				version.Status = "enabled"
			}
		}

		for _, version := range secret.Versions {
			if len(version.Data) == 0 {
				version.Data = fmt.Appendf(nil, "some data for secret %s version %d", secret.Path, version.Version)
			}
		}

		store.secretsByPath[secret.Path] = secret
	}

	return store
}

// Secret returns the secret at path, or nil when it does not exist.
func (s *SecretStore) Secret(path string) *Secret {
	normalized, err := secrets.NormalizePath(path)
	if err != nil {
		return nil
	}
	return s.secretsByPath[normalized]
}

func (secret *Secret) getVersion(version *int) (*Version, bool) {
	if len(secret.Versions) == 0 {
		return nil, false
	}

	if version == nil {
		return secret.Versions[len(secret.Versions)-1], true
	}

	for i := len(secret.Versions) - 1; i >= 0; i-- {
		if secret.Versions[i].Version == *version && secret.Versions[i].Status == "enabled" {
			return secret.Versions[i], true
		}
	}

	for _, candidate := range secret.Versions {
		if candidate.Version == *version {
			return candidate, true
		}
	}

	return nil, false
}

// MustGetVersion returns the requested version or panics when it does not exist.
func (secret *Secret) MustGetVersion(version *int) *Version {
	found, ok := secret.getVersion(version)
	if !ok {
		panic("no such version")
	}
	return found
}

func (s *SecretStore) BrowseSecrets(_ context.Context, _, path string) (*secrets.BrowseSecretsResponse, error) {
	normalized, err := secrets.NormalizePath(path)
	if err != nil {
		return nil, err
	}

	response := &secrets.BrowseSecretsResponse{Path: normalized}
	for _, secret := range s.secrets {
		if strings.HasPrefix(secret.Path, normalized) {
			response.Secrets = append(response.Secrets, secrets.Secret{
				Path:           secret.Path,
				CurrentVersion: len(secret.Versions),
				Labels:         secret.Labels,
			})
		}
	}
	return response, nil
}

func (s *SecretStore) ListSecrets(_ context.Context, _, pathPrefix string) ([]secrets.Secret, error) {
	normalized, err := secrets.NormalizePath(pathPrefix)
	if err != nil {
		return nil, err
	}

	var matches []secrets.Secret
	for _, secret := range s.secrets {
		if strings.HasPrefix(secret.Path, normalized) {
			matches = append(matches, secrets.Secret{
				Path:           secret.Path,
				CurrentVersion: len(secret.Versions),
				Labels:         secret.Labels,
			})
		}
	}
	return matches, nil
}

func (s *SecretStore) CreateSecret(_ context.Context, _ string, create secrets.CreateSecretRequest) (*secrets.Secret, error) {
	path, err := secrets.NormalizePath(create.Path)
	if err != nil {
		return nil, err
	}
	if _, exists := s.secretsByPath[path]; exists {
		return nil, tclient.ErrBadRequest
	}

	secret := &Secret{
		Path:   path,
		Labels: create.Labels,
	}
	if create.SecretString != "" {
		data, err := secrets.DecodeBytes("secretString", create.SecretString)
		if err != nil {
			return nil, err
		}
		secret.Versions = []*Version{{Version: 1, Data: data}}
	}

	s.secrets = append(s.secrets, secret)
	s.secretsByPath[path] = secret

	return &secrets.Secret{
		Path:           path,
		CurrentVersion: len(secret.Versions),
		Labels:         secret.Labels,
	}, nil
}

func (s *SecretStore) GetSecret(_ context.Context, _, path string, includeVersions bool) (*secrets.Secret, error) {
	secret, ok := s.secretsByPath[path]
	if !ok {
		return nil, tclient.ErrNotFound
	}

	result := &secrets.Secret{
		Path:           secret.Path,
		CurrentVersion: len(secret.Versions),
		Labels:         secret.Labels,
	}
	if includeVersions {
		for _, version := range secret.Versions {
			result.Versions = append(result.Versions, secrets.SecretVersion{
				Version: version.Version,
				Status:  version.Status,
			})
		}
	}
	return result, nil
}

func (s *SecretStore) DeleteSecret(_ context.Context, _, path string) error {
	secret, ok := s.secretsByPath[path]
	if !ok {
		return tclient.ErrNotFound
	}

	delete(s.secretsByPath, path)
	for i, candidate := range s.secrets {
		if candidate == secret {
			s.secrets = append(s.secrets[:i], s.secrets[i+1:]...)
			break
		}
	}
	return nil
}

func (s *SecretStore) PutSecretString(_ context.Context, _, path string, plaintext []byte) (*secrets.PutSecretValueResponse, error) {
	secret, ok := s.secretsByPath[path]
	if !ok {
		return nil, tclient.ErrNotFound
	}

	newVersion := len(secret.Versions) + 1
	secret.Versions = append(secret.Versions, &Version{
		Version: newVersion,
		Data:    append([]byte(nil), plaintext...),
	})

	return &secrets.PutSecretValueResponse{
		Path:    path,
		Version: newVersion,
	}, nil
}

func (s *SecretStore) GetSecretString(_ context.Context, _, path string, version *int) ([]byte, int, error) {
	secret, ok := s.secretsByPath[path]
	if !ok {
		return nil, 0, tclient.ErrNotFound
	}

	found, ok := secret.getVersion(version)
	if !ok {
		return nil, 0, tclient.ErrNotFound
	}

	return append([]byte(nil), found.Data...), found.Version, nil
}
