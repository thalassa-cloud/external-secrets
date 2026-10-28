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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"

	tclient "github.com/thalassa-cloud/client-go/pkg/client"
	"github.com/thalassa-cloud/client-go/secrets"
	"github.com/tidwall/gjson"
	corev1 "k8s.io/api/core/v1"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/runtime/find"
)

type client struct {
	api      secretAPI
	region   string
	kmsKeyId string
	cache    *secretCache
}

func (c *client) GetSecret(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) ([]byte, error) {
	secretPath, err := normalizeSecretPath(ref.Key)
	if err != nil {
		return nil, err
	}

	version, err := parseVersion(ref.Version)
	if err != nil {
		return nil, err
	}

	value, _, err := c.accessSecretValue(ctx, secretPath, version)
	if err != nil {
		if tclient.IsNotFound(err) {
			return nil, esv1.NoSecretError{}
		}
		return nil, err
	}

	if ref.Property != "" {
		extracted, err := extractJSONProperty(value, ref.Property)
		if err != nil {
			return nil, err
		}

		value = extracted
	}

	return value, nil
}

func (c *client) PushSecret(ctx context.Context, secret *corev1.Secret, data esv1.PushSecretData) error {
	if data.GetSecretKey() == "" {
		return errors.New("pushing the whole secret is not yet implemented")
	}

	if c.kmsKeyId == "" {
		return errors.New("kmsKeyId must be configured on the SecretStore to push secrets")
	}

	value := secret.Data[data.GetSecretKey()]
	secretPath, err := normalizeSecretPath(data.GetRemoteKey())
	if err != nil {
		return err
	}

	existingSecret, err := c.api.GetSecret(ctx, c.region, secretPath, false)
	if err != nil {
		if !tclient.IsNotFound(err) {
			return err
		}

		_, err = c.api.CreateSecret(ctx, c.region, secrets.CreateSecretRequest{
			Path:           secretPath,
			KmsKeyIdentity: c.kmsKeyId,
			SecretString:   secrets.EncodeBytes(value),
		})
		return err
	}

	if existingSecret.KmsKey != nil && existingSecret.KmsKey.Identity != c.kmsKeyId {
		return errors.New("kmsKeyId mismatch")
	}

	current, _, err := c.accessSecretValue(ctx, secretPath, nil)
	if err != nil && !tclient.IsNotFound(err) {
		return err
	}
	if err == nil && bytes.Equal(current, value) {
		return nil
	}

	resp, err := c.api.PutSecretString(ctx, c.region, secretPath, value)
	if err != nil {
		return err
	}

	c.cache.Put(secretPath, resp.Version, value)

	return nil
}

func (c *client) DeleteSecret(ctx context.Context, remoteRef esv1.PushSecretRemoteRef) error {
	secretPath, err := normalizeSecretPath(remoteRef.GetRemoteKey())
	if err != nil {
		return err
	}

	err = c.api.DeleteSecret(ctx, c.region, secretPath)
	if tclient.IsNotFound(err) {
		return nil
	}

	return err
}

func (c *client) SecretExists(ctx context.Context, remoteRef esv1.PushSecretRemoteRef) (bool, error) {
	secretPath, err := normalizeSecretPath(remoteRef.GetRemoteKey())
	if err != nil {
		return false, err
	}

	_, err = c.api.GetSecret(ctx, c.region, secretPath, false)
	if tclient.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return true, nil
}

func (c *client) Validate() (esv1.ValidationResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := c.api.BrowseSecrets(ctx, c.region, "/")
	if err != nil {
		return esv1.ValidationResultError, nil
	}

	return esv1.ValidationResultReady, nil
}

func (c *client) GetSecretMap(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) (map[string][]byte, error) {
	rawData, err := c.GetSecret(ctx, ref)
	if err != nil {
		return nil, err
	}

	structuredData := make(map[string]json.RawMessage)

	err = json.Unmarshal(rawData, &structuredData)
	if err != nil {
		return nil, errors.New("failed to unmarshal secret: invalid JSON format")
	}

	values := make(map[string][]byte)

	for key, value := range structuredData {
		values[key] = jsonToSecretData(value)
	}

	return values, nil
}

func (c *client) GetAllSecrets(ctx context.Context, ref esv1.ExternalSecretFind) (map[string][]byte, error) {
	pathPrefix := "/"
	if ref.Path != nil {
		pathPrefix = *ref.Path
	}

	secretList, err := c.api.ListSecrets(ctx, c.region, pathPrefix)
	if err != nil {
		return nil, err
	}

	var nameMatcher *find.Matcher
	if ref.Name != nil {
		nameMatcher, err = find.New(*ref.Name)
		if err != nil {
			return nil, err
		}
	}

	results := map[string][]byte{}

	for _, secret := range secretList {
		if nameMatcher != nil && !nameMatcher.MatchName(path.Base(secret.Path)) {
			continue
		}

		if len(ref.Tags) > 0 && !labelsMatch(secret.Labels, ref.Tags) {
			continue
		}

		value, _, err := c.accessSecretValue(ctx, secret.Path, nil)
		if err != nil {
			log.Error(err, "failed to access secret", "path", secret.Path)
			continue
		}

		results[path.Base(secret.Path)] = value
	}

	return results, nil
}

func (c *client) Close(context.Context) error {
	return nil
}

func (c *client) accessSecretValue(ctx context.Context, secretPath string, version *int) ([]byte, int, error) {
	if version != nil {
		cachedValue, cacheHit := c.cache.Get(secretPath, *version)
		if cacheHit {
			return cachedValue, *version, nil
		}
	}

	value, resolvedVersion, err := c.api.GetSecretString(ctx, c.region, secretPath, version)
	if err != nil {
		return nil, 0, err
	}

	if version != nil {
		c.cache.Put(secretPath, resolvedVersion, value)
	}

	return value, resolvedVersion, nil
}

func normalizeSecretPath(key string) (string, error) {
	trimmed := strings.TrimSpace(key)
	if trimmed == "" {
		return "", errors.New("secret path cannot be empty")
	}
	return secrets.NormalizePath(trimmed)
}

func parseVersion(versionSpec string) (*int, error) {
	switch versionSpec {
	case "", "latest", "latest_enabled":
		return nil, nil
	default:
		version, err := strconv.Atoi(versionSpec)
		if err != nil {
			return nil, fmt.Errorf("invalid version %q", versionSpec)
		}
		return &version, nil
	}
}

func labelsMatch(secretLabels map[string]string, required map[string]string) bool {
	for key := range required {
		if _, ok := secretLabels[key]; !ok {
			return false
		}
	}
	return true
}

func jsonToSecretData(value json.RawMessage) []byte {
	var stringValue string
	err := json.Unmarshal(value, &stringValue)
	if err == nil {
		return []byte(stringValue)
	}

	return []byte(strings.TrimSpace(string(value)))
}

func extractJSONProperty(secretData []byte, property string) ([]byte, error) {
	result := gjson.Get(string(secretData), property)

	if !result.Exists() {
		return nil, esv1.NoSecretError{}
	}

	return jsonToSecretData(json.RawMessage(result.Raw)), nil
}
