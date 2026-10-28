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
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	tfake "github.com/external-secrets/external-secrets/providers/v1/thalassa/fake"
	testingfake "github.com/external-secrets/external-secrets/runtime/testing/fake"
)

var _ secretAPI = (*tfake.SecretStore)(nil)

var db = tfake.New([]*tfake.Secret{
	{
		Path: "/secret-1",
		Versions: []*tfake.Version{
			{Version: 1},
			{Version: 2},
			{Version: 3, Status: "disabled"},
		},
	},
	{
		Path:   "/secret-2",
		Labels: map[string]string{"secret-2-tag-1": "ignored", "secret-2-tag-2": "ignored"},
		Versions: []*tfake.Version{
			{Version: 1},
			{Version: 2},
		},
	},
	{
		Path:     "/push-me",
		Versions: []*tfake.Version{},
	},
	{
		Path: "/not-changed",
		Versions: []*tfake.Version{
			{Version: 1},
		},
	},
	{
		Path: "/json-data",
		Versions: []*tfake.Version{
			{
				Version: 1,
				Data:    []byte(`{"some_string": "abc def", "some_int": -100, "some_bool": false}`),
			},
		},
	},
	{
		Path: "/json-nested",
		Versions: []*tfake.Version{
			{Version: 1, Data: []byte(`{"root":{"intermediate":{"leaf":9}}}`)},
		},
	},
	{
		Path: "/subpath/nested-secret",
		Versions: []*tfake.Version{
			{Version: 1, Data: []byte("secret data")},
		},
	},
})

func newTestClient() esv1.SecretsClient {
	return &client{
		api:      db,
		region:   "nl-01",
		kmsKeyId: "kms-test",
		cache:    newCache(),
	}
}

func TestGetSecret(t *testing.T) {
	ctx := context.Background()
	c := newTestClient()

	secret := db.Secret("/secret-1")

	testCases := map[string]struct {
		ref      esv1.ExternalSecretDataRemoteRef
		response []byte
		err      error
	}{
		"empty version should mean latest": {
			ref: esv1.ExternalSecretDataRemoteRef{
				Key:     secret.Path,
				Version: "",
			},
			response: secret.Versions[2].Data,
		},
		"asking for latest version": {
			ref: esv1.ExternalSecretDataRemoteRef{
				Key:     secret.Path,
				Version: "latest",
			},
			response: secret.Versions[2].Data,
		},
		"asking for version by number": {
			ref: esv1.ExternalSecretDataRemoteRef{
				Key:     secret.Path,
				Version: "1",
			},
			response: secret.Versions[0].Data,
		},
		"asking for nested json property": {
			ref: esv1.ExternalSecretDataRemoteRef{
				Key:      db.Secret("/json-nested").Path,
				Property: "root.intermediate.leaf",
				Version:  "latest",
			},
			response: []byte("9"),
		},
		"secret in subpath": {
			ref: esv1.ExternalSecretDataRemoteRef{
				Key:     "/subpath/nested-secret",
				Version: "latest",
			},
			response: []byte("secret data"),
		},
		"non existing secret should yield NoSecretErr": {
			ref: esv1.ExternalSecretDataRemoteRef{
				Key: "/missing-secret",
			},
			err: esv1.NoSecretErr,
		},
		"non existing revision should yield NoSecretErr": {
			ref: esv1.ExternalSecretDataRemoteRef{
				Key:     secret.Path,
				Version: "9999",
			},
			err: esv1.NoSecretErr,
		},
		"non existing json property should yield not found": {
			ref: esv1.ExternalSecretDataRemoteRef{
				Key:      db.Secret("/json-nested").Path,
				Property: "root.intermediate.missing",
				Version:  "latest",
			},
			err: esv1.NoSecretErr,
		},
	}

	for tcName, tc := range testCases {
		t.Run(tcName, func(t *testing.T) {
			response, err := c.GetSecret(ctx, tc.ref)
			if tc.err == nil {
				assert.NoError(t, err)
				assert.Equal(t, tc.response, response)
			} else {
				assert.Nil(t, response)
				assert.ErrorIs(t, err, tc.err)
				assert.Equal(t, tc.err, err)
			}
		})
	}
}

func TestPushSecret(t *testing.T) {
	secretKey := "secret-key"
	pushSecretData := func(remoteKey string) testingfake.PushSecretData {
		return testingfake.PushSecretData{
			SecretKey: secretKey,
			RemoteKey: remoteKey,
		}
	}
	secret := func(value []byte) *corev1.Secret {
		return &corev1.Secret{
			Data: map[string][]byte{secretKey: value},
		}
	}

	t.Run("to new secret", func(t *testing.T) {
		ctx := context.Background()
		c := newTestClient()
		data := []byte("some secret data 6a8ff33b-c69a-4e42-b162-b7b595ee7f5f")
		secretPath := "/secret-creation-test"

		pushErr := c.PushSecret(ctx, secret(data), pushSecretData(secretPath))

		assert.NoError(t, pushErr)
		assert.Len(t, db.Secret(secretPath).Versions, 1)
		assert.Equal(t, data, db.Secret(secretPath).Versions[0].Data)
	})

	t.Run("to secret created by us", func(t *testing.T) {
		ctx := context.Background()
		c := newTestClient()
		data := []byte("some secret data a11d416b-9169-4f4a-8c27-d2959b22e189")
		secretPath := "/secret-update-test"
		assert.NoError(t, c.PushSecret(ctx, secret([]byte("original data")), pushSecretData(secretPath)))

		pushErr := c.PushSecret(ctx, secret(data), pushSecretData(secretPath))

		assert.NoError(t, pushErr)
		assert.Len(t, db.Secret(secretPath).Versions, 2)
		assert.Equal(t, data, db.Secret(secretPath).Versions[1].Data)
	})

	t.Run("to secret with no version", func(t *testing.T) {
		ctx := context.Background()
		c := newTestClient()
		data := []byte("some secret data a11d416b-9169-4f4a-8c27-d2959b22e189")
		secretPath := "/push-me"

		pushErr := c.PushSecret(ctx, secret(data), pushSecretData(secretPath))

		assert.NoError(t, pushErr)
		assert.Len(t, db.Secret(secretPath).Versions, 1)
		assert.Equal(t, data, db.Secret(secretPath).Versions[0].Data)
	})

	t.Run("without change does not create a version", func(t *testing.T) {
		ctx := context.Background()
		c := newTestClient()
		fs := db.Secret("/not-changed")

		pushErr := c.PushSecret(ctx, secret(fs.Versions[0].Data), pushSecretData(fs.Path))

		assert.NoError(t, pushErr)
		assert.Equal(t, 1, len(fs.Versions))
	})

	t.Run("missing kms key identity is an error", func(t *testing.T) {
		ctx := context.Background()
		c := &client{
			api:    db,
			region: "nl-01",
			cache:  newCache(),
		}

		pushErr := c.PushSecret(ctx, secret([]byte("some data")), pushSecretData("/new-secret"))

		assert.Error(t, pushErr)
	})
}

func TestGetSecretMap(t *testing.T) {
	ctx := context.Background()
	c := newTestClient()

	values, getErr := c.GetSecretMap(ctx, esv1.ExternalSecretDataRemoteRef{
		Key:     db.Secret("/json-data").Path,
		Version: "latest",
	})

	assert.NoError(t, getErr)
	assert.Equal(t, map[string][]byte{
		"some_string": []byte("abc def"),
		"some_int":    []byte("-100"),
		"some_bool":   []byte("false"),
	}, values)
}

func TestGetSecretMapNested(t *testing.T) {
	ctx := context.Background()
	c := newTestClient()

	values, getErr := c.GetSecretMap(ctx, esv1.ExternalSecretDataRemoteRef{
		Key:      db.Secret("/json-nested").Path,
		Property: "root.intermediate",
		Version:  "latest",
	})

	assert.NoError(t, getErr)
	assert.Equal(t, map[string][]byte{
		"leaf": []byte("9"),
	}, values)
}

func TestGetAllSecrets(t *testing.T) {
	ctx := context.Background()
	localDB := tfake.New([]*tfake.Secret{
		{
			Path: "/secret-1",
			Versions: []*tfake.Version{
				{Version: 1},
				{Version: 2},
			},
		},
		{
			Path:   "/secret-2",
			Labels: map[string]string{"secret-2-tag-1": "ignored", "secret-2-tag-2": "ignored"},
			Versions: []*tfake.Version{
				{Version: 1},
				{Version: 2},
			},
		},
		{
			Path: "/subpath/nested-secret",
			Versions: []*tfake.Version{
				{Version: 1, Data: []byte("secret data")},
			},
		},
	})
	c := &client{
		api:      localDB,
		region:   "nl-01",
		kmsKeyId: "kms-test",
		cache:    newCache(),
	}

	testCases := map[string]struct {
		ref      esv1.ExternalSecretFind
		response map[string][]byte
		err      error
	}{
		"find secrets by name": {
			ref: esv1.ExternalSecretFind{
				Name: &esv1.FindName{RegExp: "secret-.*"},
			},
			response: map[string][]byte{
				"secret-1": localDB.Secret("/secret-1").MustGetVersion(nil).Data,
				"secret-2": localDB.Secret("/secret-2").MustGetVersion(nil).Data,
			},
		},
		"find secrets by tags": {
			ref: esv1.ExternalSecretFind{
				Tags: map[string]string{"secret-2-tag-1": "ignored-value"},
			},
			response: map[string][]byte{
				"secret-2": localDB.Secret("/secret-2").MustGetVersion(nil).Data,
			},
		},
		"find secrets by path": {
			ref: esv1.ExternalSecretFind{
				Path: new("/subpath"),
			},
			response: map[string][]byte{
				"nested-secret": localDB.Secret("/subpath/nested-secret").MustGetVersion(nil).Data,
			},
		},
	}

	for tcName, tc := range testCases {
		t.Run(tcName, func(t *testing.T) {
			response, err := c.GetAllSecrets(ctx, tc.ref)
			if tc.err == nil {
				assert.NoError(t, err)
				assert.Equal(t, tc.response, response)
			} else {
				assert.Nil(t, response)
				assert.ErrorIs(t, err, tc.err)
				assert.Equal(t, tc.err, err)
			}
		})
	}
}

func TestDeleteSecret(t *testing.T) {
	ctx := context.Background()
	localDB := tfake.New([]*tfake.Secret{
		{Path: "/delete-me", Versions: []*tfake.Version{{Version: 1}}},
		{Path: "/subpath/delete-me-too", Versions: []*tfake.Version{{Version: 1, Data: []byte("secret data")}}},
	})
	c := &client{
		api:      localDB,
		region:   "nl-01",
		kmsKeyId: "kms-test",
		cache:    newCache(),
	}

	testCases := map[string]struct {
		ref testingfake.PushSecretData
		err error
	}{
		"Delete Successfully": {
			ref: testingfake.PushSecretData{RemoteKey: "/delete-me"},
			err: nil,
		},
		"Delete by path": {
			ref: testingfake.PushSecretData{RemoteKey: "/subpath/delete-me-too"},
			err: nil,
		},
		"Secret Not Found": {
			ref: testingfake.PushSecretData{RemoteKey: "/not-a-secret"},
			err: nil,
		},
	}

	for tcName, tc := range testCases {
		t.Run(tcName, func(t *testing.T) {
			err := c.DeleteSecret(ctx, tc.ref)
			if tc.err == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tc.err)
				assert.Equal(t, tc.err, err)
			}
		})
	}
}

func TestSecretExists(t *testing.T) {
	ctx := context.Background()
	c := newTestClient()

	exists, err := c.SecretExists(ctx, testingfake.PushSecretData{RemoteKey: "/secret-2"})
	assert.NoError(t, err)
	assert.True(t, exists)

	exists, err = c.SecretExists(ctx, testingfake.PushSecretData{RemoteKey: "/missing"})
	assert.NoError(t, err)
	assert.False(t, exists)
}

func TestNormalizeSecretPath(t *testing.T) {
	testCases := map[string]struct {
		in   string
		want string
		err  bool
	}{
		"already normalized": {in: "/foo/bar", want: "/foo/bar"},
		"adds leading slash": {in: "foo/bar", want: "/foo/bar"},
		"empty is error":     {in: "  ", err: true},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			got, err := normalizeSecretPath(tc.in)
			if tc.err {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseVersion(t *testing.T) {
	latest, err := parseVersion("latest")
	assert.NoError(t, err)
	assert.Nil(t, latest)

	specific, err := parseVersion("3")
	assert.NoError(t, err)
	assert.NotNil(t, specific)
	assert.Equal(t, 3, *specific)

	_, err = parseVersion("not-a-number")
	assert.Error(t, err)
}

func TestPushSecretInvalidPath(t *testing.T) {
	ctx := context.Background()
	c := newTestClient()

	err := c.PushSecret(ctx, &corev1.Secret{
		Data: map[string][]byte{"key": []byte("value")},
	}, testingfake.PushSecretData{
		SecretKey: "key",
		RemoteKey: fmt.Sprintf("invalid path with spaces/%d", 1),
	})
	assert.Error(t, err)
}
