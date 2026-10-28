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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCacheMissReturnsFalse(t *testing.T) {
	cache := newCache()

	_, ok := cache.Get("/app/test/nonexistent", 1)

	assert.False(t, ok)
}

func TestCachePutThenGet(t *testing.T) {
	cache := newCache()
	secretPath := "/app/prod/db/password"
	version := 1
	expectedValue := []byte("some value")

	cache.Put(secretPath, version, expectedValue)

	value, ok := cache.Get(secretPath, version)
	assert.True(t, ok)
	assert.Equal(t, expectedValue, value)
}

func TestCacheLeastRecentlyUsedIsRemovedFirst(t *testing.T) {
	cache := newCache()
	secretPath := "/app/prod/db/password"

	for i := range defaultSecretCacheSize {
		cache.Put(secretPath, i+1, []byte{})
	}

	for i := range defaultSecretCacheSize {
		cache.Get(secretPath, i+1)
	}

	cache.Put(secretPath, defaultSecretCacheSize+2, []byte{})

	_, ok := cache.Get(secretPath, 1)
	assert.False(t, ok)

	_, ok = cache.Get(secretPath, defaultSecretCacheSize+2)
	assert.True(t, ok)
}
