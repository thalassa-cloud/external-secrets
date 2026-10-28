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
	"fmt"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

// Secret versions are immutable, so entries do not need a TTL.
const defaultSecretCacheSize = 500

type secretCache struct {
	lru *expirable.LRU[string, []byte]
}

func newCache() *secretCache {
	return &secretCache{
		lru: expirable.NewLRU[string, []byte](defaultSecretCacheSize, nil, 0),
	}
}

func (c *secretCache) Get(secretPath string, version int) ([]byte, bool) {
	if c == nil || c.lru == nil {
		return nil, false
	}
	return c.lru.Get(secretCacheKey(secretPath, version))
}

func (c *secretCache) Put(secretPath string, version int, value []byte) {
	if c == nil || c.lru == nil {
		return
	}
	c.lru.Add(secretCacheKey(secretPath, version), value)
}

func secretCacheKey(secretPath string, version int) string {
	return fmt.Sprintf("%s/%d", secretPath, version)
}
