package middleware

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// jwksMinRefresh bounds how often an unknown kid can trigger a refetch, so a
// stream of forged tokens can't hammer Keycloak.
const jwksMinRefresh = 30 * time.Second

// jwksCache holds a Keycloak realm's RSA signing keys by kid, refetching the
// JWKS when a token names a kid it hasn't seen (Keycloak key rotation).
type jwksCache struct {
	url    string
	client *http.Client

	mu          sync.Mutex
	keys        map[string]*rsa.PublicKey
	lastFetched time.Time
}

func newJWKSCache(url string) *jwksCache {
	return &jwksCache{url: url, client: &http.Client{Timeout: 5 * time.Second}}
}

func (c *jwksCache) key(kid string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if k, ok := c.keys[kid]; ok {
		return k, nil
	}
	if time.Since(c.lastFetched) < jwksMinRefresh && c.keys != nil {
		return nil, fmt.Errorf("unknown signing key %q", kid)
	}
	keys, err := c.fetch()
	c.lastFetched = time.Now()
	if err != nil {
		return nil, err
	}
	c.keys = keys
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("unknown signing key %q", kid)
}

func (c *jwksCache) fetch() (map[string]*rsa.PublicKey, error) {
	resp, err := c.client.Get(c.url)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch JWKS: status %d", resp.StatusCode)
	}

	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, fmt.Errorf("decode JWKS: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey)
	for _, k := range set.Keys {
		if k.Kty != "RSA" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		}
	}
	return keys, nil
}
