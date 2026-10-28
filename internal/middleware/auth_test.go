package middleware

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type fixture struct {
	mw     *JWTMiddleware
	ecKey  *ecdsa.PrivateKey
	rsaKey *rsa.PrivateKey
}

func newFixture(t *testing.T) fixture {
	t.Helper()

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(t.TempDir(), "pub.pem")
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kid": "kc-1", "kty": "RSA", "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes()),
		}}})
	}))
	t.Cleanup(jwks.Close)

	mw, err := NewJWTMiddleware(pubPath, jwks.URL)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{mw: mw, ecKey: ecKey, rsaKey: rsaKey}
}

func claims(username string) jwt.MapClaims {
	return jwt.MapClaims{
		"sub":                "u-1",
		"preferred_username": username,
		"email":              "alice@example.org",
		"exp":                time.Now().Add(time.Hour).Unix(),
		"realm_access":       map[string]any{"roles": []any{"consumer", "provider"}},
	}
}

func sign(t *testing.T, method jwt.SigningMethod, key any, kid string, c jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(method, c)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// call runs a request with token through Authenticate and returns the status
// and, on success, what the handler saw in the context.
func call(mw *JWTMiddleware, token string) (int, string, []string) {
	var providerID string
	var roles []string
	h := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerID = ProviderIDFromCtx(r.Context())
		roles = RolesFromCtx(r.Context())
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, providerID, roles
}

func TestAuthenticateKeycloakRS256(t *testing.T) {
	f := newFixture(t)
	code, providerID, roles := call(f.mw, sign(t, jwt.SigningMethodRS256, f.rsaKey, "kc-1", claims("Alice.Smith")))
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if providerID != "provider-alice-smith" {
		t.Errorf("provider id = %q, want provider-alice-smith", providerID)
	}
	if len(roles) != 2 || roles[1] != "provider" {
		t.Errorf("roles = %v", roles)
	}
}

func TestAuthenticateES256StillAccepted(t *testing.T) {
	f := newFixture(t)
	if code, _, _ := call(f.mw, sign(t, jwt.SigningMethodES256, f.ecKey, "", claims("alice"))); code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
}

func TestAuthenticateRejects(t *testing.T) {
	f := newFixture(t)
	otherRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	expired := claims("alice")
	expired["exp"] = time.Now().Add(-time.Minute).Unix()
	noExp := claims("alice")
	delete(noExp, "exp")

	cases := map[string]string{
		"no token":         "",
		"wrong RSA key":    sign(t, jwt.SigningMethodRS256, otherRSA, "kc-1", claims("alice")),
		"unknown kid":      sign(t, jwt.SigningMethodRS256, f.rsaKey, "kc-2", claims("alice")),
		"expired":          sign(t, jwt.SigningMethodRS256, f.rsaKey, "kc-1", expired),
		"no exp":           sign(t, jwt.SigningMethodRS256, f.rsaKey, "kc-1", noExp),
		"HS256 not listed": sign(t, jwt.SigningMethodHS256, []byte("secret"), "", claims("alice")),
	}
	for name, token := range cases {
		if code, _, _ := call(f.mw, token); code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", name, code)
		}
	}
}

func TestProviderIDFallsBackToEmail(t *testing.T) {
	f := newFixture(t)
	c := claims("")
	delete(c, "preferred_username")
	_, providerID, _ := call(f.mw, sign(t, jwt.SigningMethodRS256, f.rsaKey, "kc-1", c))
	if providerID != "provider-alice-example-org" {
		t.Errorf("provider id = %q, want provider-alice-example-org", providerID)
	}
}
