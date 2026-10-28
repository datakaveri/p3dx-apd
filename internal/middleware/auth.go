package middleware

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const (
	ContextKeyUserID contextKey = "userID"
	ContextKeyRoles  contextKey = "roles"
	ContextKeyEmail  contextKey = "email"
	// ContextKeyUsername holds the token's preferred_username.
	ContextKeyUsername contextKey = "username"
)

// JWTMiddleware accepts ES256 tokens signed by the configured EC key and,
// when a Keycloak JWKS URL is set, RS256 tokens issued by that Keycloak realm
// (what the P3DX UI holds after signing in).
type JWTMiddleware struct {
	publicKey *ecdsa.PublicKey
	keycloak  *jwksCache
}

func NewJWTMiddleware(publicKeyPath, keycloakJWKSURL string) (*JWTMiddleware, error) {
	data, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in public key file")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not ECDSA")
	}
	m := &JWTMiddleware{publicKey: ecPub}
	if keycloakJWKSURL != "" {
		m.keycloak = newJWKSCache(keycloakJWKSURL)
	}
	return m, nil
}

// Authenticate validates the Bearer JWT and injects claims into the request context.
func (m *JWTMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := m.extractAndValidate(r)
		if err != nil {
			http.Error(w, `{"status":"error","message":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, `{"status":"error","message":"invalid token claims"}`, http.StatusUnauthorized)
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, ContextKeyUserID, stringClaim(claims, "sub"))
		ctx = context.WithValue(ctx, ContextKeyEmail, stringClaim(claims, "email"))
		ctx = context.WithValue(ctx, ContextKeyUsername, stringClaim(claims, "preferred_username"))
		ctx = context.WithValue(ctx, ContextKeyRoles, rolesClaim(claims))

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRole returns a middleware that allows only users with one of the given roles.
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userRoles, _ := r.Context().Value(ContextKeyRoles).([]string)
			for _, ur := range userRoles {
				if allowed[ur] {
					next.ServeHTTP(w, r)
					return
				}
			}
			http.Error(w, `{"status":"error","message":"forbidden"}`, http.StatusForbidden)
		})
	}
}

func (m *JWTMiddleware) extractAndValidate(r *http.Request) (*jwt.Token, error) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, fmt.Errorf("missing bearer token")
	}
	raw := strings.TrimPrefix(authHeader, "Bearer ")

	return jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
		switch t.Method.(type) {
		case *jwt.SigningMethodECDSA:
			return m.publicKey, nil
		case *jwt.SigningMethodRSA:
			if m.keycloak == nil {
				return nil, fmt.Errorf("RS256 tokens not accepted: KEYCLOAK_JWKS_URL not set")
			}
			kid, _ := t.Header["kid"].(string)
			return m.keycloak.key(kid)
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
	}, jwt.WithValidMethods([]string{"ES256", "RS256"}), jwt.WithExpirationRequired())
}

// ---------------------------------------------------------------------------
// Context helpers (callable from handlers)
// ---------------------------------------------------------------------------

func UserIDFromCtx(ctx context.Context) string {
	v, _ := ctx.Value(ContextKeyUserID).(string)
	return v
}

func EmailFromCtx(ctx context.Context) string {
	v, _ := ctx.Value(ContextKeyEmail).(string)
	return v
}

func UsernameFromCtx(ctx context.Context) string {
	v, _ := ctx.Value(ContextKeyUsername).(string)
	return v
}

// ProviderIDFromCtx is the caller's provider_id as stored on their policies:
// "provider-" + slugify(username, or email if the token has no username).
// Must match slugify() in the UI's PolicyForm.jsx / InfraPolicyForm.jsx and
// gov_layer's providerIDForUsername.
func ProviderIDFromCtx(ctx context.Context) string {
	name := UsernameFromCtx(ctx)
	if name == "" {
		name = EmailFromCtx(ctx)
	}
	return "provider-" + slugify(name)
}

var nonSlugChars = regexp.MustCompile(`[^a-z0-9]+`)

func slugify(s string) string {
	if s == "" {
		s = "unknown"
	}
	return strings.Trim(nonSlugChars.ReplaceAllString(strings.ToLower(s), "-"), "-")
}

func RolesFromCtx(ctx context.Context) []string {
	v, _ := ctx.Value(ContextKeyRoles).([]string)
	return v
}

func HasRole(ctx context.Context, role string) bool {
	for _, r := range RolesFromCtx(ctx) {
		if r == role {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// JWT claim helpers
// ---------------------------------------------------------------------------

func stringClaim(claims jwt.MapClaims, key string) string {
	v, _ := claims[key].(string)
	return v
}

func rolesClaim(claims jwt.MapClaims) []string {
	ra, ok := claims["realm_access"].(map[string]interface{})
	if !ok {
		return nil
	}
	rolesRaw, ok := ra["roles"].([]interface{})
	if !ok {
		return nil
	}
	roles := make([]string, 0, len(rolesRaw))
	for _, r := range rolesRaw {
		if s, ok := r.(string); ok {
			roles = append(roles, s)
		}
	}
	return roles
}
