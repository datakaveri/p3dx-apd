package middleware

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const (
	ContextKeyUserID contextKey = "userID"
	ContextKeyRoles  contextKey = "roles"
	ContextKeyEmail  contextKey = "email"
)

type JWTMiddleware struct {
	publicKey *ecdsa.PublicKey
}

func NewJWTMiddleware(publicKeyPath string) (*JWTMiddleware, error) {
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
	return &JWTMiddleware{publicKey: ecPub}, nil
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
		if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return m.publicKey, nil
	})
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
