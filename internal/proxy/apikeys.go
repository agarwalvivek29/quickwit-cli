package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/agarwalvivek29/quickwit-cli/internal/apikey"
	"github.com/agarwalvivek29/quickwit-cli/internal/oidc"
)

// APIKeyService is the management surface behind the /qwproxy/apikeys endpoints.
// *apikey.Store satisfies it.
type APIKeyService interface {
	Create(ctx context.Context, sub, email, description string, ttl time.Duration) (*apikey.Created, error)
	List(ctx context.Context, sub string) ([]apikey.Info, error)
	Revoke(ctx context.Context, sub, id string) error
}

// APIKeyAdmin serves the proxy-native key-management API under /qwproxy/apikeys.
// Every endpoint requires a valid OIDC bearer token — an X-API-Key is rejected,
// so a key can never be used to mint or manage another key.
type APIKeyAdmin struct {
	svc      APIKeyService
	verifier TokenVerifier
	maxTTL   time.Duration
	now      func() time.Time
}

// NewAPIKeyAdmin builds the handler. maxTTL caps the lifetime a caller may
// request (a larger or unset request is clamped to it).
func NewAPIKeyAdmin(svc APIKeyService, verifier TokenVerifier, maxTTL time.Duration) *APIKeyAdmin {
	if maxTTL <= 0 {
		maxTTL = 30 * 24 * time.Hour
	}
	return &APIKeyAdmin{svc: svc, verifier: verifier, maxTTL: maxTTL, now: time.Now}
}

// BasePath is where the admin handler must be mounted.
const BasePath = "/qwproxy/apikeys"

type createRequest struct {
	Description string `json:"description,omitempty"`
	TTLDays     int    `json:"ttl_days,omitempty"`
}

type createResponse struct {
	ID        string    `json:"id"`
	APIKey    string    `json:"api_key"`
	ExpiresAt time.Time `json:"expires_at"`
}

type infoResponse struct {
	ID          string     `json:"id"`
	Prefix      string     `json:"prefix"`
	Description string     `json:"description,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
}

func (h *APIKeyAdmin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Management always requires an OIDC login; a key cannot manage keys.
	if r.Header.Get(apiKeyHeader) != "" {
		writeJSONError(w, http.StatusUnauthorized, "api keys must be managed with an OIDC login, not an API key")
		return
	}
	raw, ok := bearerToken(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "missing bearer token")
		return
	}
	claims, err := h.verifier.Verify(r.Context(), raw)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "invalid token: "+err.Error())
		return
	}
	if claims.Subject == "" {
		writeJSONError(w, http.StatusUnauthorized, "token has no subject")
		return
	}

	pathID := strings.TrimPrefix(r.URL.Path, BasePath)
	pathID = strings.TrimPrefix(pathID, "/")

	switch {
	case r.Method == http.MethodPost && pathID == "":
		h.create(w, r, claims)
	case r.Method == http.MethodGet && pathID == "":
		h.list(w, r, claims)
	case r.Method == http.MethodDelete:
		// Revoke takes the id either as a path segment (/qwproxy/apikeys/{id}) or
		// as a query param on the base path (/qwproxy/apikeys?id={id}). The query
		// form keeps revoke on the SAME base path as create/list, so it works
		// behind a gateway (e.g. Kong) that routes the base path but not sub-paths.
		id := pathID
		if id == "" {
			id = r.URL.Query().Get("id")
		}
		if id == "" {
			writeJSONError(w, http.StatusBadRequest, "missing api key id (use /qwproxy/apikeys/{id} or ?id=<id>)")
			return
		}
		h.revoke(w, r, claims, id)
	default:
		writeJSONError(w, http.StatusNotFound, "no such api key endpoint")
	}
}

func (h *APIKeyAdmin) create(w http.ResponseWriter, r *http.Request, claims *oidc.Claims) {
	var req createRequest
	if r.Body != nil {
		// An empty body is fine (all fields default).
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			writeJSONError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}
	}
	ttl := h.maxTTL
	if req.TTLDays > 0 {
		if want := time.Duration(req.TTLDays) * 24 * time.Hour; want < ttl {
			ttl = want
		}
	}
	created, err := h.svc.Create(r.Context(), claims.Subject, claims.Email, req.Description, ttl)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "mint api key: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, createResponse{
		ID:        created.ID,
		APIKey:    created.APIKey,
		ExpiresAt: created.ExpiresAt,
	})
}

func (h *APIKeyAdmin) list(w http.ResponseWriter, r *http.Request, claims *oidc.Claims) {
	keys, err := h.svc.List(r.Context(), claims.Subject)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "list api keys: "+err.Error())
		return
	}
	out := make([]infoResponse, 0, len(keys))
	for _, k := range keys {
		out = append(out, infoResponse{
			ID:          k.ID,
			Prefix:      k.Prefix,
			Description: k.Description,
			CreatedAt:   k.CreatedAt,
			ExpiresAt:   k.ExpiresAt,
			RevokedAt:   k.RevokedAt,
			LastUsedAt:  k.LastUsedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"api_keys": out})
}

func (h *APIKeyAdmin) revoke(w http.ResponseWriter, r *http.Request, claims *oidc.Claims, id string) {
	err := h.svc.Revoke(r.Context(), claims.Subject, id)
	if errors.Is(err, apikey.ErrInvalidKey) {
		writeJSONError(w, http.StatusNotFound, "api key not found")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "revoke api key: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
