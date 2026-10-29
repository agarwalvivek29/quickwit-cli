package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/agarwalvivek29/quickwit-cli/internal/apikey"
	"github.com/agarwalvivek29/quickwit-cli/internal/oidc"
)

// ServiceAccountsPath is where the service-account admin handler is mounted.
// Every operation lives on this one path (selected by method + query params),
// never a sub-path, so a fronting gateway (e.g. Kong) needs a single route.
const ServiceAccountsPath = "/qwproxy/serviceaccounts"

// TTLNever is the key-lifetime label for a key that never expires.
const TTLNever = "never"

// ServiceAccountService is the store behind ServiceAccountAdmin. *apikey.Store
// satisfies it.
type ServiceAccountService interface {
	CreateServiceAccount(ctx context.Context, name, description, bySub, byEmail string) (*apikey.ServiceAccount, error)
	ListServiceAccounts(ctx context.Context) ([]apikey.ServiceAccount, error)
	DisableServiceAccount(ctx context.Context, name, bySub string) error
	CreateServiceAccountKey(ctx context.Context, name, description string, ttl time.Duration, bySub, byEmail string) (*apikey.Created, error)
	ListServiceAccountKeys(ctx context.Context, name string) ([]apikey.Info, error)
	RevokeServiceAccountKey(ctx context.Context, name, id string) error
}

// ServiceAccountAdmin serves service-account management. Callers need an OIDC
// login (never an API key) AND membership in one of the admin groups, read from
// the token's `groups` claim:
//
//	GET    ?                          list service accounts
//	POST   ?        {name,description} create a service account
//	DELETE ?name=N                    disable N (all its keys stop working)
//	GET    ?name=N                    list N's keys
//	POST   ?name=N  {ttl,description} mint a key for N; ttl is an allowed label
//	DELETE ?name=N&key_id=K           revoke one of N's keys
type ServiceAccountAdmin struct {
	svc         ServiceAccountService
	verifier    TokenVerifier
	adminGroups map[string]bool
	ttls        map[string]time.Duration // label -> lifetime; 0 = never expires
	ttlLabels   []string                 // allowed labels, in configured order
}

// NewServiceAccountAdmin builds the handler. adminGroups must be non-empty (the
// caller should not mount the handler otherwise); ttlLabels is the allowed
// key-lifetime set, parsed with ParseKeyTTLs.
func NewServiceAccountAdmin(svc ServiceAccountService, verifier TokenVerifier, adminGroups, ttlLabels []string) (*ServiceAccountAdmin, error) {
	if len(adminGroups) == 0 {
		return nil, errors.New("service accounts need at least one admin group")
	}
	ttls, err := ParseKeyTTLs(ttlLabels)
	if err != nil {
		return nil, err
	}
	groups := make(map[string]bool, len(adminGroups))
	for _, g := range adminGroups {
		groups[g] = true
	}
	return &ServiceAccountAdmin{svc: svc, verifier: verifier, adminGroups: groups, ttls: ttls, ttlLabels: ttlLabels}, nil
}

// ParseKeyTTLs validates key-lifetime labels: "<n>d" (n >= 1) or "never".
func ParseKeyTTLs(labels []string) (map[string]time.Duration, error) {
	if len(labels) == 0 {
		return nil, errors.New("at least one service-account key ttl is required")
	}
	out := make(map[string]time.Duration, len(labels))
	for _, l := range labels {
		if l == TTLNever {
			out[l] = 0
			continue
		}
		n, err := strconv.Atoi(strings.TrimSuffix(l, "d"))
		if !strings.HasSuffix(l, "d") || err != nil || n < 1 {
			return nil, fmt.Errorf("invalid service-account key ttl %q: use <days>d (e.g. 30d) or %q", l, TTLNever)
		}
		out[l] = time.Duration(n) * 24 * time.Hour
	}
	return out, nil
}

type saCreateRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type saKeyCreateRequest struct {
	TTL         string `json:"ttl"`
	Description string `json:"description,omitempty"`
}

type saKeyCreateResponse struct {
	ID        string     `json:"id"`
	APIKey    string     `json:"api_key"`
	ExpiresAt *time.Time `json:"expires_at"` // null = never expires
}

type saResponse struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	DisabledAt  *time.Time `json:"disabled_at,omitempty"`
	ActiveKeys  int        `json:"active_keys"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
}

func (h *ServiceAccountAdmin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	claims, ok := oidcCaller(w, r, h.verifier)
	if !ok {
		return
	}
	if !h.isAdmin(claims) {
		writeJSONError(w, http.StatusForbidden, "service-account management requires membership in an admin group")
		return
	}
	if strings.TrimPrefix(r.URL.Path, ServiceAccountsPath) != "" {
		writeJSONError(w, http.StatusNotFound, "no such service-account endpoint (use query params on "+ServiceAccountsPath+")")
		return
	}

	q := r.URL.Query()
	name, keyID := q.Get("name"), q.Get("key_id")
	switch {
	case r.Method == http.MethodGet && name == "":
		h.list(w, r)
	case r.Method == http.MethodPost && name == "":
		h.create(w, r, claims)
	case r.Method == http.MethodDelete && name != "" && keyID == "":
		h.disable(w, r, claims, name)
	case r.Method == http.MethodGet && name != "":
		h.listKeys(w, r, name)
	case r.Method == http.MethodPost && name != "":
		h.createKey(w, r, claims, name)
	case r.Method == http.MethodDelete && name != "" && keyID != "":
		h.revokeKey(w, r, name, keyID)
	case r.Method == http.MethodDelete:
		writeJSONError(w, http.StatusBadRequest, "missing service account name (?name=<name>)")
	default:
		writeJSONError(w, http.StatusNotFound, "no such service-account endpoint")
	}
}

func (h *ServiceAccountAdmin) isAdmin(claims *oidc.Claims) bool {
	for _, g := range claims.Groups {
		if h.adminGroups[g] {
			return true
		}
	}
	return false
}

func (h *ServiceAccountAdmin) list(w http.ResponseWriter, r *http.Request) {
	sas, err := h.svc.ListServiceAccounts(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "list service accounts: "+err.Error())
		return
	}
	out := make([]saResponse, 0, len(sas))
	for _, sa := range sas {
		out = append(out, saResponse(sa))
	}
	writeJSON(w, http.StatusOK, map[string]any{"service_accounts": out})
}

func (h *ServiceAccountAdmin) create(w http.ResponseWriter, r *http.Request, claims *oidc.Claims) {
	var req saCreateRequest
	if !decodeBody(w, r, &req) {
		return
	}
	sa, err := h.svc.CreateServiceAccount(r.Context(), req.Name, req.Description, claims.Subject, claims.Email)
	switch {
	case errors.Is(err, apikey.ErrInvalidName):
		writeJSONError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, apikey.ErrServiceAccountExists):
		writeJSONError(w, http.StatusConflict, err.Error())
	case err != nil:
		writeJSONError(w, http.StatusInternalServerError, "create service account: "+err.Error())
	default:
		writeJSON(w, http.StatusCreated, saResponse(*sa))
	}
}

func (h *ServiceAccountAdmin) disable(w http.ResponseWriter, r *http.Request, claims *oidc.Claims, name string) {
	err := h.svc.DisableServiceAccount(r.Context(), name, claims.Subject)
	switch {
	case errors.Is(err, apikey.ErrServiceAccountNotFound):
		writeJSONError(w, http.StatusNotFound, "service account not found or already disabled")
	case err != nil:
		writeJSONError(w, http.StatusInternalServerError, "disable service account: "+err.Error())
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (h *ServiceAccountAdmin) listKeys(w http.ResponseWriter, r *http.Request, name string) {
	keys, err := h.svc.ListServiceAccountKeys(r.Context(), name)
	switch {
	case errors.Is(err, apikey.ErrServiceAccountNotFound):
		writeJSONError(w, http.StatusNotFound, err.Error())
	case err != nil:
		writeJSONError(w, http.StatusInternalServerError, "list service account keys: "+err.Error())
	default:
		writeJSON(w, http.StatusOK, map[string]any{"api_keys": infoResponses(keys)})
	}
}

func (h *ServiceAccountAdmin) createKey(w http.ResponseWriter, r *http.Request, claims *oidc.Claims, name string) {
	var req saKeyCreateRequest
	if !decodeBody(w, r, &req) {
		return
	}
	ttl, ok := h.ttls[req.TTL]
	if !ok {
		writeJSONError(w, http.StatusBadRequest,
			fmt.Sprintf("ttl %q not allowed; choose one of: %s", req.TTL, strings.Join(h.ttlLabels, ", ")))
		return
	}
	created, err := h.svc.CreateServiceAccountKey(r.Context(), name, req.Description, ttl, claims.Subject, claims.Email)
	switch {
	case errors.Is(err, apikey.ErrServiceAccountNotFound):
		writeJSONError(w, http.StatusNotFound, "service account not found or disabled")
		return
	case err != nil:
		writeJSONError(w, http.StatusInternalServerError, "mint service account key: "+err.Error())
		return
	}
	resp := saKeyCreateResponse{ID: created.ID, APIKey: created.APIKey}
	if !created.ExpiresAt.IsZero() {
		resp.ExpiresAt = &created.ExpiresAt
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (h *ServiceAccountAdmin) revokeKey(w http.ResponseWriter, r *http.Request, name, keyID string) {
	err := h.svc.RevokeServiceAccountKey(r.Context(), name, keyID)
	switch {
	case errors.Is(err, apikey.ErrInvalidKey):
		writeJSONError(w, http.StatusNotFound, "api key not found")
	case err != nil:
		writeJSONError(w, http.StatusInternalServerError, "revoke service account key: "+err.Error())
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// decodeBody decodes a JSON body into v; an empty body leaves v zero. On a
// malformed body it writes the 400 and returns false.
func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Body == nil {
		return true
	}
	if err := json.NewDecoder(r.Body).Decode(v); err != nil && !errors.Is(err, io.EOF) {
		writeJSONError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return false
	}
	return true
}
