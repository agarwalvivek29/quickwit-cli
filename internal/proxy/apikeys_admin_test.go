package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agarwalvivek29/quickwit-cli/internal/apikey"
)

type stubKeySvc struct {
	createdTTL  time.Duration
	createdSub  string
	createdDesc string
	listCalled  bool
	revokedID   string
	revokedSub  string
	revokeErr   error
}

func (s *stubKeySvc) Create(_ context.Context, sub, _, desc string, ttl time.Duration) (*apikey.Created, error) {
	s.createdTTL, s.createdSub, s.createdDesc = ttl, sub, desc
	return &apikey.Created{ID: "id-1", APIKey: "qw_pat_secret", ExpiresAt: time.Now().Add(ttl)}, nil
}

func (s *stubKeySvc) List(_ context.Context, _ string) ([]apikey.Info, error) {
	s.listCalled = true
	return []apikey.Info{{ID: "id-1", Prefix: "qw_pat_ab"}}, nil
}

func (s *stubKeySvc) Revoke(_ context.Context, sub, id string) error {
	s.revokedSub, s.revokedID = sub, id
	return s.revokeErr
}

func newAdmin(svc APIKeyService) *APIKeyAdmin {
	return NewAPIKeyAdmin(svc, stubVerifier{}, 30*24*time.Hour)
}

func adminReq(h *APIKeyAdmin, method, path, token, apiKey, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if apiKey != "" {
		r.Header.Set(apiKeyHeader, apiKey)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestAdminCreateClampsTTL(t *testing.T) {
	svc := &stubKeySvc{}
	h := newAdmin(svc)

	w := adminReq(h, http.MethodPost, BasePath, "good", "", `{"ttl_days":90,"description":"ci bot"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	if svc.createdTTL != 30*24*time.Hour {
		t.Errorf("ttl = %s, want clamped to 30d", svc.createdTTL)
	}
	if svc.createdSub != "u1" {
		t.Errorf("sub = %q, want u1 (from token)", svc.createdSub)
	}
	if svc.createdDesc != "ci bot" {
		t.Errorf("desc = %q, want 'ci bot'", svc.createdDesc)
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["api_key"] != "qw_pat_secret" {
		t.Errorf("response api_key = %v, want the raw key", resp["api_key"])
	}
}

func TestAdminCreateHonorsShorterTTL(t *testing.T) {
	svc := &stubKeySvc{}
	adminReq(newAdmin(svc), http.MethodPost, BasePath, "good", "", `{"ttl_days":7}`)
	if svc.createdTTL != 7*24*time.Hour {
		t.Errorf("ttl = %s, want 7d", svc.createdTTL)
	}
}

func TestAdminRejectsAPIKey(t *testing.T) {
	svc := &stubKeySvc{}
	// A caller presenting an API key (not an OIDC token) must be refused: a key
	// can never mint another key.
	w := adminReq(newAdmin(svc), http.MethodPost, BasePath, "", "qw_pat_whatever", `{}`)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if svc.createdSub != "" {
		t.Fatal("Create was called for an API-key-authenticated request")
	}
}

func TestAdminRejectsBadToken(t *testing.T) {
	w := adminReq(newAdmin(&stubKeySvc{}), http.MethodPost, BasePath, "bad", "", `{}`)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestAdminList(t *testing.T) {
	svc := &stubKeySvc{}
	w := adminReq(newAdmin(svc), http.MethodGet, BasePath, "good", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !svc.listCalled {
		t.Fatal("List was not called")
	}
}

func TestAdminRevoke(t *testing.T) {
	svc := &stubKeySvc{}
	w := adminReq(newAdmin(svc), http.MethodDelete, BasePath+"/id-42", "good", "", "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", w.Code)
	}
	if svc.revokedID != "id-42" || svc.revokedSub != "u1" {
		t.Errorf("revoke got id=%q sub=%q, want id-42/u1", svc.revokedID, svc.revokedSub)
	}
}

func TestAdminRevokeUnknownIs404(t *testing.T) {
	svc := &stubKeySvc{revokeErr: apikey.ErrInvalidKey}
	w := adminReq(newAdmin(svc), http.MethodDelete, BasePath+"/nope", "good", "", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}
