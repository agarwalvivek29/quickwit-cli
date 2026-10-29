package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agarwalvivek29/quickwit-cli/internal/apikey"
	"github.com/agarwalvivek29/quickwit-cli/internal/oidc"
)

// groupVerifier: "admin" is in the qw-admins group, "good" is a valid user in
// no admin group, anything else is invalid.
type groupVerifier struct{}

func (groupVerifier) Verify(_ context.Context, raw string) (*oidc.Claims, error) {
	switch raw {
	case "admin":
		return &oidc.Claims{Subject: "a1", Email: "a1@example.com", Groups: []string{"Engineering", "qw-admins"}}, nil
	case "good":
		return &oidc.Claims{Subject: "u1", Email: "u1@example.com", Groups: []string{"Engineering"}}, nil
	}
	return nil, errors.New("bad token")
}

type stubSASvc struct {
	calls   []string
	name    string
	desc    string
	ttl     time.Duration
	bySub   string
	keyID   string
	saErr   error
	keyErr  error
	created *apikey.Created
}

func (s *stubSASvc) CreateServiceAccount(_ context.Context, name, desc, bySub, _ string) (*apikey.ServiceAccount, error) {
	s.calls = append(s.calls, "create")
	s.name, s.desc, s.bySub = name, desc, bySub
	if s.saErr != nil {
		return nil, s.saErr
	}
	return &apikey.ServiceAccount{ID: "sa-1", Name: name, CreatedBy: "a1@example.com"}, nil
}

func (s *stubSASvc) ListServiceAccounts(context.Context) ([]apikey.ServiceAccount, error) {
	s.calls = append(s.calls, "list")
	return []apikey.ServiceAccount{{ID: "sa-1", Name: "bot", ActiveKeys: 2}}, nil
}

func (s *stubSASvc) DisableServiceAccount(_ context.Context, name, bySub string) error {
	s.calls = append(s.calls, "disable")
	s.name, s.bySub = name, bySub
	return s.saErr
}

func (s *stubSASvc) CreateServiceAccountKey(_ context.Context, name, desc string, ttl time.Duration, bySub, _ string) (*apikey.Created, error) {
	s.calls = append(s.calls, "createKey")
	s.name, s.desc, s.ttl, s.bySub = name, desc, ttl, bySub
	if s.saErr != nil {
		return nil, s.saErr
	}
	c := &apikey.Created{ID: "k-1", APIKey: "qw_pat_sa"}
	if ttl > 0 {
		c.ExpiresAt = time.Now().Add(ttl)
	}
	s.created = c
	return c, nil
}

func (s *stubSASvc) ListServiceAccountKeys(_ context.Context, name string) ([]apikey.Info, error) {
	s.calls = append(s.calls, "listKeys")
	s.name = name
	if s.saErr != nil {
		return nil, s.saErr
	}
	return []apikey.Info{{ID: "k-1", Prefix: "qw_pat_ab", CreatedBy: "a1@example.com"}}, nil
}

func (s *stubSASvc) RevokeServiceAccountKey(_ context.Context, name, id string) error {
	s.calls = append(s.calls, "revokeKey")
	s.name, s.keyID = name, id
	return s.keyErr
}

func newSAAdmin(t *testing.T, svc ServiceAccountService) *ServiceAccountAdmin {
	t.Helper()
	h, err := NewServiceAccountAdmin(svc, groupVerifier{}, []string{"qw-admins"}, []string{"30d", "90d", "never"})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func saReq(h http.Handler, method, target, token, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestSAAdminRequiresAdminGroup(t *testing.T) {
	svc := &stubSASvc{}
	w := saReq(newSAAdmin(t, svc), http.MethodPost, ServiceAccountsPath, "good", `{"name":"bot"}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if len(svc.calls) != 0 {
		t.Fatalf("store called for a non-admin: %v", svc.calls)
	}
}

func TestSAAdminRejectsAPIKeyAndBadToken(t *testing.T) {
	h := newSAAdmin(t, &stubSASvc{})
	r := httptest.NewRequest(http.MethodGet, ServiceAccountsPath, nil)
	r.Header.Set(apiKeyHeader, "qw_pat_x")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("api key: status = %d, want 401", w.Code)
	}
	if w := saReq(h, http.MethodGet, ServiceAccountsPath, "bad", ""); w.Code != http.StatusUnauthorized {
		t.Errorf("bad token: status = %d, want 401", w.Code)
	}
}

func TestSAAdminCreate(t *testing.T) {
	svc := &stubSASvc{}
	w := saReq(newSAAdmin(t, svc), http.MethodPost, ServiceAccountsPath, "admin", `{"name":"bot","description":"triage"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	if svc.name != "bot" || svc.desc != "triage" || svc.bySub != "a1" {
		t.Errorf("create got name=%q desc=%q by=%q", svc.name, svc.desc, svc.bySub)
	}
}

func TestSAAdminCreateErrors(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int
	}{
		{apikey.ErrInvalidName, http.StatusBadRequest},
		{apikey.ErrServiceAccountExists, http.StatusConflict},
	} {
		w := saReq(newSAAdmin(t, &stubSASvc{saErr: tc.err}), http.MethodPost, ServiceAccountsPath, "admin", `{"name":"X"}`)
		if w.Code != tc.want {
			t.Errorf("%v: status = %d, want %d", tc.err, w.Code, tc.want)
		}
	}
}

func TestSAAdminList(t *testing.T) {
	svc := &stubSASvc{}
	w := saReq(newSAAdmin(t, svc), http.MethodGet, ServiceAccountsPath, "admin", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp struct {
		ServiceAccounts []map[string]any `json:"service_accounts"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.ServiceAccounts) != 1 || resp.ServiceAccounts[0]["name"] != "bot" {
		t.Errorf("unexpected list: %s", w.Body.String())
	}
}

func TestSAAdminCreateKeyTTLs(t *testing.T) {
	for _, tc := range []struct {
		ttl         string
		want        time.Duration
		wantExpires bool
	}{
		{"30d", 30 * 24 * time.Hour, true},
		{"90d", 90 * 24 * time.Hour, true},
		{"never", 0, false},
	} {
		svc := &stubSASvc{}
		w := saReq(newSAAdmin(t, svc), http.MethodPost, ServiceAccountsPath+"?name=bot", "admin", `{"ttl":"`+tc.ttl+`"}`)
		if w.Code != http.StatusCreated {
			t.Fatalf("%s: status = %d, want 201; body=%s", tc.ttl, w.Code, w.Body.String())
		}
		if svc.ttl != tc.want || svc.name != "bot" || svc.bySub != "a1" {
			t.Errorf("%s: got ttl=%s name=%q by=%q", tc.ttl, svc.ttl, svc.name, svc.bySub)
		}
		var resp map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["api_key"] != "qw_pat_sa" {
			t.Errorf("%s: api_key = %v", tc.ttl, resp["api_key"])
		}
		if (resp["expires_at"] != nil) != tc.wantExpires {
			t.Errorf("%s: expires_at = %v, want set=%v", tc.ttl, resp["expires_at"], tc.wantExpires)
		}
	}
}

func TestSAAdminCreateKeyRejectsDisallowedTTL(t *testing.T) {
	svc := &stubSASvc{}
	h, err := NewServiceAccountAdmin(svc, groupVerifier{}, []string{"qw-admins"}, []string{"30d", "90d"})
	if err != nil {
		t.Fatal(err)
	}
	for _, ttl := range []string{"never", "365d", ""} {
		w := saReq(h, http.MethodPost, ServiceAccountsPath+"?name=bot", "admin", `{"ttl":"`+ttl+`"}`)
		if w.Code != http.StatusBadRequest {
			t.Errorf("ttl %q: status = %d, want 400", ttl, w.Code)
		}
	}
	if len(svc.calls) != 0 {
		t.Errorf("store called for a disallowed ttl: %v", svc.calls)
	}
}

func TestSAAdminCreateKeyUnknownAccountIs404(t *testing.T) {
	svc := &stubSASvc{saErr: apikey.ErrServiceAccountNotFound}
	w := saReq(newSAAdmin(t, svc), http.MethodPost, ServiceAccountsPath+"?name=ghost", "admin", `{"ttl":"30d"}`)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestSAAdminListKeys(t *testing.T) {
	svc := &stubSASvc{}
	w := saReq(newSAAdmin(t, svc), http.MethodGet, ServiceAccountsPath+"?name=bot", "admin", "")
	if w.Code != http.StatusOK || svc.name != "bot" {
		t.Fatalf("status = %d name=%q, want 200/bot", w.Code, svc.name)
	}
	if !strings.Contains(w.Body.String(), `"created_by":"a1@example.com"`) {
		t.Errorf("created_by missing: %s", w.Body.String())
	}
}

func TestSAAdminDisable(t *testing.T) {
	svc := &stubSASvc{}
	w := saReq(newSAAdmin(t, svc), http.MethodDelete, ServiceAccountsPath+"?name=bot", "admin", "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", w.Code)
	}
	if svc.calls[0] != "disable" || svc.name != "bot" || svc.bySub != "a1" {
		t.Errorf("got calls=%v name=%q by=%q", svc.calls, svc.name, svc.bySub)
	}
}

func TestSAAdminRevokeKey(t *testing.T) {
	svc := &stubSASvc{}
	w := saReq(newSAAdmin(t, svc), http.MethodDelete, ServiceAccountsPath+"?name=bot&key_id=k-9", "admin", "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", w.Code)
	}
	if svc.calls[0] != "revokeKey" || svc.name != "bot" || svc.keyID != "k-9" {
		t.Errorf("got calls=%v name=%q key=%q", svc.calls, svc.name, svc.keyID)
	}

	svc = &stubSASvc{keyErr: apikey.ErrInvalidKey}
	if w := saReq(newSAAdmin(t, svc), http.MethodDelete, ServiceAccountsPath+"?name=bot&key_id=nope", "admin", ""); w.Code != http.StatusNotFound {
		t.Errorf("unknown key: status = %d, want 404", w.Code)
	}
}

func TestSAAdminRejectsSubPathAndBareDelete(t *testing.T) {
	h := newSAAdmin(t, &stubSASvc{})
	if w := saReq(h, http.MethodGet, ServiceAccountsPath+"/bot", "admin", ""); w.Code != http.StatusNotFound {
		t.Errorf("sub-path: status = %d, want 404", w.Code)
	}
	if w := saReq(h, http.MethodDelete, ServiceAccountsPath, "admin", ""); w.Code != http.StatusBadRequest {
		t.Errorf("bare delete: status = %d, want 400", w.Code)
	}
}

func TestParseKeyTTLs(t *testing.T) {
	got, err := ParseKeyTTLs([]string{"30d", "never"})
	if err != nil {
		t.Fatal(err)
	}
	if got["30d"] != 30*24*time.Hour || got["never"] != 0 {
		t.Errorf("parsed = %v", got)
	}
	for _, bad := range [][]string{nil, {"30"}, {"0d"}, {"-1d"}, {"forever"}, {"1w"}} {
		if _, err := ParseKeyTTLs(bad); err == nil {
			t.Errorf("ParseKeyTTLs(%v) = nil error, want error", bad)
		}
	}
}

func TestNewServiceAccountAdminRequiresGroups(t *testing.T) {
	if _, err := NewServiceAccountAdmin(&stubSASvc{}, groupVerifier{}, nil, []string{"30d"}); err == nil {
		t.Fatal("expected error with no admin groups")
	}
}

// A service-account key is audited as sa-key with the sa:<name> principal.
func TestServiceAccountKeyAuditedAsSAKey(t *testing.T) {
	up := newUpstream(t)
	ca := &capAudit{}
	h := handlerWithKeys(t, up, ca, saKeyAuth{})

	if w := doKey(h, http.MethodGet, "/api/v1/indexes", "sa-key"); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	rec, ok := ca.last()
	if !ok {
		t.Fatal("no audit record")
	}
	if rec.AuthMethod != "sa-key" || rec.PrincipalSub != "sa:bot" {
		t.Errorf("audit = %q/%q, want sa-key/sa:bot", rec.AuthMethod, rec.PrincipalSub)
	}
}

type saKeyAuth struct{}

func (saKeyAuth) Authenticate(context.Context, string) (*oidc.Claims, error) {
	return &oidc.Claims{Subject: apikey.ServiceAccountSubjectPrefix + "bot"}, nil
}
