package syncstore

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestObsidianMobileCORS(t *testing.T) {
	const origin = "capacitor://localhost"
	handler := (&ManagedServer{passwordAccounts: true}).Handler()
	for _, test := range []struct {
		path, method, header string
	}{
		{"/api/auth/login", "POST", "content-type"},
		{"/sync/vault/objects/object", "PUT", "authorization, x-content-lease, x-ciphertext-sha256"},
	} {
		request := httptest.NewRequest(http.MethodOptions, test.path, nil)
		request.Header.Set("Origin", origin)
		request.Header.Set("Access-Control-Request-Method", test.method)
		request.Header.Set("Access-Control-Request-Headers", test.header)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent || response.Header().Get("Access-Control-Allow-Origin") != origin {
			t.Fatalf("preflight %s: %d %v", test.path, response.Code, response.Header())
		}
		if !strings.Contains(response.Header().Get("Access-Control-Allow-Methods"), test.method) {
			t.Fatalf("preflight does not allow %s", test.method)
		}
		for _, name := range strings.Split(test.header, ", ") {
			if !strings.Contains(strings.ToLower(response.Header().Get("Access-Control-Allow-Headers")), name) {
				t.Fatalf("preflight does not allow %s", name)
			}
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/sync/invalid-vault/handshake", nil)
	request.Header.Set("Origin", origin)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound || response.Header().Get("Access-Control-Allow-Origin") != origin ||
		response.Header().Get("Access-Control-Expose-Headers") != "X-Ciphertext-SHA256, X-Sync-Continuity-Token" {
		t.Fatalf("error response: %d %v", response.Code, response.Header())
	}

	for _, test := range []struct{ path, origin string }{
		{"/api/auth/login", "https://untrusted.example"},
		{"/admin/api/login", origin},
	} {
		request := httptest.NewRequest(http.MethodOptions, test.path, nil)
		request.Header.Set("Origin", test.origin)
		request.Header.Set("Access-Control-Request-Method", "POST")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code == http.StatusNoContent || response.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatalf("unexpected preflight success for %s at %s", test.origin, test.path)
		}
	}
}
