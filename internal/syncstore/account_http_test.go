package syncstore

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPasswordAccountLifecycle(t *testing.T) {
	dsn := os.Getenv("XSYNC_ACCOUNT_TEST_DSN")
	if dsn == "" {
		t.Skip("set XSYNC_ACCOUNT_TEST_DSN to an isolated PostgreSQL instance")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	cfg := pool.Config().ConnConfig
	if cfg.Host != "127.0.0.1" {
		t.Fatal("this test requires loopback PostgreSQL")
	}
	cfg.RuntimeParams["search_path"] = "account_test_" + opaqueID()[:16]
	schema := cfg.RuntimeParams["search_path"]
	if _, err = pool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer pool.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
	// ConnString returns the original DSN, so set search_path on the parsed URL explicitly.
	separator := "?"
	if strings.Contains(dsn, "?") {
		separator = "&"
	}
	server, err := NewManagedServer(ctx, Config{DSN: dsn + separator + "search_path=" + schema, ObjectDir: t.TempDir()}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	assert := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	handler := server.Handler()
	call := func(method, path, token string, body any, status int) []byte {
		t.Helper()
		var reader io.Reader
		if body != nil {
			encoded, err := json.Marshal(body)
			assert(err)
			reader = bytes.NewReader(encoded)
		}
		r := httptest.NewRequest(method, path, reader)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, r)
		if out.Code != status {
			t.Fatalf("%s %s got %d: %s", method, path, out.Code, out.Body)
		}
		return out.Body.Bytes()
	}
	login := func(name, password string) (string, passwordAccount, []byte) {
		t.Helper()
		var reply struct {
			Token       string
			ServerID    string
			User        User
			KeyEnvelope json.RawMessage
		}
		body := call("POST", "/api/auth/login", "", map[string]string{"login": name, "password": password}, 200)
		assert(json.Unmarshal(body, &reply))
		if len(reply.ServerID) != 64 {
			t.Fatal("server identity missing")
		}
		a, err := server.passwordAccount(ctx, name)
		assert(err)
		a.envelope = reply.KeyEnvelope
		key, err := a.open(password)
		assert(err)
		return reply.Token, a, key
	}

	count := -1
	assert(server.Pool.QueryRow(ctx, "SELECT count(*) FROM sync_users").Scan(&count))
	if count != 0 {
		t.Fatal("deployment must be empty")
	}
	recovery := randomBytes(32)
	const original = "original-password"
	const changed = "updated-password"
	const reset = "recovered-password"
	assert(server.AddPasswordUser(ctx, "alice", original, recovery))
	assert(server.AddPasswordUser(ctx, "friend", original, recovery))
	if err = server.AddPasswordUser(ctx, "ALICE", original, recovery); err == nil {
		t.Fatal("duplicate login accepted")
	}
	aliceToken, alice, key := login("alice", original)
	friendToken, friend, _ := login("friend", original)
	vault := managedVault(t, server, alice.User, "Alice's encrypted vault")
	deviceToken := opaqueID()
	enroll := map[string]string{"deviceId": "alice-mac", "name": "Alice's Mac", "tokenHash": stringHash(deviceToken)}
	call("POST", "/api/vaults/"+vault.ID+"/devices", friendToken, enroll, 401)
	call("POST", "/api/vaults/"+vault.ID+"/devices", aliceToken, enroll, 200)
	call("GET", "/sync/"+vault.ID+"/handshake", friendToken, nil, 401)
	store, err := server.store(ctx, vault.ID)
	assert(err)
	_, err = store.Authorize(ctx, deviceToken)
	assert(err)
	otherVault := managedVault(t, server, friend.User, "Friend's encrypted vault")
	other, err := server.store(ctx, otherVault.ID)
	assert(err)
	if _, err = other.Authorize(ctx, deviceToken); err == nil {
		t.Fatal("cross-vault device token accepted")
	}

	data := []byte("synthetic ciphertext")
	id := opaqueID()
	assert(store.PutObject(ctx, id, stringHash(string(data)), data))
	call("GET", "/api/storage/usage", "", nil, 401)
	var report struct {
		TotalBytes int
		Accounts   []struct {
			Login string
			Bytes int
			Self  bool
		}
	}
	assert(json.Unmarshal(call("GET", "/api/storage/usage", friendToken, nil, 200), &report))
	if report.TotalBytes != len(data) || len(report.Accounts) != 2 ||
		report.Accounts[0].Login != "alice" || report.Accounts[0].Bytes != len(data) || !report.Accounts[1].Self {
		t.Fatalf("unexpected storage report: %+v", report)
	}

	call("POST", "/api/auth/password", aliceToken, map[string]string{"currentPassword": original, "newPassword": changed}, 200)
	call("GET", "/api/connection", aliceToken, nil, 401)
	if _, err = store.Authorize(ctx, deviceToken); err == nil {
		t.Fatal("password change preserved a stale device token")
	}
	changedToken, _, updatedKey := login("alice", changed)
	if !bytes.Equal(key, updatedKey) {
		t.Fatal("password change replaced the account key")
	}
	if err = server.ResetAccountPassword(ctx, "alice", reset, randomBytes(32)); err == nil {
		t.Fatal("wrong recovery key accepted")
	}
	assert(server.ResetAccountPassword(ctx, "alice", reset, recovery))
	call("GET", "/api/connection", changedToken, nil, 401)
	finalToken, _, finalKey := login("alice", reset)
	if !bytes.Equal(key, finalKey) {
		t.Fatal("password reset replaced the account key")
	}
	if latest := call("GET", "/api/connection", finalToken, nil, 200); !bytes.Contains(latest, []byte(vault.ID)) {
		t.Fatal("password reset lost the original vault")
	}
}
