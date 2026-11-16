package syncstore

import (
	"encoding/json"
	"errors"
	"net/http"
	"syscall"

	"github.com/jackc/pgx/v5"
)

func (m *ManagedServer) startAccountWork(w http.ResponseWriter, r *http.Request) bool {
	if m.allowLogin(r) {
		select {
		case m.accountWork <- struct{}{}:
			return true
		default:
		}
	}
	writeError(w, code("LOGIN_RATE_LIMITED"))
	return false
}

func (m *ManagedServer) accountLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if err := decodeBody(w, r, &in); err != nil {
		writeError(w, err)
		return
	}
	if !m.startAccountWork(w, r) {
		return
	}
	defer func() { <-m.accountWork }()
	ctx := r.Context()
	if !ValidAccountPassword(in.Password) {
		writeError(w, code("UNAUTHORIZED"))
		return
	}
	a, err := m.passwordAccount(ctx, in.Login)
	if errors.Is(err, pgx.ErrNoRows) {
		// Unknown accounts still incur the same password derivation cost.
		a.salt, a.hash = make([]byte, 16), make([]byte, 32)
	} else if err != nil {
		writeError(w, err)
		return
	}
	if !a.verify(in.Password) || !a.User.Active {
		writeError(w, code("UNAUTHORIZED"))
		return
	}
	tx, err := m.Pool.Begin(ctx)
	if err != nil {
		writeError(w, err)
		return
	}
	defer tx.Rollback(ctx)
	var revision int64
	if err = tx.QueryRow(ctx, "SELECT key_revision FROM sync_users WHERE id=$1 AND active AND deleted_at IS NULL FOR UPDATE", a.User.ID).Scan(&revision); err != nil || revision != a.User.Revision {
		writeError(w, code("UNAUTHORIZED"))
		return
	}
	token := "xsk_" + opaqueID()
	if _, err = tx.Exec(ctx, "DELETE FROM account_sessions WHERE expires_at<=now()"); err == nil {
		_, err = tx.Exec(ctx, "INSERT INTO account_sessions VALUES($1,$2,$3,now()+interval '30 days')", hashSecret(token), a.User.ID, revision)
	}
	var serverID string
	if err == nil {
		err = tx.QueryRow(ctx, "SELECT id FROM account_server").Scan(&serverID)
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "serverId": serverID, "user": a.User, "keyEnvelope": json.RawMessage(a.envelope)})
}

func (m *ManagedServer) accountPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u, err := m.access(ctx, bearer(r))
	if err != nil {
		writeError(w, err)
		return
	}
	var in struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	if err = decodeBody(w, r, &in); err != nil {
		writeError(w, err)
		return
	}
	if !ValidAccountPassword(in.NewPassword) {
		writeError(w, code("INVALID_REQUEST"))
		return
	}
	if !m.startAccountWork(w, r) {
		return
	}
	defer func() { <-m.accountWork }()
	a, err := m.passwordAccount(ctx, u.Name)
	if err != nil || a.User.Revision != u.Revision || !ValidAccountPassword(in.CurrentPassword) || !a.verify(in.CurrentPassword) {
		writeError(w, code("UNAUTHORIZED"))
		return
	}
	key, err := a.open(in.CurrentPassword)
	if err != nil {
		writeError(w, err)
		return
	}
	defer clear(key)
	if err = m.replacePassword(ctx, u, key, in.NewPassword); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"changed": true})
}

func (m *ManagedServer) accountUsage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, err := m.access(ctx, bearer(r))
	if err != nil {
		writeError(w, err)
		return
	}
	rows, err := m.Pool.Query(ctx, `SELECT u.name, COALESCE(SUM(o.size),0)::bigint AS bytes, u.id=$1
		FROM sync_users u JOIN password_accounts p ON p.user_id=u.id
		LEFT JOIN vault_owners v ON v.user_id=u.id
		LEFT JOIN objects o ON o.vault_id=v.vault_id AND o.state IN ('ready','candidate')
		WHERE u.deleted_at IS NULL GROUP BY u.id ORDER BY bytes DESC,u.name`, user.ID)
	if err != nil {
		writeError(w, err)
		return
	}
	defer rows.Close()
	type accountUsage struct {
		Login string `json:"login"`
		Bytes int64  `json:"bytes"`
		Self  bool   `json:"self"`
	}
	accounts := []accountUsage{}
	var total int64
	for rows.Next() {
		var account accountUsage
		if err = rows.Scan(&account.Login, &account.Bytes, &account.Self); err != nil {
			writeError(w, err)
			return
		}
		accounts = append(accounts, account)
		total += account.Bytes
	}
	if err = rows.Err(); err != nil {
		writeError(w, err)
		return
	}
	var disk syscall.Statfs_t
	if err = syscall.Statfs(m.config.ObjectDir, &disk); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accounts": accounts, "totalBytes": total, "freeBytes": uint64(disk.Bavail) * uint64(disk.Bsize)})
}
