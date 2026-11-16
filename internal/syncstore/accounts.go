package syncstore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/argon2"
)

var accountLoginPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

func normalizedLogin(login string) string {
	return strings.ToLower(strings.TrimSpace(login))
}

func ValidAccountPassword(password string) bool {
	return len(password) >= 12 && len(password) <= 1024
}

type accountEnvelope struct {
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type passwordAccount struct {
	User                           User
	salt, hash, envelope, recovery []byte
}

const argonMemoryKiB = 64 * 1024

func accountKDF(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 2, argonMemoryKiB, 1, 32)
}

func (a passwordAccount) verify(password string) bool {
	hash := accountKDF(password, a.salt)
	defer clear(hash)
	return subtle.ConstantTimeCompare(hash, a.hash) == 1
}

func randomBytes(size int) []byte {
	data := make([]byte, size)
	rand.Read(data)
	return data
}

func accountAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func accountAAD(id string) []byte { return []byte("xsync:account:v1:" + id) }

func sealAccountKey(key, wrapping []byte, id string) ([]byte, error) {
	aead, err := accountAEAD(wrapping)
	if err != nil {
		return nil, err
	}
	nonce := randomBytes(aead.NonceSize())
	return aead.Seal(nonce, nonce, key, accountAAD(id)), nil
}

func openAccountKey(sealed, wrapping []byte, id string) ([]byte, error) {
	aead, err := accountAEAD(wrapping)
	if err != nil {
		return nil, err
	}
	if len(sealed) != aead.NonceSize()+32+aead.Overhead() {
		return nil, errors.New("invalid account key envelope")
	}
	return aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], accountAAD(id))
}

func passwordEnvelope(key []byte, password, id string) ([]byte, error) {
	salt := randomBytes(16)
	wrapping := accountKDF(password, salt)
	defer clear(wrapping)
	sealed, err := sealAccountKey(key, wrapping, id)
	if err != nil {
		return nil, err
	}
	b64 := base64.RawStdEncoding
	return json.Marshal(accountEnvelope{b64.EncodeToString(salt), b64.EncodeToString(sealed[:12]), b64.EncodeToString(sealed[12:])})
}

func (a passwordAccount) open(password string) ([]byte, error) {
	var envelope accountEnvelope
	if err := json.Unmarshal(a.envelope, &envelope); err != nil {
		return nil, err
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(envelope.Salt)
	if err != nil || len(salt) != 16 {
		return nil, errors.New("invalid account key salt")
	}
	nonce, err := b64.DecodeString(envelope.Nonce)
	if err != nil || len(nonce) != 12 {
		return nil, errors.New("invalid account key nonce")
	}
	ciphertext, err := b64.DecodeString(envelope.Ciphertext)
	if err != nil {
		return nil, err
	}
	wrapping := accountKDF(password, salt)
	defer clear(wrapping)
	return openAccountKey(append(nonce, ciphertext...), wrapping, a.User.ID)
}

func (m *ManagedServer) passwordAccount(ctx context.Context, login string) (passwordAccount, error) {
	var a passwordAccount
	err := m.Pool.QueryRow(ctx, `SELECT u.id,u.name,u.active,u.key_revision,p.password_salt,p.password_hash,p.key_envelope,p.recovery_envelope
		FROM sync_users u JOIN password_accounts p ON p.user_id=u.id WHERE u.name_key=$1 AND u.deleted_at IS NULL`, normalizedLogin(login)).
		Scan(&a.User.ID, &a.User.Name, &a.User.Active, &a.User.Revision, &a.salt, &a.hash, &a.envelope, &a.recovery)
	return a, err
}

func (m *ManagedServer) AddPasswordUser(ctx context.Context, login, password string, recoveryKey []byte) error {
	login = normalizedLogin(login)
	if !accountLoginPattern.MatchString(login) {
		return errors.New("login must use 1–64 letters, digits, dots, dashes or underscores")
	}
	if !ValidAccountPassword(password) {
		return errors.New("password must be 12–1024 bytes")
	}
	id := opaqueID()
	key := randomBytes(32)
	defer clear(key)
	recovery, err := sealAccountKey(key, recoveryKey, id)
	if err != nil {
		return err
	}
	envelope, err := passwordEnvelope(key, password, id)
	if err != nil {
		return err
	}
	salt := randomBytes(16)
	hash := accountKDF(password, salt)
	tx, err := m.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, "INSERT INTO sync_users(id,name,name_key,key_tail) VALUES($1,$2,$2,'')", id, login)
	if err != nil {
		return controlError(err)
	}
	if _, err = tx.Exec(ctx, "INSERT INTO password_accounts VALUES($1,$2,$3,$4,$5)", id, salt, hash, envelope, recovery); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (m *ManagedServer) ResetAccountPassword(ctx context.Context, login, password string, recoveryKey []byte) error {
	if !ValidAccountPassword(password) {
		return errors.New("password must be 12–1024 bytes")
	}
	a, err := m.passwordAccount(ctx, login)
	if errors.Is(err, pgx.ErrNoRows) {
		return code("USER_NOT_FOUND")
	}
	if err != nil {
		return err
	}
	key, err := openAccountKey(a.recovery, recoveryKey, a.User.ID)
	if err != nil {
		return errors.New("could not recover account key; check the deployment recovery key")
	}
	defer clear(key)
	return m.replacePassword(ctx, a.User, key, password)
}

func (m *ManagedServer) replacePassword(ctx context.Context, user User, key []byte, password string) error {
	envelope, err := passwordEnvelope(key, password, user.ID)
	if err != nil {
		return err
	}
	salt := randomBytes(16)
	hash := accountKDF(password, salt)
	tx, err := m.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, "UPDATE sync_users SET key_revision=key_revision+1 WHERE id=$1 AND key_revision=$2 AND active AND deleted_at IS NULL", user.ID, user.Revision)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return code("UNAUTHORIZED")
	}
	if _, err = tx.Exec(ctx, "UPDATE password_accounts SET password_salt=$2,password_hash=$3,key_envelope=$4 WHERE user_id=$1", user.ID, salt, hash, envelope); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "DELETE FROM account_sessions WHERE user_id=$1", user.ID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
