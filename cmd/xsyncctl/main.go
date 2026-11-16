package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/term"
	"obsidiansync/server/internal/syncstore"
)

func readPassword() (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("run xsyncctl in an interactive terminal")
	}
	read := func(prompt string) ([]byte, error) {
		fmt.Fprint(os.Stderr, prompt)
		value, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		return value, err
	}
	password, err := read("Password: ")
	defer clear(password)
	if err != nil {
		return "", err
	}
	repeated, err := read("Repeat password: ")
	defer clear(repeated)
	if err != nil {
		return "", err
	}
	if string(password) != string(repeated) {
		return "", errors.New("passwords do not match")
	}
	if !syncstore.ValidAccountPassword(string(password)) {
		return "", errors.New("password must be non-empty and at most 1024 bytes")
	}
	return string(password), nil
}

func run() error {
	args := os.Args[1:]
	if len(args) != 3 || args[0] != "user" || (args[1] != "add" && args[1] != "passwd") {
		return errors.New("usage: xsyncctl user add|passwd LOGIN")
	}
	raw, err := os.ReadFile(os.Getenv("XSYNC_RECOVERY_KEY_FILE"))
	if err != nil {
		return errors.New("cannot read deployment recovery key")
	}
	defer clear(raw)
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != 32 {
		return errors.New("deployment recovery key must be 32 bytes encoded in hex")
	}
	defer clear(key)
	password, err := readPassword()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, os.Getenv("XSYNC_DATABASE_URL"))
	if err != nil {
		return errors.New("invalid database configuration")
	}
	defer pool.Close()
	manager := &syncstore.ManagedServer{Pool: pool}
	if args[1] == "add" {
		err = manager.AddPasswordUser(ctx, args[2], password, key)
	} else {
		err = manager.ResetAccountPassword(ctx, args[2], password, key)
	}
	if err == nil {
		fmt.Fprintln(os.Stdout, "Account saved.")
	}
	return err
}

func main() {
	log.SetFlags(0)
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
