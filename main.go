package main

import (
	"errors"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/opalsecurity/opal-1password-connector/internal/op"
	"github.com/opalsecurity/opal-1password-connector/onepasswordconnector"
)

func main() {
	signingSecret := os.Getenv("OPAL_SIGNING_SECRET")
	if signingSecret == "" {
		log.Fatal("OPAL_SIGNING_SECRET is required")
	}
	port := envOr("PORT", "8080")

	connector := onepasswordconnector.NewConnector(newClient(), time.Now)
	log.Printf("1Password connector listening on :%s", port)
	log.Fatal(onepasswordconnector.NewServer(connector, signingSecret).Run(":" + port))
}

// newClient picks the `op` backend: OP_FAKE=1 serves an in-memory demo account; OP_PASSWORD signs in
// as the admin identity (production); otherwise `op` uses the desktop app integration (local only).
func newClient() *op.Client {
	if os.Getenv("OP_FAKE") == "1" {
		log.Print("OP_FAKE=1: serving an in-memory demo 1Password account")
		return op.NewClient(op.NewDemoAccount().Exec(), nil, "")
	}
	exec := op.BinaryExec(envOr("OP_BIN", "op"))
	if os.Getenv("OP_PASSWORD") == "" {
		log.Print("OP_PASSWORD unset: using the 1Password desktop app integration")
		return op.NewClient(exec, nil, os.Getenv("OP_ACCOUNT"))
	}
	// With the desktop app's CLI integration on, `op signin --raw` defers to the app and prints no
	// session token. The connector must authenticate with its own credentials, never the app.
	if err := os.Setenv("OP_BIOMETRIC_UNLOCK_ENABLED", "false"); err != nil {
		log.Fatal(err)
	}
	// Kubernetes' fsGroup ownership change makes a mounted OP_CONFIG_DIR group-accessible on every pod
	// start, and `op` refuses a config directory that isn't 0700 or a config file that isn't 0600.
	if dir := os.Getenv("OP_CONFIG_DIR"); dir != "" {
		restrict(dir, 0o700)
		restrict(filepath.Join(dir, "config"), 0o600)
	}
	session := op.NewSession(exec, op.Credentials{
		Address:   envOr("OP_ACCOUNT_ADDRESS", "my.1password.com"),
		Email:     os.Getenv("OP_EMAIL"),
		SecretKey: os.Getenv("OP_SECRET_KEY"),
		Password:  os.Getenv("OP_PASSWORD"),
	}, time.Now)
	return op.NewClient(exec, session, "")
}

func restrict(path string, mode fs.FileMode) {
	if err := os.Chmod(path, mode); err != nil && !errors.Is(err, fs.ErrNotExist) {
		log.Fatal(err)
	}
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
