package op

import (
	"context"
	"errors"
	"testing"
)

func TestClassify(t *testing.T) {
	for _, k := range stderrKinds {
		t.Run(k.substr, func(t *testing.T) {
			err := Classify("[ERROR] 2026/10/13 12:00:00 " + k.substr + " (details)")
			if !errors.Is(err, k.kind) {
				t.Fatalf("Classify(%q) = %v, want %v", k.substr, err.Kind, k.kind)
			}
		})
	}
	t.Run("unknown", func(t *testing.T) {
		if err := Classify("[ERROR] something new"); !errors.Is(err, ErrUnknown) {
			t.Fatalf("got %v, want ErrUnknown", err.Kind)
		}
	})
	t.Run("inherited grant wins over not found wording", func(t *testing.T) {
		if err := Classify(`the accessor doesn't have any permissions: user not found in vault acl`); !errors.Is(err, ErrNoDirectAccess) {
			t.Fatalf("got %v, want ErrNoDirectAccess", err.Kind)
		}
	})
}

func TestBinaryExecKeepsShellMetacharactersInOneArg(t *testing.T) {
	arg := `vault"; rm -rf / $(whoami) | cat`
	out, err := BinaryExec("/bin/echo")(context.Background(), []string{arg}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(out); got != arg+"\n" {
		t.Fatalf("echo output = %q, want %q", got, arg+"\n")
	}
}

func TestBinaryExecClassifiesStderr(t *testing.T) {
	_, err := BinaryExec("/bin/sh")(context.Background(), []string{"-c", `echo '[ERROR] "x" isn'"'"'t a vault in this account' >&2; exit 1`}, nil, "")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestBinaryExecMissingBinaryIsUnknown(t *testing.T) {
	_, err := BinaryExec("/nonexistent/op")(context.Background(), nil, nil, "")
	if !errors.Is(err, ErrUnknown) {
		t.Fatalf("got %v, want ErrUnknown", err)
	}
}

func TestTwoFactorIsNotRetriedAsAuth(t *testing.T) {
	for _, stderr := range []string{
		"[ERROR] authentication required: enter the one-time password for your account",
		// Verbatim from `op` 2.34.0 when `op account add` runs without a TTY on a 2FA identity.
		"Enter your six-digit authentication code: [ERROR] 2026/10/17 15:37:12 incorrect One-Time Password length. expected 6",
	} {
		if err := Classify(stderr); !errors.Is(err, ErrTwoFactor) {
			t.Fatalf("Classify(%q) = %v, want ErrTwoFactor", stderr, err.Kind)
		}
	}
}
