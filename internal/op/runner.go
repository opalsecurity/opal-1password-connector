// Package op drives the 1Password CLI (`op`).
//
// Every invocation is an argv slice passed straight to exec — never a shell string — and argv is
// never logged, because it carries `--session <token>`.
package op

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// waitDelay bounds how long Wait blocks on pipes after a cancelled process is killed.
const waitDelay = 5 * time.Second

// Exec runs `op` with args. env entries are appended to the process environment, stdin is piped in
// when non-empty. Failures are returned as *Error.
type Exec func(ctx context.Context, args, env []string, stdin string) ([]byte, error)

// BinaryExec runs the `op` binary at path bin.
func BinaryExec(bin string) Exec {
	return func(ctx context.Context, args, env []string, stdin string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Env = append(os.Environ(), env...)
		if stdin != "" {
			cmd.Stdin = strings.NewReader(stdin)
		}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		cmd.WaitDelay = waitDelay
		out, err := cmd.Output()
		if err != nil {
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) {
				// The process never ran (e.g. missing binary) or was cancelled; stderr says nothing.
				return nil, &Error{Kind: ErrUnknown, Stderr: err.Error()}
			}
			if stderr.Len() == 0 {
				stderr.WriteString(err.Error())
			}
			return nil, Classify(stderr.String())
		}
		return out, nil
	}
}

var (
	ErrAuth           = errors.New("1password session is not signed in")
	ErrTwoFactor      = errors.New("1password asked for a second factor (new device)")
	ErrNotFound       = errors.New("not found in 1password")
	ErrNoDirectAccess = errors.New(
		"principal has no direct permissions; access may be inherited from a 1password group",
	)
	ErrAlreadyMember = errors.New("already a member")
	ErrNotMember     = errors.New("not a member")
	ErrRateLimited   = errors.New("1password rate limit exceeded")
	ErrUnknown       = errors.New("1password cli error")
)

// Error is a classified `op` failure. Stderr never contains argv, so it is safe to surface.
type Error struct {
	Kind   error
	Stderr string
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Kind, e.Stderr) }
func (e *Error) Unwrap() error { return e.Kind }

// stderrKinds is ordered: the first matching substring wins. The strings are pinned to the `op`
// version in the Dockerfile; every entry is covered by runner_test.go.
var stderrKinds = []struct {
	substr string
	kind   error
}{
	{"doesn't have any permissions", ErrNoDirectAccess},
	{"already a member", ErrAlreadyMember},
	{"isn't a member", ErrNotMember},
	{"is not a member", ErrNotMember},
	// 2FA is only asked on a new device, i.e. when OP_CONFIG_DIR lost its device trust. Matched before
	// ErrAuth so a re-auth retry does not loop on it.
	{"two-factor", ErrTwoFactor},
	{"second factor", ErrTwoFactor},
	{"one-time password", ErrTwoFactor},
	{"authentication code", ErrTwoFactor},
	{"not currently signed in", ErrAuth},
	{"account is not signed in", ErrAuth},
	{"session expired", ErrAuth},
	{"invalid session token", ErrAuth},
	{"authentication required", ErrAuth},
	{"too many requests", ErrRateLimited},
	{"rate limit", ErrRateLimited},
	{"isn't a vault", ErrNotFound},
	{"isn't a user", ErrNotFound},
	{"isn't a group", ErrNotFound},
}

// Classify maps `op` stderr to an *Error.
func Classify(stderr string) *Error {
	stderr = strings.TrimSpace(stderr)
	lower := strings.ToLower(stderr)
	for _, k := range stderrKinds {
		if strings.Contains(lower, k.substr) {
			return &Error{Kind: k.kind, Stderr: stderr}
		}
	}
	return &Error{Kind: ErrUnknown, Stderr: stderr}
}
