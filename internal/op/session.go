package op

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Sessions expire after 30 minutes of inactivity; refresh with margin.
const refreshAfter = 25 * time.Minute

// bootstrapCooldown spaces out retries of an `op account add` that failed, or an `op signin` that
// 1Password answered with a 2FA prompt. Both mean this device has not passed 2FA yet; retrying on every
// request would hammer 1Password with failed sign-ins and race an operator bootstrapping the device by
// hand in the same OP_CONFIG_DIR.
const bootstrapCooldown = 5 * time.Minute

// ErrBootstrap marks a device that needs a one-time bootstrap by hand: a 2FA-enabled identity cannot
// add or first sign in on a device without its one-time code. It also wraps the cooldown error, so every
// request in that state reports the same upstream failure.
var ErrBootstrap = errors.New(
	"this device needs a one-time 2FA bootstrap by hand (see README: 2FA and device bootstrap)",
)

// Credentials identify the dedicated 1Password admin identity.
type Credentials struct {
	Address   string
	Email     string
	SecretKey string
	Password  string
}

// Session holds a `op signin --raw` token and refreshes it single-flight: `op` is not safe to
// re-authenticate concurrently, so the mutex is held across the signin exec.
type Session struct {
	exec  Exec
	creds Credentials
	now   func() time.Time

	mu       sync.Mutex
	token    string
	lastUsed time.Time
	account  string // resolved once; cleared when signin fails so a changed config is re-resolved
	// No `op account add` / `op signin` before these; set when one needs a bootstrap by hand.
	addAfter    time.Time
	signinAfter time.Time
}

func NewSession(exec Exec, creds Credentials, now func() time.Time) *Session {
	return &Session{exec: exec, creds: creds, now: now}
}

// Token returns a live session token, signing in when there is none or it is near idle expiry.
func (s *Session) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token == "" || s.now().Sub(s.lastUsed) >= refreshAfter {
		token, err := s.signIn(ctx)
		if err != nil {
			return "", err
		}
		s.token = token
	}
	s.lastUsed = s.now()
	return s.token, nil
}

// Invalidate drops the cached token so the next Token call signs in again. It only acts when the
// cache still holds the token that failed, so a concurrent refresh is not thrown away.
func (s *Session) Invalidate(failed string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token == failed {
		s.token = ""
	}
}

func (s *Session) signIn(ctx context.Context) (string, error) {
	if s.account == "" {
		account, err := s.accountUUID(ctx)
		if err != nil {
			return "", err
		}
		s.account = account
	}
	if s.now().Before(s.signinAfter) {
		return "", fmt.Errorf("%w (retrying op signin after %s)", ErrBootstrap, s.signinAfter.Format(time.RFC3339))
	}
	out, err := s.exec(
		ctx,
		[]string{"signin", "--account", s.account, "--raw"},
		nil,
		s.creds.Password+"\n",
	)
	if err != nil {
		s.account = ""
		// The account is in OP_CONFIG_DIR but this device never passed 2FA, e.g. it was added before 2FA
		// was turned on for the identity or enforced for the account.
		if errors.Is(err, ErrTwoFactor) {
			s.signinAfter = s.now().Add(bootstrapCooldown)
			return "", fmt.Errorf("%w: op signin: %w", ErrBootstrap, err)
		}
		return "", fmt.Errorf("op signin: %w", err)
	}
	token := strings.TrimSpace(string(out))
	if token == "" {
		return "", fmt.Errorf("op signin returned no session token")
	}
	return token, nil
}

// accountUUID finds the account in OP_CONFIG_DIR, adding it non-interactively on first run.
func (s *Session) accountUUID(ctx context.Context) (string, error) {
	// Checked before the cooldown so an account an operator just added is picked up immediately.
	if uuid, err := s.findAccount(ctx); err != nil || uuid != "" {
		return uuid, err
	}
	if s.now().Before(s.addAfter) {
		return "", fmt.Errorf("%w (retrying op account add after %s)", ErrBootstrap, s.addAfter.Format(time.RFC3339))
	}
	_, err := s.exec(ctx,
		[]string{"account", "add", "--address", s.creds.Address, "--email", s.creds.Email},
		[]string{"OP_SECRET_KEY=" + s.creds.SecretKey},
		s.creds.Password+"\n",
	)
	if err != nil {
		s.addAfter = s.now().Add(bootstrapCooldown)
		return "", fmt.Errorf("%w: op account add: %w", ErrBootstrap, err)
	}
	uuid, err := s.findAccount(ctx)
	if err == nil && uuid == "" {
		err = fmt.Errorf("account %s not found after op account add", s.creds.Address)
	}
	return uuid, err
}

func (s *Session) findAccount(ctx context.Context) (string, error) {
	out, err := s.exec(ctx, []string{"account", "list", "--format=json"}, nil, "")
	if err != nil {
		return "", fmt.Errorf("op account list: %w", err)
	}
	var accounts []struct {
		URL         string `json:"url"`
		Email       string `json:"email"`
		AccountUUID string `json:"account_uuid"`
	}
	if err := json.Unmarshal(out, &accounts); err != nil {
		return "", fmt.Errorf("op account list: %w", err)
	}
	address := strings.TrimPrefix(s.creds.Address, "https://")
	for _, a := range accounts {
		if strings.EqualFold(a.Email, s.creds.Email) &&
			strings.TrimPrefix(a.URL, "https://") == address {
			return a.AccountUUID, nil
		}
	}
	return "", nil
}
