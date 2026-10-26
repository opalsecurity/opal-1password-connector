package op

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"
)

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

var testCreds = Credentials{Address: "fake.1password.com", Email: "admin@example.com", SecretKey: "A3-SECRET", Password: "hunter2"}

func countCommand(f *FakeAccount, command string) int {
	n := 0
	for _, call := range f.Calls {
		if parseArgs(call).command == command {
			n++
		}
	}
	return n
}

func accountType(client *Client) error {
	_, err := client.AccountType(context.Background())
	return err
}

func newSessionClient() (*FakeAccount, *clock, *Client) {
	fake := NewDemoAccount()
	clk := &clock{now: time.Unix(1_700_000_000, 0)}
	session := NewSession(fake.Exec(), testCreds, clk.Now)
	return fake, clk, NewClient(fake.Exec(), session, "")
}

func TestSessionReusesTokenWithinTTL(t *testing.T) {
	fake, clk, client := newSessionClient()
	for range 5 {
		if err := accountType(client); err != nil {
			t.Fatal(err)
		}
		clk.Advance(20 * time.Minute)
	}
	if n := countCommand(fake, "signin"); n != 1 {
		t.Fatalf("signed in %d times, want 1", n)
	}
	last := fake.Calls[len(fake.Calls)-1]
	if i := slices.Index(last, "--session"); i < 0 || last[i+1] != "fake-session-token" {
		t.Fatalf("command did not carry the session token: %v", last)
	}
}

func TestSessionRefreshesAfterIdle(t *testing.T) {
	fake, clk, client := newSessionClient()
	_ = accountType(client)
	clk.Advance(25 * time.Minute)
	_ = accountType(client)
	if n := countCommand(fake, "signin"); n != 2 {
		t.Fatalf("signed in %d times, want 2", n)
	}
}

func TestSessionSingleFlightUnderConcurrency(t *testing.T) {
	fake, _, client := newSessionClient()
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = accountType(client)
		}()
	}
	wg.Wait()
	if n := countCommand(fake, "signin"); n != 1 {
		t.Fatalf("signed in %d times, want 1", n)
	}
}

func TestSessionAddsAccountNonInteractively(t *testing.T) {
	var addEnv []string
	var addStdin, signinStdin string
	added := false
	exec := func(_ context.Context, args, env []string, stdin string) ([]byte, error) {
		switch parseArgs(args).command {
		case "account list":
			if !added {
				return []byte(`[]`), nil
			}
			return []byte(`[{"url":"fake.1password.com","email":"admin@example.com","account_uuid":"UUID1"}]`), nil
		case "account add":
			added, addEnv, addStdin = true, env, stdin
			return nil, nil
		case "signin":
			if !slices.Equal(args, []string{"signin", "--account", "UUID1", "--raw"}) {
				t.Errorf("signin argv = %v", args)
			}
			signinStdin = stdin
			return []byte("tok\n"), nil
		}
		return nil, errors.New("unexpected command")
	}
	token, err := NewSession(exec, testCreds, time.Now).Token(context.Background())
	if err != nil || token != "tok" {
		t.Fatalf("Token() = %q, %v", token, err)
	}
	if !slices.Equal(addEnv, []string{"OP_SECRET_KEY=A3-SECRET"}) {
		t.Fatalf("account add env = %v", addEnv)
	}
	if addStdin != "hunter2\n" || signinStdin != "hunter2\n" {
		t.Fatal("password was not piped on stdin")
	}
}

func TestClientRetriesOnceOnAuthError(t *testing.T) {
	fake, _, client := newSessionClient()
	failures := 1
	fake.Fail = func(args []string) error {
		if parseArgs(args).command == "account get" && failures > 0 {
			failures--
			return Classify("[ERROR] You are not currently signed in.")
		}
		return nil
	}
	if err := accountType(client); err != nil {
		t.Fatalf("expected retry to succeed, got %v", err)
	}
	if n := countCommand(fake, "signin"); n != 2 {
		t.Fatalf("signed in %d times, want 2", n)
	}

	failures = 10
	if err := accountType(client); !errors.Is(err, ErrAuth) {
		t.Fatalf("expected ErrAuth after one retry, got %v", err)
	}
	if n := countCommand(fake, "account get"); n != 4 {
		t.Fatalf("account get ran %d times, want 4 (2 per call)", n)
	}
}

func TestRateLimitIsClassified(t *testing.T) {
	fake, _, client := newSessionClient()
	fake.Fail = func(args []string) error {
		if parseArgs(args).command == "user list" {
			return Classify("[ERROR] Too many requests. Try again later.")
		}
		return nil
	}
	if _, err := client.ListUsers(context.Background()); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("got %v, want ErrRateLimited", err)
	}
	if n := countCommand(fake, "user list"); n != 1 {
		t.Fatalf("user list ran %d times; rate limits must not trigger re-auth retries", n)
	}
}

func TestInvalidateIgnoresAlreadyRefreshedToken(t *testing.T) {
	fake := NewDemoAccount()
	clk := &clock{now: time.Unix(1_700_000_000, 0)}
	session := NewSession(fake.Exec(), testCreds, clk.Now)
	ctx := context.Background()
	if _, err := session.Token(ctx); err != nil {
		t.Fatal(err)
	}
	session.Invalidate("stale-token")
	before := countCommand(fake, "signin")
	if _, err := session.Token(ctx); err != nil {
		t.Fatal(err)
	}
	if got := countCommand(fake, "signin"); got != before {
		t.Fatalf("signin ran %d times after a stale Invalidate, want %d", got, before)
	}
}

func TestSessionBacksOffAfterFailedAccountAdd(t *testing.T) {
	adds, added := 0, false
	exec := func(_ context.Context, args, _ []string, _ string) ([]byte, error) {
		switch parseArgs(args).command {
		case "account list":
			if !added {
				return []byte(`[]`), nil
			}
			return []byte(`[{"url":"fake.1password.com","email":"admin@example.com","account_uuid":"UUID1"}]`), nil
		case "account add":
			adds++
			return nil, Classify("[ERROR] Enter your six-digit authentication code: EOF")
		case "signin":
			return []byte("tok\n"), nil
		}
		return nil, errors.New("unexpected command")
	}
	clk := &clock{now: time.Unix(1_700_000_000, 0)}
	session := NewSession(exec, testCreds, clk.Now)
	ctx := context.Background()

	if _, err := session.Token(ctx); !errors.Is(err, ErrTwoFactor) || !errors.Is(err, ErrBootstrap) {
		t.Fatalf("Token() error = %v, want ErrTwoFactor wrapped in ErrBootstrap", err)
	}
	clk.Advance(bootstrapCooldown - time.Second)
	if _, err := session.Token(ctx); !errors.Is(err, ErrBootstrap) || adds != 1 {
		t.Fatalf("Token() = %v with %d adds; want the cooldown to skip `op account add`", err, adds)
	}

	t.Run("an account added by hand is used within the cooldown", func(t *testing.T) {
		added = true
		defer func() { added = false }()
		if token, err := session.Token(ctx); err != nil || token != "tok" {
			t.Fatalf("Token() = %q, %v", token, err)
		}
		session.Invalidate("tok")
		session.account = ""
	})

	clk.Advance(time.Second)
	_, _ = session.Token(ctx)
	if adds != 2 {
		t.Fatalf("account add ran %d times, want a retry once the cooldown passed", adds)
	}
}

func TestSessionBacksOffWhenSigninWantsTwoFactor(t *testing.T) {
	signins, trusted := 0, false
	exec := func(_ context.Context, args, _ []string, _ string) ([]byte, error) {
		switch parseArgs(args).command {
		case "account list":
			return []byte(`[{"url":"fake.1password.com","email":"admin@example.com","account_uuid":"UUID1"}]`), nil
		case "signin":
			signins++
			if !trusted {
				return nil, Classify("Enter your six-digit authentication code: [ERROR] incorrect One-Time Password length. expected 6")
			}
			return []byte("tok\n"), nil
		}
		return nil, errors.New("unexpected command")
	}
	clk := &clock{now: time.Unix(1_700_000_000, 0)}
	session := NewSession(exec, testCreds, clk.Now)
	ctx := context.Background()

	if _, err := session.Token(ctx); !errors.Is(err, ErrTwoFactor) || !errors.Is(err, ErrBootstrap) {
		t.Fatalf("Token() error = %v, want ErrTwoFactor wrapped in ErrBootstrap", err)
	}
	trusted = true // an operator signs in by hand with the code
	clk.Advance(bootstrapCooldown - time.Second)
	if _, err := session.Token(ctx); !errors.Is(err, ErrBootstrap) || signins != 1 {
		t.Fatalf("Token() = %v with %d signins; want the cooldown to skip `op signin`", err, signins)
	}
	clk.Advance(time.Second)
	if token, err := session.Token(ctx); err != nil || token != "tok" || signins != 2 {
		t.Fatalf("Token() = %q, %v with %d signins; want one retry once the cooldown passed", token, err, signins)
	}
}
