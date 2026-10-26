package onepasswordconnector

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/opalsecurity/opal-1password-connector/internal/op"
)

const testSecret = "test-signing-secret"

var (
	testNow = time.Unix(1_700_000_000, 0)
	logs    syncBuffer
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	gin.DefaultWriter = &logs
	log.SetOutput(&logs)
	os.Exit(m.Run())
}

func newTestServer() (*op.FakeAccount, *gin.Engine) {
	fake := op.NewDemoAccount()
	now := func() time.Time { return testNow }
	session := op.NewSession(fake.Exec(), op.Credentials{Address: "fake.1password.com", Email: "admin@example.com", Password: "pw"}, now)
	return fake, NewServer(NewConnector(op.NewClient(fake.Exec(), session, ""), now), testSecret)
}

// opalSignature reimplements Opal's request signer independently of Sign.
func opalSignature(timestamp, payload string) string {
	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write([]byte("v0:" + timestamp + ":" + payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func send(router *gin.Engine, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		request.Header.Set(k, v)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

func signedHeaders(body string) map[string]string {
	timestamp := strconv.FormatInt(testNow.Unix(), 10)
	payload := strings.TrimSpace(body)
	if payload == "" {
		payload = "{}"
	}
	return map[string]string{"X-Opal-Request-Timestamp": timestamp, "X-Opal-Signature": opalSignature(timestamp, payload)}
}

func do(t *testing.T, router *gin.Engine, method, path, body string, wantStatus int) *httptest.ResponseRecorder {
	t.Helper()
	recorder := send(router, method, path, body, signedHeaders(body))
	if recorder.Code != wantStatus {
		t.Fatalf("%s %s = %d %s, want %d", method, path, recorder.Code, recorder.Body, wantStatus)
	}
	return recorder
}

// decode mirrors Opal's generated client, which rejects unknown fields.
func decode[T any](t *testing.T, recorder *httptest.ResponseRecorder) T {
	t.Helper()
	var value T
	decoder := json.NewDecoder(recorder.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("decode %T: %v", value, err)
	}
	return value
}

func lastCall(fake *op.FakeAccount) []string {
	call := fake.Calls[len(fake.Calls)-1]
	return call[:slices.Index(call, "--format=json")]
}

func TestSignature(t *testing.T) {
	_, router := newTestServer()
	timestamp := strconv.FormatInt(testNow.Unix(), 10)
	body := `{"user_id":"UBOB","app_id":"app"}`

	for _, tc := range []struct {
		name    string
		body    string
		headers map[string]string
		want    int
	}{
		{"valid signature", body, signedHeaders(body), http.StatusOK},
		{"trailing whitespace body", body + "\n", signedHeaders(body), http.StatusOK},
		{"tampered body", strings.Replace(body, "UBOB", "UCAROL", 1), signedHeaders(body), http.StatusUnauthorized},
		{"stale timestamp", body, map[string]string{
			"X-Opal-Request-Timestamp": strconv.FormatInt(testNow.Add(-6*time.Minute).Unix(), 10),
			"X-Opal-Signature":         opalSignature(strconv.FormatInt(testNow.Add(-6*time.Minute).Unix(), 10), body),
		}, http.StatusUnauthorized},
		{"missing headers", body, nil, http.StatusUnauthorized},
		{"wrong secret", body, map[string]string{"X-Opal-Request-Timestamp": timestamp, "X-Opal-Signature": Sign("other", timestamp, []byte(body))}, http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := send(router, http.MethodPost, "/groups/GENG/users", tc.body, tc.headers).Code; got != tc.want {
				t.Fatalf("status = %d, want %d", got, tc.want)
			}
		})
	}

	t.Run("empty body is signed as {}", func(t *testing.T) {
		headers := map[string]string{"X-Opal-Request-Timestamp": timestamp, "X-Opal-Signature": opalSignature(timestamp, "{}")}
		if got := send(router, http.MethodGet, "/status", "", headers).Code; got != http.StatusOK {
			t.Fatalf("status = %d", got)
		}
	})

	t.Run("status identifies the connector build to Opal", func(t *testing.T) {
		headers := map[string]string{"X-Opal-Request-Timestamp": timestamp, "X-Opal-Signature": opalSignature(timestamp, "{}")}
		got := send(router, http.MethodGet, "/status", "", headers).Body.String()
		if want := `{"implementation":"opal-1password-connector","version":"dev"}`; got != want {
			t.Fatalf("body = %s, want %s", got, want)
		}
	})
}

// The signature covers the body, so the body is read before the request is known to be from Opal.
func TestOversizedBodyIsRejectedBeforeAnyHandlerRuns(t *testing.T) {
	fake, router := newTestServer()
	body := strings.Repeat("a", maxBodyBytes+1)

	for _, tc := range []struct {
		name    string
		headers map[string]string
	}{
		{"forged signature", map[string]string{
			"X-Opal-Request-Timestamp": strconv.FormatInt(testNow.Unix(), 10),
			"X-Opal-Signature":         "not-a-signature",
		}},
		{"valid signature", signedHeaders(body)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := len(fake.Calls)
			if got := send(router, http.MethodPost, "/groups/GENG/users", body, tc.headers).Code; got != http.StatusRequestEntityTooLarge {
				t.Fatalf("status = %d, want 413", got)
			}
			if len(fake.Calls) != calls {
				t.Fatalf("op ran %d times, want none", len(fake.Calls)-calls)
			}
		})
	}
}

func TestUsers(t *testing.T) {
	_, router := newTestServer()
	recorder := do(t, router, http.MethodGet, "/users?app_id=app", "", http.StatusOK)
	if strings.Contains(recorder.Body.String(), "next_cursor") {
		t.Fatal("next_cursor should be omitted for a single page")
	}
	users := decode[UsersResponse](t, recorder)
	var ids []string
	for _, u := range users.Users {
		ids = append(ids, u.Id)
	}
	if !slices.Equal(ids, []string{"UCONNECTOR", "UALICE", "UBOB", "UCAROL"}) {
		t.Fatalf("users = %v, want only ACTIVE users with valid emails", ids)
	}
	if !strings.Contains(logs.String(), "skipping 1Password user UBADEMAIL") || strings.Contains(logs.String(), "shared-login") {
		t.Fatal("expected a warning naming the user ID without its email")
	}
}

func TestResources(t *testing.T) {
	fake, router := newTestServer()

	resources := decode[ResourcesResponse](t, do(t, router, http.MethodGet, "/resources?app_id=app", "", http.StatusOK))
	var descriptions []string
	for _, r := range resources.Resources {
		descriptions = append(descriptions, r.Description)
	}
	if want := []string{"Shared Cloudflare admin login", "", ""}; !slices.Equal(descriptions, want) {
		t.Fatalf("descriptions = %v, want %v", descriptions, want)
	}
	if nested := decode[ResourcesResponse](t, do(t, router, http.MethodGet, "/resources?app_id=app&parent_id=VPRODDB", "", http.StatusOK)); len(nested.Resources) != 0 {
		t.Fatal("vaults have no child resources")
	}
	if r := decode[ResourceResponse](t, do(t, router, http.MethodGet, "/resources/VPRODDB?app_id=app", "", http.StatusOK)); r.Resource.Description != "" {
		t.Fatalf("description = %q", r.Resource.Description)
	}
	do(t, router, http.MethodGet, "/resources/VNOPE?app_id=app", "", http.StatusNotFound)

	t.Run("lists vaults the identity only manages through a group, but not its personal vault", func(t *testing.T) {
		var ids []string
		for _, r := range resources.Resources {
			ids = append(ids, r.Id)
		}
		if want := []string{"VCLOUDFLARE", "VPRODDB", "VMARKETING"}; !slices.Equal(ids, want) {
			t.Fatalf("resources = %v, want %v", ids, want)
		}
		listed := slices.ContainsFunc(fake.Calls, func(call []string) bool {
			return len(call) >= 4 && slices.Equal(call[:4], []string{"vault", "list", "--user", "UCONNECTOR"})
		})
		if !listed {
			t.Fatalf("calls = %v, want vaults listed for the connector's identity", fake.Calls)
		}
	})

	t.Run("business accounts expose 12 access levels named by their bundle", func(t *testing.T) {
		levels := decode[ResourceAccessLevelsResponse](t, do(t, router, http.MethodGet, "/resources/VPRODDB/access_levels?app_id=app", "", http.StatusOK))
		if len(levels.AccessLevels) != 12 || levels.AccessLevels[0] != (AccessLevel{Id: "view_items", Name: "View items"}) {
			t.Fatalf("access levels = %v", levels.AccessLevels)
		}
		want := AccessLevel{Id: "edit_items", Name: "Edit items (+ View and copy passwords, View items)"}
		if !slices.Contains(levels.AccessLevels, want) {
			t.Fatalf("access levels = %v, want %v", levels.AccessLevels, want)
		}
	})

	t.Run("each held bundle is one entry", func(t *testing.T) {
		users := decode[ResourceUsersResponse](t, do(t, router, http.MethodGet, "/resources/VPRODDB/users?app_id=app", "", http.StatusOK))
		var levels []string
		for _, u := range users.Users {
			if u.UserId != "UALICE" || u.Email != "alice@example.com" {
				t.Fatalf("unexpected user %v", u)
			}
			levels = append(levels, u.AccessLevel.Id)
		}
		if !slices.Equal(levels, []string{"export_items"}) {
			t.Fatalf("levels = %v", levels)
		}
	})

	t.Run("grant expands dependencies", func(t *testing.T) {
		do(t, router, http.MethodPost, "/resources/VMARKETING/users", `{"user_id":"UBOB","app_id":"app","access_level_id":"export_items"}`, http.StatusOK)
		want := []string{"vault", "user", "grant", "--vault", "VMARKETING", "--user", "UBOB", "--permissions", "export_items,view_and_copy_passwords,view_item_history,view_items", "--no-input"}
		if got := lastCall(fake); !slices.Equal(got, want) {
			t.Fatalf("argv = %v, want %v", got, want)
		}
	})

	t.Run("grant without access level uses the base permission", func(t *testing.T) {
		do(t, router, http.MethodPost, "/resources/VCLOUDFLARE/users", `{"user_id":"UCAROL","app_id":"app"}`, http.StatusOK)
		if got := fake.VaultUsers["VCLOUDFLARE"]["UCAROL"]; !slices.Equal(got, []string{"view_items"}) {
			t.Fatalf("held = %v", got)
		}
	})

	t.Run("grant rejects unknown access level", func(t *testing.T) {
		do(t, router, http.MethodPost, "/resources/VMARKETING/users", `{"user_id":"UBOB","app_id":"app","access_level_id":"allow_viewing"}`, http.StatusBadRequest)
	})

	t.Run("revoke removes the bundle except what other bundles require", func(t *testing.T) {
		fake.VaultUsers["VPRODDB"]["UALICE"] = append(op.ExpandGrant("export_items"), "edit_items")
		do(t, router, http.MethodDelete, "/resources/VPRODDB/users/UALICE?access_level_id=export_items", "", http.StatusOK)
		if got := fake.VaultUsers["VPRODDB"]["UALICE"]; !slices.Equal(op.TopPermissions(got), []string{"edit_items"}) ||
			!slices.Equal(slices.Sorted(slices.Values(got)), op.ExpandGrant("edit_items")) {
			t.Fatalf("held after revoke = %v", got)
		}
	})

	t.Run("revoke removes the dependencies the bundle brought", func(t *testing.T) {
		do(t, router, http.MethodPost, "/resources/VPRODDB/users", `{"user_id":"UCAROL","app_id":"app","access_level_id":"view_and_copy_passwords"}`, http.StatusOK)
		do(t, router, http.MethodDelete, "/resources/VPRODDB/users/UCAROL?access_level_id=view_and_copy_passwords", "", http.StatusOK)
		if got, ok := fake.VaultUsers["VPRODDB"]["UCAROL"]; ok {
			t.Fatalf("held after revoke = %v, want nothing", got)
		}
	})

	t.Run("revoking a dependency also revokes its dependents", func(t *testing.T) {
		do(t, router, http.MethodDelete, "/resources/VPRODDB/users/UALICE?access_level_id=view_items", "", http.StatusOK)
		if got, ok := fake.VaultUsers["VPRODDB"]["UALICE"]; ok {
			t.Fatalf("held after revoke = %v, want nothing", got)
		}
		fake.VaultUsers["VPRODDB"]["UALICE"] = op.ExpandGrant("export_items")
	})

	t.Run("revoke without access level removes everything", func(t *testing.T) {
		do(t, router, http.MethodDelete, "/resources/VPRODDB/users/UALICE", "", http.StatusOK)
		if _, ok := fake.VaultUsers["VPRODDB"]["UALICE"]; ok {
			t.Fatal("user still has access")
		}
	})

	t.Run("revoking a non-member succeeds without calling op", func(t *testing.T) {
		calls := len(fake.Calls)
		do(t, router, http.MethodDelete, "/resources/VPRODDB/users/UBOB", "", http.StatusOK)
		for _, call := range fake.Calls[calls:] {
			if slices.Contains(call, "revoke") {
				t.Fatalf("unexpected revoke: %v", call)
			}
		}
	})

	t.Run("group-inherited access returns 409", func(t *testing.T) {
		fake.Fail = func(args []string) error {
			if slices.Contains(args, "revoke") {
				return op.Classify("[ERROR] the accessor doesn't have any permissions in the vault")
			}
			return nil
		}
		defer func() { fake.Fail = nil }()
		do(t, router, http.MethodDelete, "/resources/VMARKETING/users/UCAROL", "", http.StatusConflict)
	})
}

func TestGroups(t *testing.T) {
	fake, router := newTestServer()

	fake.Groups = append(fake.Groups, op.Group{ID: "GPLAIN", Name: "Plain", State: "ACTIVE"})
	groups := decode[GroupsResponse](t, do(t, router, http.MethodGet, "/groups?app_id=app", "", http.StatusOK))
	if len(groups.Groups) != 4 || groups.Groups[3].Description != "" {
		t.Fatalf("groups = %v", groups.Groups)
	}
	if g := decode[GroupResponse](t, do(t, router, http.MethodGet, "/groups/GENG?app_id=app", "", http.StatusOK)); g.Group.Description != "All engineers" {
		t.Fatalf("description = %q", g.Group.Description)
	}
	do(t, router, http.MethodGet, "/groups/GNOPE?app_id=app", "", http.StatusNotFound)
	do(t, router, http.MethodGet, "/groups/GNOPE/users?app_id=app", "", http.StatusNotFound)

	users := decode[GroupUsersResponse](t, do(t, router, http.MethodGet, "/groups/GONCALL/users?app_id=app", "", http.StatusOK))
	if len(users.Users) != 1 || users.Users[0] != (GroupUser{UserId: "UBOB", Email: "bob@example.com"}) {
		t.Fatalf("users = %v", users.Users)
	}

	t.Run("member-groups is always empty", func(t *testing.T) {
		recorder := do(t, router, http.MethodGet, "/groups/GENG/member-groups?app_id=app", "", http.StatusOK)
		if got := recorder.Body.String(); got != `{"next_cursor":null,"groups":[]}` {
			t.Fatalf("body = %s", got)
		}
	})

	t.Run("membership grant and revoke are idempotent", func(t *testing.T) {
		body := `{"user_id":"UCAROL","app_id":"app"}`
		do(t, router, http.MethodPost, "/groups/GONCALL/users", body, http.StatusOK)
		want := []string{"group", "user", "grant", "--group", "GONCALL", "--user", "UCAROL", "--role", "member"}
		if got := lastCall(fake); !slices.Equal(got, want) {
			t.Fatalf("argv = %v, want %v", got, want)
		}
		do(t, router, http.MethodPost, "/groups/GONCALL/users", body, http.StatusOK)
		do(t, router, http.MethodDelete, "/groups/GONCALL/users/UCAROL", "", http.StatusOK)
		do(t, router, http.MethodDelete, "/groups/GONCALL/users/UCAROL", "", http.StatusOK)
		if slices.Contains(fake.GroupMembers["GONCALL"], "UCAROL") {
			t.Fatal("user still a member")
		}
	})

	t.Run("group vault access", func(t *testing.T) {
		resources := decode[GroupResourcesResponse](t, do(t, router, http.MethodGet, "/groups/GONCALL/resources?app_id=app", "", http.StatusOK))
		want := []GroupResource{{ResourceId: "VCLOUDFLARE", AccessLevel: AccessLevel{Id: "view_and_copy_passwords", Name: "View and copy passwords (+ View items)"}}}
		if !slices.Equal(resources.Resources, want) {
			t.Fatalf("resources = %v", resources.Resources)
		}

		do(t, router, http.MethodPost, "/groups/GENG/resources", `{"resource_id":"VPRODDB","app_id":"app","access_level_id":"manage_vault"}`, http.StatusOK)
		wantArgv := []string{"vault", "group", "grant", "--vault", "VPRODDB", "--group", "GENG", "--permissions", "manage_vault", "--no-input"}
		if got := lastCall(fake); !slices.Equal(got, wantArgv) {
			t.Fatalf("argv = %v, want %v", got, wantArgv)
		}
		resources = decode[GroupResourcesResponse](t, do(t, router, http.MethodGet, "/groups/GENG/resources?app_id=app", "", http.StatusOK))
		if len(resources.Resources) != 1 || resources.Resources[0].AccessLevel.Id != "manage_vault" {
			t.Fatalf("grant not reflected after cache reset: %v", resources.Resources)
		}

		do(t, router, http.MethodDelete, "/groups/GONCALL/resources/VCLOUDFLARE?access_level_id=view_and_copy_passwords", "", http.StatusOK)
		if got, ok := fake.VaultGroups["VCLOUDFLARE"]["GONCALL"]; ok {
			t.Fatalf("group still has vault access after its bundle was revoked: %v", got)
		}
		do(t, router, http.MethodDelete, "/groups/GONCALL/resources/VCLOUDFLARE", "", http.StatusOK)
	})
}

func TestConnectorIdentityIsProtected(t *testing.T) {
	fake, router := newTestServer()
	writes := func() int {
		n := 0
		for _, call := range fake.Calls {
			if slices.Contains(call, "grant") || slices.Contains(call, "revoke") {
				n++
			}
		}
		return n
	}

	for _, tc := range []struct{ name, method, path, body string }{
		{"leave Administrators", http.MethodDelete, "/groups/GADMINS/users/UCONNECTOR", ""},
		{"join a group", http.MethodPost, "/groups/GENG/users", `{"user_id":"UCONNECTOR","app_id":"app"}`},
		{"lose vault access", http.MethodDelete, "/resources/VPRODDB/users/UCONNECTOR", ""},
		{"gain vault access", http.MethodPost, "/resources/VPRODDB/users", `{"user_id":"UCONNECTOR","app_id":"app"}`},
		{"Administrators lose vault access", http.MethodDelete, "/groups/GADMINS/resources/VCLOUDFLARE", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			do(t, router, tc.method, tc.path, tc.body, http.StatusForbidden)
		})
	}
	if n := writes(); n != 0 {
		t.Fatalf("%d op writes, want none", n)
	}
	if !slices.Contains(fake.GroupMembers["GADMINS"], "UCONNECTOR") || fake.VaultGroups["VCLOUDFLARE"]["GADMINS"] == nil {
		t.Fatal("connector identity was changed")
	}

	t.Run("other users are unaffected", func(t *testing.T) {
		do(t, router, http.MethodPost, "/groups/GADMINS/users", `{"user_id":"UBOB","app_id":"app"}`, http.StatusOK)
		do(t, router, http.MethodDelete, "/groups/GADMINS/users/UBOB", "", http.StatusOK)
	})

	t.Run("whoami failure blocks the write", func(t *testing.T) {
		failing, router := newTestServer()
		failing.Fail = func(args []string) error {
			if slices.Contains(args, "whoami") {
				return op.Classify("[ERROR] something went wrong")
			}
			return nil
		}
		do(t, router, http.MethodDelete, "/groups/GENG/users/UBOB", "", http.StatusInternalServerError)
		if !slices.Contains(failing.GroupMembers["GENG"], "UBOB") {
			t.Fatal("membership changed despite whoami failure")
		}
	})
}

func TestHealthzIsUnsigned(t *testing.T) {
	_, router := newTestServer()
	if got := send(router, http.MethodGet, "/healthz", "", nil).Code; got != http.StatusOK {
		t.Fatalf("/healthz = %d, want 200", got)
	}
	if got := send(router, http.MethodGet, "/status", "", nil).Code; got != http.StatusUnauthorized {
		t.Fatalf("unsigned /status = %d, want 401", got)
	}
}

func TestReadyzReflectsSignin(t *testing.T) {
	fake, router := newTestServer()
	if got := send(router, http.MethodGet, "/readyz", "", nil).Code; got != http.StatusOK {
		t.Fatalf("unsigned /readyz = %d, want 200", got)
	}
	fake.Fail = func(args []string) error {
		if slices.Contains(args, "whoami") {
			return op.Classify("Enter your six-digit authentication code: [ERROR] incorrect One-Time Password length. expected 6")
		}
		return nil
	}
	rec := send(router, http.MethodGet, "/readyz", "", nil)
	if rec.Code != http.StatusServiceUnavailable || rec.Body.Len() != 0 {
		t.Fatalf("/readyz = %d %q, want 503 with no body", rec.Code, rec.Body.String())
	}
}

func TestUnsupportedEndpoints(t *testing.T) {
	_, router := newTestServer()
	do(t, router, http.MethodGet, "/events?app_id=app", "", http.StatusNotImplemented)
	do(t, router, http.MethodPost, "/users", `{"user_id":"x"}`, http.StatusNotImplemented)
}

func TestLogsNeverContainSessionToken(t *testing.T) {
	TestSignature(t)
	TestUsers(t)
	TestResources(t)
	TestGroups(t)
	output := logs.String()
	if output == "" {
		t.Fatal("expected some log output")
	}
	for _, secret := range []string{"fake-session-token", "--session"} {
		if strings.Contains(output, secret) {
			t.Fatalf("logs contain %q", secret)
		}
	}
}
