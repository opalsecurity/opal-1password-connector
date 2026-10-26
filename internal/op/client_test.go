package op

import (
	"context"
	"errors"
	"slices"
	"testing"
)

// Opal's client has no request timeout, but a proxy or load balancer in front of the connector does.
// Killing `op` partway through a grant or revoke would change 1Password with nothing recording what
// landed, so writes must outlive the request that started them.
func TestWritesOutliveCallerCancellation(t *testing.T) {
	var ran [][]string
	exec := func(ctx context.Context, args, _ []string, _ string) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ran = append(ran, args)
		return []byte("{}"), nil
	}
	client := NewClient(exec, nil, "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	t.Run("writes still run", func(t *testing.T) {
		if err := client.GrantVaultUser(ctx, "VPRODDB", "UBOB", []string{"view_items"}); err != nil {
			t.Fatalf("GrantVaultUser: %v", err)
		}
		if err := client.RevokeGroupUser(ctx, "GENG", "UBOB"); err != nil {
			t.Fatalf("RevokeGroupUser: %v", err)
		}
		if len(ran) != 2 || !slices.Contains(ran[0], "grant") || !slices.Contains(ran[1], "revoke") {
			t.Fatalf("ran = %v, want both writes", ran)
		}
	})

	t.Run("reads still honor it", func(t *testing.T) {
		if _, err := client.ListVaults(ctx, "UCONNECTOR"); !errors.Is(err, context.Canceled) {
			t.Fatalf("ListVaults = %v, want context.Canceled", err)
		}
		if len(ran) != 2 {
			t.Fatalf("ran = %v, want the read not to have run", ran)
		}
	})
}
