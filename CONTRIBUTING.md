# Contributing

Issues and pull requests are welcome. For anything security-sensitive, follow [SECURITY.md](SECURITY.md)
instead of opening an issue.

## Development

```bash
make test        # unit tests, no 1Password account needed
make run-fake    # serve an in-memory demo account on :8080
make helm-lint   # lint and render the Helm chart
```

CI also runs `go vet ./...` and `go test -race ./...`, and builds the multi-arch image.

## Generated code

The `onepasswordconnector/model_*.go` files are generated from Opal's public
[Custom Connector spec](https://github.com/opalsecurity/opal-connector-spec) with `make gen-openapi`.
Don't edit them by hand. Files the generator must leave alone are listed in `.openapi-generator-ignore`.

## Pull requests

- Keep changes focused, and add or update tests in `internal/op` or `onepasswordconnector/server_test.go`.
- `op` stderr classification is pinned to the CLI version in the `Dockerfile`. If you bump it, check
  the strings in `internal/op/runner.go` against the new version.
