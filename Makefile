SECRETS_DOTFILE=.secrets
# Opal's public Custom Connector spec, pinned to a commit of github.com/opalsecurity/opal-connector-spec.
SPEC_URL=https://raw.githubusercontent.com/opalsecurity/opal-connector-spec/ae08f1af11ae2acaa24823e8d13886c11780e5e9/openapi-connector-spec.yaml

run:
	set -a && source $(SECRETS_DOTFILE) && set +a && go run .

run-fake:
	OP_FAKE=1 OPAL_SIGNING_SECRET=$${OPAL_SIGNING_SECRET:-local-dev-secret} go run .

test:
	go test ./...

gen-openapi:
	curl -fsSLo api/openapi.yaml $(SPEC_URL)
	docker run --rm -v "$$PWD:/local" openapitools/openapi-generator-cli:v7.12.0 generate \
		-g go-gin-server -i /local/api/openapi.yaml -c /local/openapi_config.json -o /local

helm-lint:
	helm lint charts/opal-1password-connector --set fake=true --set secret.opalSigningSecret=dev
	helm template dev charts/opal-1password-connector --set fake=true --set secret.opalSigningSecret=dev --set replicaCount=3 >/dev/null

docker-build:
	docker build -t opal-1password-connector:dev .
