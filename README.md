# Opal Connector for 1Password

A customer-hosted [Opal Custom Connector](https://docs.opal.dev/docs/how-to-create-your-own-connector)
that lets Opal govern 1Password **vaults** (as resources) and **groups** (membership and group → vault
access). It drives the 1Password CLI (`op`) signed in as a dedicated admin identity, so the 1Password
credential stays in your environment and never enters Opal.

1Password has no server-side admin API: account data is end-to-end encrypted, so permission changes
need key material client-side. That is why this runs next to `op` rather than inside Opal.

Out of scope: user provisioning/deprovisioning and the audit/events feed. 1Password has no nested groups.

## How it maps

| Opal | 1Password |
|---|---|
| Users | Active users with a valid email (`op user list`) |
| Resources | Vaults the identity can manage, directly or through Owners/Administrators (`op vault list --user <self>`); its own personal vault is skipped |
| Access levels | One bundle per vault permission: 12 on Business, 3 on Teams/Families (`op account get` decides) |
| Resource users | One entry per (user, bundle held) (`op vault user list`) |
| Groups / group users | `op group list`, `op group user list` |
| Group resources | Vaults a group can access, reported at its highest permission (`op vault group list`) |

Vault permissions have dependencies, so each access level is a bundle: the permission plus everything
it requires (`Export items (+ View item history, View and copy passwords, View items)`). Granting one
grants the whole bundle; sync reports only the bundles a user holds, not the permissions folded into
them; revoking one removes the bundle and everything that depends on it, except what the user's
other bundles still require. So a time-bound grant leaves nothing behind when it expires. 1Password
doesn't record why a permission is held, so a `view_items` the user already had before a temporary
`view_and_copy_passwords` grant is removed along with it. The dependency map follows 1Password's
[documented dependency table](https://www.1password.dev/cli/vault-permissions/).

Grants and revokes are idempotent. Revoking vault access a user only has through a 1Password group
returns **409**: remove them from the group instead.

## Run locally

```bash
make test
make run-fake          # in-memory demo account (Business tier, sample users)
cp .secrets.example .secrets && make run   # a real account
```

With `OP_PASSWORD` unset, `make run` uses the 1Password desktop app integration (Touch ID) instead
of signing in. That's convenient for local testing, but not for deployment.

## Deploy

### Prerequisites
- 1Password **Business**. Custom groups and granular permissions are Business-only.
- A dedicated identity for the connector, in the built-in **Administrators** (or **Owners**) group.
  Without it, `op user list` fails with `(403) Forbidden` and user sync errors out. Keep its password
  and Secret Key in your own secret store, not in 1Password itself.
- Vault coverage comes from that group: 1Password gives Owners and Administrators `manage_vault` on
  every shared vault by default, and the connector syncs every vault its identity can manage. You don't
  add the identity to vaults one by one. A vault someone removed Administrators' access from doesn't
  sync until the identity (or one of its groups) gets `manage_vault` on it again.
- An HTTPS URL Opal can reach. Opal Cloud needs a publicly reachable endpoint; self-hosted Opal can
  use a private one. If the hostname's DNS is behind a proxying CDN (for example Cloudflare's orange
  cloud), Opal reaches the CDN instead of a private origin and every call times out: use a DNS-only
  record for a private endpoint.
- Recommended: a 1Password firewall rule that pins this identity's sign-ins to the connector's egress IP.
- If you use Unlock with SSO, leave this identity out of it: the connector signs in with a password.

Deploy the connector first, then in Opal open **Add App → 1Password**, set **Base URL** to its HTTPS URL,
paste its signing secret into **Signing Secret**, and click **Create**. The Helm chart generates the
secret and prints the command to read it; for Docker, use `openssl rand -hex 32` (at least 32 characters).
Then **Import assets** to bring in vaults and groups. Vault access shows up per bundle under each vault's
**User Access** tab, and grants and revokes from Opal call `op vault user grant/revoke`.

### Option 1: Helm (Kubernetes)

```bash
helm install op-connector oci://ghcr.io/opalsecurity/charts/opal-1password-connector \
  --namespace opal-1password-connector --create-namespace \
  --set accountAddress=example.1password.com \
  --set secret.opEmail=<admin email> \
  --set secret.opSecretKey=<A3-...> --set secret.opPassword=<password>
```

- Runs a StatefulSet with one replica by default, each with a 1Gi volume for 1Password device state.
  For redundancy, `--set replicaCount=N`. See [High availability](#high-availability-multiple-replicas).
- To keep credentials out of Helm values, create the Secret yourself (keys `OPAL_SIGNING_SECRET`,
  `OP_EMAIL`, `OP_SECRET_KEY`, `OP_PASSWORD`) and pass `--set secret.create=false
  --set secret.existingSecret=<name>`.
- Expose it with `--set ingress.enabled=true --set ingress.host=<host>` plus your ingress class and
  TLS settings, or with your own load balancer. See [`values.yaml`](charts/opal-1password-connector/values.yaml).

### Option 2: Docker Compose (single VM)

```bash
cd deploy/docker-compose
cp .env.example .env && $EDITOR .env
CONNECTOR_DOMAIN=op.example.com docker compose --profile https up -d
```

Caddy gets a Let's Encrypt certificate for `CONNECTOR_DOMAIN`, which must point at the VM with ports 80
and 443 open. Without `--profile https`, the connector listens on `127.0.0.1:8080` only, for use behind
your own load balancer.

### Option 3: Docker

```bash
docker run -d --name op-connector -p 8080:8080 -v op-data:/data --env-file .env \
  ghcr.io/opalsecurity/opal-1password-connector:latest
```

Put it behind your own HTTPS termination.

### 2FA and device bootstrap

1Password only asks for a second factor when an identity signs in on a **new device**. Routine
sign-ins on a known device are password + Secret Key only. 2FA enforcement is account-wide; you can't
exempt one identity. The connector's device is `OP_CONFIG_DIR` (`/data/op` on the persistent volume).
Once that device is trusted, the connector never sees a 2FA prompt.

Without 2FA on the identity, the connector adds the device itself on first start. With 2FA, add it by
hand once, and again whenever device trust is lost:

- The volume is deleted or recreated: a new PVC or storage class, a cluster move, `helm uninstall` plus
  PVC cleanup, or `docker compose down -v`.
- The device is removed in 1Password, under the identity's **Devices** list, or with "sign out of all
  devices".
- The identity's password changes or its Secret Key is regenerated.
- 2FA is turned on for the identity, or enforced for the account, after the connector was set up. The
  account is already in `OP_CONFIG_DIR` but the device never passed 2FA, so `op signin` asks for a code
  once. Use the `op signin` variant below.

Turning org-wide enforcement on or off doesn't affect a device that has already passed 2FA.

When this happens, the logs say `this device needs a one-time 2FA bootstrap by hand`. On Kubernetes the
pod's readiness check (`/readyz`) fails, so it gets no traffic: with other ready replicas Opal is
unaffected, with one replica Opal can't reach the connector. Elsewhere, Opal requests get **502**.
While it's in this state, the connector retries `op account add` or `op signin` at most every 5 minutes,
so it won't race you or pile up failed sign-ins.

To bootstrap, have the identity's 2FA (authenticator or security key) at hand. If the log says
`op account add`, add the account:

```bash
# Kubernetes (statefulset/... is pod -0; with several replicas, name the pod, e.g. ...-connector-1)
kubectl -n opal-1password-connector exec -it statefulset/op-connector-opal-1password-connector -- \
  sh -c 'op account add --address "$OP_ACCOUNT_ADDRESS" --email "$OP_EMAIL"'
# Docker Compose
docker compose exec connector sh -c 'op account add --address "$OP_ACCOUNT_ADDRESS" --email "$OP_EMAIL"'
```

If the log says `op signin`, the account is already there; sign in once instead:

```bash
kubectl -n opal-1password-connector exec -it statefulset/op-connector-opal-1password-connector -- \
  sh -c 'op signin --account "$OP_ACCOUNT_ADDRESS" --raw >/dev/null'
docker compose exec connector sh -c 'op signin --account "$OP_ACCOUNT_ADDRESS" --raw >/dev/null'
```

`op` reads the Secret Key from the container's `OP_SECRET_KEY`. Enter the password and the current
six-digit code when prompted. Run it in an interactive terminal (`-it`): `op` can't take the code from a
pipe or script. When bootstrapping outside the container on a machine with the 1Password desktop app,
also set `OP_BIOMETRIC_UNLOCK_ENABLED=false`, or `op` hands the account to the app instead.

After `op account add`, the connector picks up the account on its next request. After `op signin`, it
picks it up when the 5-minute wait ends; restart it to skip the wait. To check the device, run
`op signin --account "$OP_ACCOUNT_ADDRESS" --raw >/dev/null` again. It should ask only for the password.

Keep the identity's 2FA secret wherever its password and Secret Key live, so whoever is on call can
bootstrap without the original admin.

### High availability (multiple replicas)

The Helm chart can run several replicas with `--set replicaCount=N` (Docker Compose is single-VM). Each
pod (`<release>-opal-1password-connector-0`, `-1`, ...) has its own volume and is its own 1Password
device: it shows up in the identity's **Devices** list, and 1Password may send a new-device email for it.
Replicas never share a volume, since `op` must not sign in on one device concurrently.

- Without 2FA on the identity, every pod adds its own device on first start.
- With 2FA, bootstrap each pod by hand once, as above, naming the pod:
  `kubectl exec -it <release>-opal-1password-connector-1 -- sh -c '...'`. Pods start in order, and the
  next one is created only once the previous one is ready, so bootstrap `-0` first, then `-1`, and so on.
- A pod is ready only while `op whoami` succeeds, so a pod that still needs a bootstrap, or whose
  device trust was lost, gets no traffic while the others keep serving.
- Scaling up, or losing one pod's volume, means bootstrapping just that pod.
- With more than one replica the chart adds a PodDisruptionBudget (`minAvailable: 1`) and, unless you
  set `affinity`, prefers to spread pods across nodes.
- Each pod caches user, group and group-access listings for up to a minute and only clears that cache
  for writes it handled itself. Right after a change, another pod may report the old state until its
  cache expires; the next Opal sync picks it up.

### Verify the release

Images and charts are signed with keyless [cosign](https://docs.sigstore.dev/) from this repo's
release workflow:

```bash
cosign verify ghcr.io/opalsecurity/opal-1password-connector:<version> \
  --certificate-identity-regexp 'https://github.com/opalsecurity/opal-1password-connector/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

### Health check

`GET /healthz` returns 200 without a signature and without calling 1Password. Every other endpoint
requires Opal's signature.

### Security notes

- The connector host can effectively decrypt the account. Treat it as tier-0.
- Requests are verified with Opal's HMAC (`X-Opal-Signature`, 5-minute replay window).
- The connector refuses (403) any change to its own identity (`op whoami`): group membership, including
  Owners/Administrators, and vault access. It also refuses revoking vault access from the built-in
  Owners/Administrators groups. Either would break sync.
- `op` is always run with an argv slice, never a shell string.
- Argv is never logged, because it carries `--session <token>`.
- Sessions refresh single-flight before 1Password's 30-minute idle expiry. An auth error re-signs-in
  once, then fails.
- A 2FA-enabled identity needs a one-time manual device bootstrap. See
  [2FA and device bootstrap](#2fa-and-device-bootstrap).

## Releasing

Push a `vX.Y.Z` tag. The release workflow tests, builds a multi-arch (amd64/arm64) image, pushes it and
the Helm chart to GHCR (`ghcr.io/opalsecurity/opal-1password-connector`,
`oci://ghcr.io/opalsecurity/charts`), and signs both with cosign.

## Regenerating API models

The `model_*.go` files are generated with `make gen-openapi` from Opal's public
[Custom Connector spec](https://github.com/opalsecurity/opal-connector-spec), pinned to a commit in the
`Makefile`. Hand-written files, including the gin router, are listed in `.openapi-generator-ignore`.

## License

See [LICENSE](LICENSE).
