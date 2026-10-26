# Security Policy

## Reporting a vulnerability

Please report security issues privately to **security@opal.dev**. Do not open a public GitHub issue,
pull request, or discussion for a suspected vulnerability.

Include what you can of:

- the affected version (image tag or commit),
- steps to reproduce or a proof of concept,
- the impact you expect, for example access to 1Password data or unauthorized grants.

We will acknowledge your report, keep you updated while we investigate, and credit you in the release
notes if you'd like.

## Supported versions

Security fixes go into the latest release. Upgrade to the newest `vX.Y.Z` image and Helm chart to pick
them up.

## Scope

This connector runs in your environment with an identity that can administer your 1Password account,
so treat its host as tier-0. See [Security notes](README.md#security-notes) for how it handles
credentials, sessions, and request signatures.
