# Agent Trust Verifier

Phase 1 provides the identity and cryptographic foundation for an inter-agent
trust protocol: Ed25519 key generation, deterministic payload canonicalization,
signing and verification helpers, and an in-memory key registry with rotation
and revocation support.

Later phases will add instruction verification, delegated scopes, service APIs,
durable storage, and deployment infrastructure.

## Deployment

The Phase 10 deployment uses AWS Lambda, API Gateway HTTP API, and four DynamoDB
on-demand tables. It is intended for free-tier/demo use. The Lambda execution role
is limited to `GetItem`, `PutItem`, `UpdateItem`, and `Query` for the four tables,
plus `Scan` on the audit table only; the latter is required by the current audit-chain
implementation and should be replaced with a queryable production design.

Prerequisites:

- Python 3.12, AWS CLI, and AWS SAM CLI installed locally.
- AWS credentials configured for an IAM principal allowed to create the SAM resources
  in `infrastructure/template.yaml` (Lambda, HTTP API, DynamoDB, CloudFormation,
  IAM role/policy, and artifact bucket access).
- A base64-encoded raw Ed25519 root private key. Keep it outside the repository.

Generate a demo root key and store it in your shell variable:

```bash
export ROOT_PRIVATE_KEY_B64="$(python -c 'import base64; from identity.keygen import generate_keypair; print(base64.b64encode(generate_keypair().private_key_bytes).decode())')"
```

First deployment:

```bash
chmod +x scripts/deploy.sh
./scripts/deploy.sh --guided
```

Before a demo/red-team deployment, enable the gated bootstrap endpoint in the shell:

```bash
export ALLOW_TEST_BOOTSTRAP=1
```

`scripts/deploy.sh` passes `ROOT_PRIVATE_KEY_B64`, optional `GEMINI_API_KEY`, and
`ALLOW_TEST_BOOTSTRAP` only as deploy-time parameter overrides. They are not placed
in `samconfig.toml`. SAM prompts for the stack and region. Set bootstrap to `0` for
normal use. Subsequent deploys use:

```bash
./scripts/deploy.sh
```

CloudFormation prints an `ApiBaseUrl` output such as
`https://abc123.execute-api.us-east-1.amazonaws.com`. Seed the deployed demo
identities and root-issued Agent A token:

```bash
python scripts/seed_demo_data.py --base-url "https://abc123.execute-api.us-east-1.amazonaws.com"
```

Run the deployed red-team suite while test bootstrap is enabled:

```bash
python -m redteam.run_attack_suite --base-url "https://abc123.execute-api.us-east-1.amazonaws.com"
```

To run the live Gemini demo, set `GEMINI_API_KEY` locally and pass the deployed
base URL. This demo also requires `AllowTestBootstrap=1`:

```bash
python scripts/demo_valid_flow.py --base-url "https://abc123.execute-api.us-east-1.amazonaws.com"
```

For production, store both Gemini and root signing credentials in AWS Secrets
Manager or SSM Parameter Store and disable `/test/bootstrap`.
