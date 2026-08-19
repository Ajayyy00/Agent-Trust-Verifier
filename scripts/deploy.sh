#!/usr/bin/env bash
set -euo pipefail

# Build a Lambda deployment artifact using infrastructure/template.yaml.
sam build --template-file infrastructure/template.yaml

# Secrets are read from this caller's shell and passed only at deploy time. Do not
# put them in samconfig.toml or commit them. Set ROOT_PRIVATE_KEY_B64 before use.
: "${ROOT_PRIVATE_KEY_B64:?Set ROOT_PRIVATE_KEY_B64 before deploying.}"
PARAMETERS=(
  "RootPrivateKeyB64=${ROOT_PRIVATE_KEY_B64}"
  "GeminiApiKey=${GEMINI_API_KEY:-}"
  "AllowTestBootstrap=${ALLOW_TEST_BOOTSTRAP:-0}"
)

# First deployment: ./scripts/deploy.sh --guided
# SAM asks for the stack and region. Later deployments reuse samconfig.toml:
# ./scripts/deploy.sh
if [[ "${1:-}" == "--guided" ]]; then
  sam deploy --guided --template-file .aws-sam/build/template.yaml --config-file infrastructure/samconfig.toml --parameter-overrides "${PARAMETERS[@]}"
else
  sam deploy --template-file .aws-sam/build/template.yaml --config-file infrastructure/samconfig.toml --parameter-overrides "${PARAMETERS[@]}"
fi
