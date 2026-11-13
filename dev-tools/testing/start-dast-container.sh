#!/usr/bin/env bash
set -euo pipefail

for variable in CONTAINER_IMAGE CONTAINER_NAME DAST_DB_HOST DAST_DB_PORT \
  DAST_DB_NAME DAST_DB_USERNAME DAST_DB_PASSWORD GITHUB_WORKSPACE; do
  if [[ -z "${!variable:-}" ]]; then
    echo "::error::Missing required DAST variable: ${variable}"
    exit 1
  fi
done

profiles_dir="${GITHUB_WORKSPACE}/dev-tools/credentials/profiles"
if [[ ! -d "${profiles_dir}" ]]; then
  echo "::error::Credential profiles directory not found: ${profiles_dir}"
  exit 1
fi

# EUD-269: the issuer does not start without its own idempotency secret. A throwaway one per run: the DAST
# container only lives for this job, so nothing kept with it has to be found again.
idempotency_secret="$(openssl rand -base64 48)"

docker run -d --name "${CONTAINER_NAME}" \
  --network host \
  -e SERVER_PORT=8080 \
  -e SPRING_R2DBC_URL="r2dbc:postgresql://${DAST_DB_HOST}:${DAST_DB_PORT}/${DAST_DB_NAME}" \
  -e SPRING_R2DBC_USERNAME="${DAST_DB_USERNAME}" \
  -e SPRING_R2DBC_PASSWORD="${DAST_DB_PASSWORD}" \
  -e SPRING_FLYWAY_URL="jdbc:postgresql://${DAST_DB_HOST}:${DAST_DB_PORT}/${DAST_DB_NAME}" \
  -e CREDENTIAL_PROFILES_PATH=file:/etc/eudistack/schemas \
  -e EMAIL_ASSETS_BASE_URL=https://assets.dast.example/assets/tenants \
  -e ISSUER_IDEMPOTENCY_SECRET="${idempotency_secret}" \
  -v "${profiles_dir}:/etc/eudistack/schemas:ro" \
  "${CONTAINER_IMAGE}"
