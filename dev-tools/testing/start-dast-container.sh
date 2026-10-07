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

docker run -d --name "${CONTAINER_NAME}" \
  --network host \
  -e SERVER_PORT=8080 \
  -e SPRING_R2DBC_URL="r2dbc:postgresql://${DAST_DB_HOST}:${DAST_DB_PORT}/${DAST_DB_NAME}" \
  -e SPRING_R2DBC_USERNAME="${DAST_DB_USERNAME}" \
  -e SPRING_R2DBC_PASSWORD="${DAST_DB_PASSWORD}" \
  -e SPRING_FLYWAY_URL="jdbc:postgresql://${DAST_DB_HOST}:${DAST_DB_PORT}/${DAST_DB_NAME}" \
  -e CREDENTIAL_PROFILES_PATH=file:/etc/eudistack/schemas \
  -v "${profiles_dir}:/etc/eudistack/schemas:ro" \
  "${CONTAINER_IMAGE}"
