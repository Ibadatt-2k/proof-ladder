#!/usr/bin/env bash
# Deploy to Google Cloud Run from source (Cloud Build builds the Dockerfile).
#   GCP_PROJECT=my-project bash deploy/cloudrun.sh
#
# Default is low cost: scales to zero when idle, re-seeds 600 alerts on each cold start
# (a few seconds), and demo data resets whenever the instance restarts.
# ALWAYS_ON=true keeps one warm instance with a live alert feed (billed continuously).
# Optional env: REGION, SERVICE, READONLY, LLM_PROVIDER, DATABASE_URL (Postgres), QDRANT_URL
set -euo pipefail
: "${GCP_PROJECT:?set GCP_PROJECT}"
REGION="${REGION:-us-west1}"
SERVICE="${SERVICE:-proof-ladder}"

ENV_VARS="SEED_ON_START=600,READONLY=${READONLY:-false},LLM_PROVIDER=${LLM_PROVIDER:-offline}"
[[ -n "${DATABASE_URL:-}" ]] && ENV_VARS="$ENV_VARS,DATABASE_URL=$DATABASE_URL"
[[ -n "${QDRANT_URL:-}" ]] && ENV_VARS="$ENV_VARS,MEMORY_BACKEND=qdrant,QDRANT_URL=$QDRANT_URL"

if [[ "${ALWAYS_ON:-false}" == "true" ]]; then
  SCALING=(--min-instances 1 --no-cpu-throttling)
  ENV_VARS="$ENV_VARS,LIVE_REPLAY=true,LIVE_REPLAY_INTERVAL_SEC=4"
else
  SCALING=(--min-instances 0)
  ENV_VARS="$ENV_VARS,LIVE_REPLAY=false"
fi

gcloud run deploy "$SERVICE" \
  --project "$GCP_PROJECT" --region "$REGION" --source . \
  --allow-unauthenticated --max-instances 1 "${SCALING[@]}" \
  --memory 512Mi --cpu 1 \
  --set-env-vars "$ENV_VARS"
# Secrets (API keys) belong in Secret Manager:
#   --set-secrets LLM_API_KEY=llm-api-key:latest,QDRANT_API_KEY=qdrant-api-key:latest

gcloud run services describe "$SERVICE" --project "$GCP_PROJECT" --region "$REGION" --format 'value(status.url)'
