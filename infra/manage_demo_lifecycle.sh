#!/usr/bin/env bash
# ==============================================================================
# Helper script to Pause (Lock Down) or Teardown the Demo Environment
# Usage:
#   ./infra/manage_demo_lifecycle.sh lock     # Re-enables IAM auth check on Cloud Run (0 cost, blocks public URL)
#   ./infra/manage_demo_lifecycle.sh unlock   # Re-opens Cloud Run URL for live demoing
#   ./infra/manage_demo_lifecycle.sh destroy  # Deletes Cloud Run service, BQ dataset, GCS bucket, and Model Armor templates
# ==============================================================================
set -euo pipefail

ACTION="${1:-lock}"
PROJECT_ID="${GCP_PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || echo '')}"
LOCATION="${GCP_LOCATION:-us-central1}"
SERVICE_NAME="agent-governance-demo-cockpit"

if [[ -z "${PROJECT_ID}" ]]; then
  echo "❌ Error: GCP_PROJECT_ID environment variable is not set."
  exit 1
fi

export CLOUDSDK_METRICS_ENVIRONMENT="${CLOUDSDK_METRICS_ENVIRONMENT:+$CLOUDSDK_METRICS_ENVIRONMENT }datacloud.antigravity"

if [[ "${ACTION}" == "lock" ]]; then
  echo "🔒 Locking Cloud Run service [${SERVICE_NAME}] (enforcing IAM invoker check while idle)..."
  gcloud run services update "${SERVICE_NAME}" \
    --invoker-iam-check \
    --region="${LOCATION}" \
    --project="${PROJECT_ID}" \
    --quiet
  echo "✅ Locked! Idle cost is $0.00. Run './infra/manage_demo_lifecycle.sh unlock' before your next demo."

elif [[ "${ACTION}" == "unlock" ]]; then
  echo "🔓 Unlocking Cloud Run service [${SERVICE_NAME}] for live browser demo..."
  gcloud run services update "${SERVICE_NAME}" \
    --no-invoker-iam-check \
    --region="${LOCATION}" \
    --project="${PROJECT_ID}" \
    --quiet
  URL=$(gcloud run services describe "${SERVICE_NAME}" --region="${LOCATION}" --project="${PROJECT_ID}" --format='value(status.url)' 2>/dev/null || echo "")
  echo "✅ Unlocked! URL: ${URL:-https://${SERVICE_NAME}-<project-number>.<region>.run.app}"

elif [[ "${ACTION}" == "destroy" ]]; then
  echo "🗑️ Deleting Cloud Run service, BigQuery dataset, GCS context bucket, and Model Armor templates..."
  gcloud run services delete "${SERVICE_NAME}" --region="${LOCATION}" --project="${PROJECT_ID}" --quiet || true
  bq rm -r -f -d "${PROJECT_ID}:corp_finance" || true
  gcloud storage rm -r "gs://${PROJECT_ID}-agent-context" --project="${PROJECT_ID}" || true
  TOKEN="$(gcloud auth print-access-token)"
  for TMPL in "standard-safety-guardrails-v1" "enterprise-agent-strict-sdp-v1"; do
    curl -s -X DELETE \
      "https://modelarmor.${LOCATION}.rep.googleapis.com/v1/projects/${PROJECT_ID}/locations/${LOCATION}/templates/${TMPL}" \
      -H "Authorization: Bearer ${TOKEN}" >/dev/null || true
  done
  echo "✅ Demo resources removed from ${PROJECT_ID}."
else
  echo "Usage: $0 {lock|unlock|destroy}"
  exit 1
fi
