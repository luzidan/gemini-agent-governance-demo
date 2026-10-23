#!/usr/bin/env bash
# ==============================================================================
# Gemini Enterprise Agent Platform — GCP Demo Provisioning Script (gcloud)
# Provisions:
#   1. Required APIs (modelarmor, aiplatform, dlp, run, bigquery, accesscontextmanager)
#   2. Sensitive Data Protection (SDP / Cloud DLP) Inspect & De-identify Templates
#   3. Google Cloud Model Armor Templates (Standard Safety & Strict Enterprise SDP)
#   4. Managed Agent Identities (Co-Worker Agent Service Accounts)
#   5. BigQuery Customer 360 Dataset & Seeded PII Table (`corp_finance.customer_accounts`)
#   6. Cloud Run Deployment of the Demo Cockpit & A2A/MCP Services
# ==============================================================================
set -euo pipefail

PROJECT_ID="${GCP_PROJECT_ID:-$(gcloud config get-value project)}"
LOCATION="${GCP_LOCATION:-us-central1}"
SERVICE_NAME="${SERVICE_NAME:-agent-governance-demo-cockpit}"

echo "🚀 Provisioning Gemini Enterprise Agent Platform Demo in project: ${PROJECT_ID} (${LOCATION})"

# 1. Enable Required Google Cloud APIs
gcloud services enable \
  cloudresourcemanager.googleapis.com \
  iap.googleapis.com \
  modelarmor.googleapis.com \
  dlp.googleapis.com \
  aiplatform.googleapis.com \
  bigquery.googleapis.com \
  storage.googleapis.com \
  run.googleapis.com \
  iam.googleapis.com \
  iamcredentials.googleapis.com \
  --project="${PROJECT_ID}"

# 2. Create Managed Agent Identities (Co-Worker Agent IDs) & Grant Model Armor + Argolis Cloud Build Roles
ACTIVE_USER="$(gcloud config get-value account)"
PROJECT_NUMBER="$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)')"
for CB_ROLE in "roles/storage.admin" "roles/artifactregistry.writer" "roles/logging.logWriter" "roles/cloudbuild.builds.builder"; do
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
    --role="${CB_ROLE}" --condition=None --quiet >/dev/null || true
done

gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member="user:${ACTIVE_USER}" \
  --role="roles/modelarmor.admin" --condition=None --quiet >/dev/null
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member="user:${ACTIVE_USER}" \
  --role="roles/modelarmor.user" --condition=None --quiet >/dev/null

for SA_NAME in "adk-orchestrator-agent" "finance-coworker-agent"; do
  if ! gcloud iam service-accounts describe "${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    gcloud iam service-accounts create "${SA_NAME}" \
      --display-name="Managed Agent Identity (${SA_NAME})" \
      --project="${PROJECT_ID}"
  fi
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role="roles/modelarmor.user" --condition=None --quiet >/dev/null
done

# 3. Create Model Armor Template 1: Standard Guardrails (PI/Jailbreak + RAI + Malicious URI)
echo "🛡️ Creating Model Armor Template: standard-safety-guardrails-v1..."
ACCESS_TOKEN="$(gcloud auth print-access-token)"
curl -s -X POST \
  "https://modelarmor.${LOCATION}.rep.googleapis.com/v1/projects/${PROJECT_ID}/locations/${LOCATION}/templates?templateId=standard-safety-guardrails-v1" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "filterConfig": {
      "piAndJailbreakFilterSettings": {
        "filterEnforcement": "ENABLED",
        "confidenceLevel": "MEDIUM_AND_ABOVE"
      },
      "maliciousUriFilterSettings": {
        "filterEnforcement": "ENABLED"
      },
      "raiSettings": {
        "raiFilters": [
          {"filterType": "DANGEROUS", "confidenceLevel": "MEDIUM_AND_ABOVE"},
          {"filterType": "HATE_SPEECH", "confidenceLevel": "MEDIUM_AND_ABOVE"},
          {"filterType": "HARASSMENT", "confidenceLevel": "MEDIUM_AND_ABOVE"},
          {"filterType": "SEXUALLY_EXPLICIT", "confidenceLevel": "MEDIUM_AND_ABOVE"}
        ]
      }
    }
  }' || true

# 4. Create Model Armor Template 2: Strict Enterprise SDP (with PII/Secret Inspection)
echo "🛡️ Creating Model Armor Template: enterprise-agent-strict-sdp-v1..."
curl -s -X POST \
  "https://modelarmor.${LOCATION}.rep.googleapis.com/v1/projects/${PROJECT_ID}/locations/${LOCATION}/templates?templateId=enterprise-agent-strict-sdp-v1" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "filterConfig": {
      "piAndJailbreakFilterSettings": {
        "filterEnforcement": "ENABLED",
        "confidenceLevel": "LOW_AND_ABOVE"
      },
      "maliciousUriFilterSettings": {
        "filterEnforcement": "ENABLED"
      },
      "raiSettings": {
        "raiFilters": [
          {"filterType": "DANGEROUS", "confidenceLevel": "LOW_AND_ABOVE"},
          {"filterType": "HATE_SPEECH", "confidenceLevel": "LOW_AND_ABOVE"},
          {"filterType": "HARASSMENT", "confidenceLevel": "LOW_AND_ABOVE"},
          {"filterType": "SEXUALLY_EXPLICIT", "confidenceLevel": "LOW_AND_ABOVE"}
        ]
      },
      "sdpSettings": {
        "basicConfig": {
          "filterEnforcement": "ENABLED"
        }
      }
    }
  }' || true

# 5. Create BigQuery Dataset & Seeded Customer Table (1P VPC-SC Protected Resource)
echo "📊 Creating BigQuery dataset corp_finance.customer_accounts..."
bq --location="${LOCATION}" mk --dataset --if_not_exists "${PROJECT_ID}:corp_finance"
bq query --use_legacy_sql=false --project_id="${PROJECT_ID}" "
CREATE OR REPLACE TABLE \`${PROJECT_ID}.corp_finance.customer_accounts\` AS
SELECT
  'CUST-99201' AS customer_id,
  'Apex Global Holdings Ltd.' AS organization,
  'Elena Rostova' AS primary_contact,
  '412-88-9021' AS tax_ssn,
  '4532-8910-2291-8841' AS corporate_card,
  1420000 AS wire_transfer_limit_usd,
  'PENDING_3P_AUDIT' AS compliance_status;
"

echo "✅ GCP resources provisioned! To deploy the interactive Demo Cockpit to Cloud Run with Google Sign-In (IAP) for @google.com ONLY, run:"
echo "   gcloud beta run deploy ${SERVICE_NAME} --source . --region ${LOCATION} --iap --invoker-iam-check --service-account=adk-orchestrator-agent@${PROJECT_ID}.iam.gserviceaccount.com --set-env-vars GCP_PROJECT_ID=${PROJECT_ID},GCP_LOCATION=${LOCATION},USE_LIVE_MODEL_ARMOR_API=true"
echo "   printf 'accessSettings:\n  allowedDomainsSettings:\n    enable: true\n    domains:\n      - google.com\n' > /tmp/iap_domains.yaml"
echo "   gcloud iap settings set /tmp/iap_domains.yaml --project=${PROJECT_ID} --resource-type=cloud-run --service=${SERVICE_NAME} --region=${LOCATION}"
echo "   gcloud beta iap web add-iam-policy-binding --project=${PROJECT_ID} --resource-type=cloud-run --service=${SERVICE_NAME} --region=${LOCATION} --member=domain:google.com --role=roles/iap.httpsResourceAccessor"
