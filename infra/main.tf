# ==============================================================================
# Terraform Configuration for Gemini Enterprise Agent Platform Demo
# Provisions:
# - Required GCP APIs (Model Armor, DLP/SDP, Vertex AI, BigQuery, Cloud Run)
# - Managed Agent Identities (Service Accounts for Orchestrator & Co-Worker Agent)
# - Per-Agent Isolated Context GCS Bucket (Memory Bank & Per-Task Folders)
# - BigQuery Dataset & Customer 360 Table (1P VPC-SC Protected Target)
# ==============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.30.0"
    }
  }
}

variable "project_id" {
  description = "Customer-managed GCP Project ID"
  type        = string
}

variable "region" {
  description = "Primary GCP Region for Agent Platform & Model Armor"
  type        = string
  default     = "us-central1"
}

provider "google" {
  project = var.project_id
  region  = var.region
}

locals {
  services = [
    "modelarmor.googleapis.com",
    "dlp.googleapis.com",
    "aiplatform.googleapis.com",
    "bigquery.googleapis.com",
    "storage.googleapis.com",
    "run.googleapis.com",
    "iam.googleapis.com",
  ]
}

resource "google_project_service" "enabled_apis" {
  for_each           = toset(local.services)
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

# Managed Agent Identities (Diagram 2: Co-Worker Agents with their own Managed Identity)
resource "google_service_account" "adk_orchestrator_agent_id" {
  account_id   = "adk-orchestrator-agent"
  display_name = "Managed Agent ID: Gemini ADK Enterprise Orchestrator"
  description  = "Primary ADK Agent Harness identity inside Customer-Managed GCP Project"
}

resource "google_service_account" "finance_coworker_agent_id" {
  account_id   = "finance-coworker-agent"
  display_name = "Managed Agent ID: Autonomous Finance Co-Worker Agent"
  description  = "Co-Worker Agent identity governed by Agent Gateway PDPs"
}

resource "google_project_iam_member" "orchestrator_model_armor_user" {
  project = var.project_id
  role    = "roles/modelarmor.user"
  member  = "serviceAccount:${google_service_account.adk_orchestrator_agent_id.email}"
}

resource "google_project_iam_member" "coworker_model_armor_user" {
  project = var.project_id
  role    = "roles/modelarmor.user"
  member  = "serviceAccount:${google_service_account.finance_coworker_agent_id.email}"
}

# Agent Context Resources: Isolated Memory Bank & Per-Task Artifact Storage Bucket
resource "google_storage_bucket" "agent_context_storage" {
  name                        = "${var.project_id}-agent-context-resources"
  location                    = var.region
  uniform_bucket_level_access = true
  force_destroy               = true

  versioning {
    enabled = true
  }
}

# 1P BigQuery Dataset & Table (VPC-SC Protected Data Source)
resource "google_bigquery_dataset" "corp_finance" {
  dataset_id  = "corp_finance"
  location    = var.region
  description = "Enterprise Customer 360 financial records protected by VPC-SC and accessed via 1P BigQuery MCP"
}

resource "google_bigquery_table" "customer_accounts" {
  dataset_id          = google_bigquery_dataset.corp_finance.dataset_id
  table_id            = "customer_accounts"
  deletion_protection = false

  schema = jsonencode([
    { name = "customer_id", type = "STRING", mode = "REQUIRED" },
    { name = "organization", type = "STRING", mode = "REQUIRED" },
    { name = "primary_contact", type = "STRING", mode = "REQUIRED" },
    { name = "tax_ssn", type = "STRING", mode = "NULLABLE" },
    { name = "corporate_card", type = "STRING", mode = "NULLABLE" },
    { name = "wire_transfer_limit_usd", type = "INTEGER", mode = "NULLABLE" },
    { name = "compliance_status", type = "STRING", mode = "NULLABLE" }
  ])
}
