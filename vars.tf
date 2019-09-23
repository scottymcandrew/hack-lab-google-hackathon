/*
 * Terraform variable declarations
 */

/*
 * GCP Variables
 */

variable "gcp_project_id" {
  description = "GCP Project ID"
  type        = string
  default     = "cloud-automation-demo"
}

variable "gcp_region" {
  description = "GCP Region"
  type        = string
  default     = "europe-west2"
}

variable "gcp_zone" {
  description = "GCP Zone"
  type        = string
  default     = "europe-west2-b"
}

/*
 * Creds
 */

variable "gcp_credentials" {
  description = "GCP JSON credentials file"
  type        = string
}

variable "gcp_ssh_public_key" {
  description = "SSH public key file"
  type        = string
}

variable "panos_api_key" {
  description = "API key for PAN-OS"
  type        = string
}

variable "sms_key" {
  description = "API key for SMS service"
  type        = string
}

variable "email_key" {
  description = "API key for email service"
  type        = string
}

variable "user_password" {
  description = "PAN-OS password for the user account"
  type        = string
}

/*
 * Automation variables
 */

variable "subnetOctet" {
  description = "This will be incremented by 1 for each deployment to ensure unique IP addressing and hostnames"
  type        = string
  default     = "0"
}

variable "deploymentArea" {
  description = "This will be used for the firewall hostname"
  type        = string
  default     = "Prod"
}

variable "devWorkflow" {
  description = "This will be used for the firewall hostname"
  type        = string
  default     = "Two-Tier"
}

variable "projectName" {
  description = "This will be used for the firewall login banner"
  type        = string
  default     = "Never test the depth of the water with both feet."
}

variable "requestNumber" {
  description = "This will be used to track each run of the demo deployment"
  type        = string
  default     = "SCOPS000"
}

variable "requested_for_mobile" {
  description = "This will be used to send SMS to the SE"
  type        = string
}

variable "requested_for_email" {
  description = "This will be used to send email to the SE"
  type        = string
}

variable "project_mgr_mobile" {
  description = "This will be used to send SMS to the user"
  type        = string
}

variable "project_mgr_email" {
  description = "This will be used to send email to the user"
  type        = string
}

