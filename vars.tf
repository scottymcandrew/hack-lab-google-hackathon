/*
 * Terraform variable declarations
 */

/*
 * GCP Variables
 */

variable "my_gcp_project" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP Region"
}

variable "zone" {
  description = "GCP Zone"
}

/*
 * Creds
 */

# This particular project is intended to be run within GCP cloud shell, so this is not required
#variable "gcp_credentials" {
#  description = "GCP JSON credentials file"
#  type        = string
#}

variable "gce_ssh_user" {
  # Set value in environment variable TF_VAR_gce_ssh_user
  description = " ssh user that is used in the public key"
}

variable "gce_ssh_pub_key" {
  # Set value in environment variable TF_VAR_gce_ssh_pub_key
  description = "SSH public key file"
  type        = string
}

variable "panos_api_key" {
  description = "API key for PAN-OS"
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

