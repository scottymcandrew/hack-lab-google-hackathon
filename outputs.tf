/*
 * Terraform output variables for GCP
 */

output "panos-mgmt-pip" {
  value = google_compute_instance.vm-series[0].network_interface[0].access_config[0].nat_ip
}

output "panos-untrust-pip" {
  value = google_compute_instance.vm-series[0].network_interface[1].access_config[0].nat_ip
}

output "kali-pip" {
  value = google_compute_instance.kali.network_interface[0].access_config[0].nat_ip
}

