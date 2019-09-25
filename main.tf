/*
 *  Provider - GCP
 */

provider "google" {
  project = var.my_gcp_project
  region = var.region
}

/*
 *  GCP networks and subnetworks
 */

resource "google_compute_network" "mgmt" {
  name = "mgmt-${var.subnetOctet}"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "mgmt-net" {
  name = "mgmt-net-${var.subnetOctet}"
  ip_cidr_range = "192.168.${var.subnetOctet}.0/24"
  region = var.region
  network = "mgmt-${var.subnetOctet}"
  enable_flow_logs = "true"
  depends_on = [
    google_compute_network.mgmt]
}

resource "google_compute_network" "inside" {
  name = "inside-${var.subnetOctet}"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "inside-net" {
  name = "inside-net-${var.subnetOctet}"
  ip_cidr_range = "10.${var.subnetOctet}.10.0/24"
  region = var.region
  network = "inside-${var.subnetOctet}"
  enable_flow_logs = "true"
  depends_on = [
    google_compute_network.inside]
}

resource "google_compute_network" "database" {
  name = "database-${var.subnetOctet}"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "database-net" {
  name = "database-net-${var.subnetOctet}"
  ip_cidr_range = "10.${var.subnetOctet}.20.0/24"
  region = var.region
  network = "database-${var.subnetOctet}"
  enable_flow_logs = "true"
  depends_on = [
    google_compute_network.database]
}

resource "google_compute_network" "outside" {
  name = "outside-${var.subnetOctet}"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "outside-net" {
  name = "outside-net-${var.subnetOctet}"
  ip_cidr_range = "172.16.${var.subnetOctet}.0/24"
  region = var.region
  network = "outside-${var.subnetOctet}"
  enable_flow_logs = "true"
  depends_on = [
    google_compute_network.outside]
}

/*
 *  GCP Routing
 */

resource "google_compute_route" "outside-route-to-inside" {
  name = "outside-route-to-inside-${var.subnetOctet}"
  dest_range = "10.${var.subnetOctet}.10.0/24"
  network = "outside-${var.subnetOctet}"
  next_hop_ip = "172.16.${var.subnetOctet}.2"
  priority = 100
  depends_on = [
    google_compute_subnetwork.outside-net]
}

resource "google_compute_route" "inside-route-to-outside" {
  name = "inside-route-to-outside-${var.subnetOctet}"
  dest_range = "172.16.${var.subnetOctet}.0/24"
  network = "inside-${var.subnetOctet}"
  next_hop_ip = "10.${var.subnetOctet}.10.2"
  priority = 100
  depends_on = [
    google_compute_subnetwork.inside-net]
}

resource "google_compute_route" "inside-route-to-database" {
  name = "inside-route-to-database-${var.subnetOctet}"
  dest_range = "10.${var.subnetOctet}.20.0/24"
  network = "inside-${var.subnetOctet}"
  next_hop_ip = "10.${var.subnetOctet}.10.2"
  priority = 100
  depends_on = [
    google_compute_subnetwork.inside-net]
}

resource "google_compute_route" "inside-route-to-real-internet" {
  name = "inside-route-to-real-internet-${var.subnetOctet}"
  dest_range = "0.0.0.0/0"
  network = "inside-${var.subnetOctet}"
  next_hop_ip = "10.${var.subnetOctet}.10.2"
  priority = 100
  depends_on = [
    google_compute_subnetwork.inside-net]
}

resource "google_compute_route" "database-route-to-inside" {
  name = "database-route-to-inside-${var.subnetOctet}"
  dest_range = "10.${var.subnetOctet}.10.0/24"
  network = "database-${var.subnetOctet}"
  next_hop_ip = "10.${var.subnetOctet}.20.2"
  priority = 100
  depends_on = [
    google_compute_subnetwork.database-net]
}

/*
 *  GCP Instance - PAN-OS Next-generation Firewall
 */

resource "google_compute_instance" "vm-series" {
  count = 1
  name = "${lower(var.requestNumber)}-${lower(var.deploymentArea)}-${lower(var.devWorkflow)}-fw-${var.subnetOctet}"
  machine_type = "n1-standard-4"
  zone = var.zone
  can_ip_forward = true
  allow_stopping_for_update = true
  metadata = {
    serial-port-enable = true
    ssh-keys = "admin:${var.gce_ssh_pub_key}"
    vmseries-bootstrap-gce-storagebucket = "panos-bootstrap-bucket"
  }
  service_account {
    scopes = [
      "https://www.googleapis.com/auth/cloud.useraccounts.readonly",
      "https://www.googleapis.com/auth/devstorage.read_only",
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring.write",
    ]
  }
  network_interface {
    subnetwork = "mgmt-net-${var.subnetOctet}"
    network_ip = "192.168.${var.subnetOctet}.2"
    access_config {
      // Ephemeral public IP
    }
  }

  network_interface {
    subnetwork = "outside-net-${var.subnetOctet}"
    network_ip = "172.16.${var.subnetOctet}.2"
    access_config {
      // Ephemeral public IP
    }
  }

  network_interface {
    network_ip = "10.${var.subnetOctet}.10.2"
    subnetwork = "inside-net-${var.subnetOctet}"
  }

  network_interface {
    network_ip = "10.${var.subnetOctet}.20.2"
    subnetwork = "database-net-${var.subnetOctet}"
  }

  boot_disk {
    initialize_params {
      #image = "https://www.googleapis.com/compute/v1/projects/auto-hack-cloud/global/images/vmseries-byol-8-1-5"
      image = "https://www.googleapis.com/compute/v1/projects/paloaltonetworksgcp-public/global/images/vmseries-bundle2-814"
    }
  }
  depends_on = [
    google_compute_subnetwork.mgmt-net,
    google_compute_subnetwork.inside-net,
    google_compute_subnetwork.outside-net,
    google_compute_subnetwork.database-net,
  ]

  // This provisioner checks the firewall is up and ready to accept configuration
  #provisioner "local-exec" {
  #  command = "./check_fw.sh ${google_compute_instance.vm-series.network_interface.0.access_config.0.nat_ip} ${var.panos_api_key}"
  #}
  // This provisioner checks the firewall is up and ready to accept configuration
  #provisioner "local-exec" {
  #  command = "./check_fw.sh ${google_compute_instance.vm-series.network_interface.0.access_config.0.nat_ip} ${var.panos_api_key}"
  #}
  provisioner "local-exec" {
    command = "ansible-playbook -vvv check_fw.yml --extra-vars \"mgmt_ip=${google_compute_instance.vm-series[0].network_interface[0].access_config[0].nat_ip} admin_username=panadmin admin_password=Panadmin001!\""
  }

  // This provisioner configures NAT rules on the firewall using Ansible
  // This provisioner configures NAT rules on the firewall using Ansible
  provisioner "local-exec" {
    command = "ansible-playbook -vvv create_nat_rules.yml --extra-vars \"mgmt_ip=${google_compute_instance.vm-series[0].network_interface[0].access_config[0].nat_ip} untrust_ip=${google_compute_instance.vm-series[0].network_interface[1].network_ip} linux_ip=${google_compute_instance.linux.network_interface[0].network_ip} apikey=${var.panos_api_key}\""
  }

  // This provisioner configures system settings on the firewall using Ansible
  // This provisioner configures system settings on the firewall using Ansible
  provisioner "local-exec" {
    command = "ansible-playbook -vvv customise_panos.yml --extra-vars \"mgmt_ip=${google_compute_instance.vm-series[0].network_interface[0].access_config[0].nat_ip} nickname='${lower(var.requestNumber)}-${lower(var.deploymentArea)}-${lower(var.devWorkflow)}' message='${var.my_gcp_project}' apikey=${var.panos_api_key}\""
  }
}

/*
 *  GCP Instance - Linux Web Server Victim
 */

resource "google_compute_instance" "linux" {
  name = "${lower(var.requestNumber)}-${lower(var.deploymentArea)}-${lower(var.devWorkflow)}-linux-${var.subnetOctet}"
  machine_type = "n1-standard-1"
  zone = var.zone

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-1404-trusty-v20180818"
    }
  }

  network_interface {
    subnetwork = "inside-net-${var.subnetOctet}"
    network_ip = "10.${var.subnetOctet}.10.101"

    access_config {
      // Ephemeral public IP
    }
  }

  metadata = {
    serial-port-enable = true
    ssh-keys = "admin:${var.gce_ssh_pub_key}"
  }

  metadata_startup_script = "wget https://raw.githubusercontent.com/jamesholland-uk/auto-hack-cloud/master/linuxserver-startup.sh \n chmod 755 linuxserver-startup.sh \n ./linuxserver-startup.sh ${var.subnetOctet}"

  labels = {
    "type" = "web"
  }

  service_account {
    scopes = [
      "userinfo-email",
      "compute-ro",
      "storage-ro"]
  }

  depends_on = [
    google_compute_subnetwork.inside-net]
}

/*
 *  GCP Instance - Kali attacker
 */

resource "google_compute_instance" "kali" {
  name = "${lower(var.requestNumber)}-${lower(var.deploymentArea)}-${lower(var.devWorkflow)}-kali-${var.subnetOctet}"
  machine_type = "n1-standard-1"
  zone = var.zone

  boot_disk {
    initialize_params {
      image = "centos-cloud/centos-7-v20180815"
    }
  }

  network_interface {
    subnetwork = "outside-net-${var.subnetOctet}"
    network_ip = "172.16.${var.subnetOctet}.10"

    access_config {
      // Ephemeral public IP
    }
  }

  metadata = {
    serial-port-enable = true
    ssh-keys = "admin:${var.gce_ssh_pub_key}"
  }

  metadata_startup_script = "curl https://raw.githubusercontent.com/jamesholland-uk/auto-hack-cloud/master/kali-startup.sh > kali-startup.sh \n chmod 755 kali-startup.sh \n ./kali-startup.sh ${var.subnetOctet}"

  service_account {
    scopes = [
      "userinfo-email",
      "compute-ro",
      "storage-ro"]
  }

  depends_on = [
    google_compute_subnetwork.outside-net]
}

/*
 *  GCP Instance - Database server
 */

resource "google_compute_instance" "db" {
  name = "${lower(var.requestNumber)}-${lower(var.deploymentArea)}-${lower(var.devWorkflow)}-db-${var.subnetOctet}"
  machine_type = "n1-standard-1"
  zone = var.zone

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-1404-trusty-v20180818"
    }
  }

  network_interface {
    subnetwork = "database-net-${var.subnetOctet}"
    network_ip = "10.${var.subnetOctet}.20.50"

    access_config {
      // Ephemeral public IP
    }
  }

  metadata = {
    serial-port-enable = true
    ssh-keys = "admin:${var.gce_ssh_pub_key}"
  }

  metadata_startup_script = "wget https://raw.githubusercontent.com/jamesholland-uk/auto-hack-cloud/master/database-startup.sh \n chmod 755 database-startup.sh \n ./database-startup.sh ${var.subnetOctet}"

  labels = {
    "type" = "database"
  }

  service_account {
    scopes = [
      "userinfo-email",
      "compute-ro",
      "storage-ro"]
  }

  depends_on = [
    google_compute_subnetwork.database-net]
}

/*
 *  GCP Firewall Rules
 */

resource "google_compute_firewall" "internet-ingress-for-mgt" {
  name = "internet-ingress-for-mgt-${var.subnetOctet}"
  network = "mgmt-${var.subnetOctet}"
  allow {
    protocol = "tcp"
    ports = [
      "22",
      "443"]
  }
  source_ranges = [
    "0.0.0.0/0"]
  depends_on = [
    google_compute_network.mgmt]
}

resource "google_compute_firewall" "internet-ingress-for-db" {
  name = "internet-ingress-for-db-${var.subnetOctet}"
  network = "database-${var.subnetOctet}"
  allow {
    protocol = "tcp"
    ports = [
      "22",
      "443"]
  }
  source_ranges = [
    "0.0.0.0/0"]
  depends_on = [
    google_compute_network.database]
}

resource "google_compute_firewall" "internet-ingress-for-outside" {
  name = "internet-ingress-for-outside-${var.subnetOctet}"
  network = "outside-${var.subnetOctet}"
  allow {
    protocol = "tcp"
    ports = [
      "22",
      "80",
      "443",
      "3389",
      "4200",
      "8080"]
  }
  allow {
    protocol = "udp"
    ports = [
      "4501"]
  }
  source_ranges = [
    "0.0.0.0/0"]
  depends_on = [
    google_compute_network.outside]
}

resource "google_compute_firewall" "internet-ingress-for-inside" {
  name = "internet-ingress-for-inside-${var.subnetOctet}"
  network = "inside-${var.subnetOctet}"
  allow {
    protocol = "tcp"
    ports = [
      "22",
      "80",
      "443",
      "3389",
      "8080"]
  }
  source_ranges = [
    "0.0.0.0/0"]
  depends_on = [
    google_compute_network.inside]
}

resource "google_compute_firewall" "outside-to-inside" {
  name = "outside-to-inside-${var.subnetOctet}"
  network = "inside-${var.subnetOctet}"
  allow {
    protocol = "all"
    // Any port
  }
  source_ranges = [
    "10.${var.subnetOctet}.10.0/24",
    "172.16.${var.subnetOctet}.0/24"]
  depends_on = [
    google_compute_network.inside]
}

resource "google_compute_firewall" "inside-to-db" {
  name = "inside-to-db-${var.subnetOctet}"
  network = "database-${var.subnetOctet}"
  allow {
    protocol = "all"
    // Any port
  }
  source_ranges = [
    "10.${var.subnetOctet}.10.0/24",
    "10.${var.subnetOctet}.20.0/24"]
  depends_on = [
    google_compute_network.database]
}

resource "google_compute_firewall" "inside-to-outside" {
  name = "inside-to-outside-${var.subnetOctet}"
  network = "outside-${var.subnetOctet}"
  allow {
    protocol = "all"
    // Any port
  }
  source_ranges = [
    "10.${var.subnetOctet}.10.0/24",
    "172.16.${var.subnetOctet}.0/24"]
  depends_on = [
    google_compute_network.outside]
}

resource "google_compute_firewall" "db-to-inside" {
  name = "db-to-inside-${var.subnetOctet}"
  network = "inside-${var.subnetOctet}"
  allow {
    protocol = "all"
    // Any port
  }
  source_ranges = [
    "10.${var.subnetOctet}.10.0/24",
    "10.${var.subnetOctet}.20.0/24"]
  depends_on = [
    google_compute_network.inside]
}