# NEVER run terraform apply from GitHub CI. New dedicated OCI Always Free VM only.
# By default this creates ZERO resources and opens ZERO public decoy ports.
terraform {
  required_version = ">= 1.5.0"
  required_providers { oci = { source = "oracle/oci", version = "~> 7.0" } }
}
provider "oci" { region = var.region }

locals {
  sensor_name = "vynalth-isolated-honeypot"
  decoy_ports = [2222, 2323, 2121, 13306]
}
resource "oci_core_vcn" "sensor" {
  count          = var.launch_approved ? 1 : 0
  compartment_id = var.compartment_ocid
  cidr_blocks    = ["172.29.0.0/16"]
  display_name   = "${local.sensor_name}-vcn"
  dns_label      = "vynsensor"
}
resource "oci_core_internet_gateway" "sensor" {
  count          = var.launch_approved ? 1 : 0
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.sensor[0].id
  display_name   = "${local.sensor_name}-igw"
  enabled        = true
}
resource "oci_core_route_table" "sensor" {
  count          = var.launch_approved ? 1 : 0
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.sensor[0].id
  display_name   = "${local.sensor_name}-routes"
  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_internet_gateway.sensor[0].id
  }
}
resource "oci_core_security_list" "sensor" {
  count          = var.launch_approved ? 1 : 0
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.sensor[0].id
  display_name   = "${local.sensor_name}-ingress"
  dynamic "ingress_security_rules" {
    for_each = var.admin_ssh_cidr == "" ? [] : [var.admin_ssh_cidr]
    content {
      protocol = "6"
      source   = ingress_security_rules.value
      tcp_options {
        min = 22
        max = 22
      }
    }
  }
  dynamic "ingress_security_rules" {
    for_each = var.public_decoys_approved ? local.decoy_ports : []
    content {
      protocol = "6"
      source   = "0.0.0.0/0"
      tcp_options {
        min = ingress_security_rules.value
        max = ingress_security_rules.value
      }
    }
  }
  # Only host HTTPS + DNS for package bootstrap. Container egress requires
  # an additional host DROP-NEW rule; this rule alone is not containment.
  egress_security_rules {
    protocol = "6"
    destination = "0.0.0.0/0"
    tcp_options {
      min = 443
      max = 443
    }
  }
  egress_security_rules {
    protocol = "17"
    destination = "0.0.0.0/0"
    udp_options {
      min = 53
      max = 53
    }
  }
}
resource "oci_core_subnet" "sensor" {
  count                   = var.launch_approved ? 1 : 0
  compartment_id          = var.compartment_ocid
  vcn_id                  = oci_core_vcn.sensor[0].id
  cidr_block              = "172.29.10.0/24"
  display_name            = "${local.sensor_name}-subnet"
  dns_label               = "sensor"
  route_table_id          = oci_core_route_table.sensor[0].id
  security_list_ids       = [oci_core_security_list.sensor[0].id]
  prohibit_public_ip_on_vnic = false
}
resource "oci_core_instance" "sensor" {
  count               = var.launch_approved ? 1 : 0
  compartment_id      = var.compartment_ocid
  availability_domain = var.availability_domain
  display_name        = local.sensor_name
  shape               = "VM.Standard.A1.Flex"
  shape_config {
    ocpus = 1
    memory_in_gbs = 6
  }
  source_details {
    source_type             = "image"
    source_id               = var.arm64_image_ocid
    boot_volume_size_in_gbs = 50
  }
  create_vnic_details {
    subnet_id        = oci_core_subnet.sensor[0].id
    assign_public_ip = true
    display_name     = "${local.sensor_name}-vnic"
  }
  metadata = {
    ssh_authorized_keys = var.operator_ssh_public_key
  }
  lifecycle {
    precondition {
      condition     = !var.public_decoys_approved || var.launch_approved
      error_message = "Decoy ingress requires explicit new VM approval."
    }
  }
  # No automated software install or secret injection. Network isolation,
  # provider eligibility and storage must be verified before deployment.
}
output "sensor_instance_id" {
  value       = var.launch_approved ? oci_core_instance.sensor[0].id : null
  description = "Instance OCID only available after an explicitly reviewed apply"
}
