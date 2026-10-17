terraform {
  required_providers {
    vsphere = {
      source  = "hashicorp/vsphere"
      version = "~> 2.7"
    }
   kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.31"
  }
}
  required_version = ">= 1.7.0"
}

provider "vsphere" {
  user                 = var.vsphere_user
  password             = var.vsphere_password
  vsphere_server       = var.vsphere_server
  allow_unverified_ssl = true
}

data "vsphere_datacenter" "dc" {
  name = var.datacenter
}

data "vsphere_datastore" "datastore" {
  name          = var.datastore
  datacenter_id = data.vsphere_datacenter.dc.id
}

data "vsphere_resource_pool" "pool" {
  name          = "${var.esxi_host}/Resources"
  datacenter_id = data.vsphere_datacenter.dc.id
}

data "vsphere_network" "network" {
  name          = var.network
  datacenter_id = data.vsphere_datacenter.dc.id
}



resource "vsphere_virtual_machine" "k3s_node" {
  count            = var.node_count
  name             = "k3s-node-${count.index}"
  resource_pool_id = data.vsphere_resource_pool.pool.id
  datastore_id     = data.vsphere_datastore.datastore.id

  num_cpus = 2
  memory   = 4096
  guest_id = "ubuntu64Guest"


  network_interface {
    network_id   = data.vsphere_network.network.id
    adapter_type = "vmxnet3"
  }

  disk {
    label            = "Hard disk 1"
    size             = 25
    thin_provisioned = true
  }

  lifecycle {
    ignore_changes = [disk[0].size, guest_id, memory, cdrom, enable_logging, boot_delay]
  }
}

provider "kubernetes" {
  config_path = "${path.module}/kubeconfig.yaml"
}

resource "kubernetes_namespace" "lab_apps" {
  metadata {
    name = "lab-apps"
labels = {
      purpose = "learning"
    }
  }
}
