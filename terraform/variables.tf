variable "vsphere_user" {
  type = string
}

variable "vsphere_password" {
  type      = string
  sensitive = true
}

variable "vsphere_server" {
  type        = string
  description = "vCenter or ESXi host address, e.g. 192.168.1.10"
}

variable "datacenter" {
  type    = string
  default = "ha-datacenter" # default name for a standalone ESXi host
}

variable "datastore" {
  type = string
}

variable "esxi_host" {
  type        = string
  description = "ESXi host name as it appears in the datacenter (often localhost.localdomain on standalone hosts)"
}

variable "network" {
  type    = string
  default = "VM Network"
}

variable "template_name" {
  type        = string
  description = "Name of the VM template to clone (e.g. an Ubuntu cloud-init image)"
}

variable "node_count" {
  type    = number
  default = 3 # 1 control-plane + 2 workers is a reasonable starting cluster
}
