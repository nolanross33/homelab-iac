# homelab-iac

Terraform + Kubernetes for a home lab. Terraform provisions VM nodes on
vSphere/ESXi; those nodes run a k3s cluster, with workloads deployed via
Kubernetes manifests.

## Setup

Runs against ESXi (a type-1 hypervisor) via the vSphere Terraform provider.
Swap in Proxmox, a different vSphere host, or whatever hypervisor you're
running by adjusting the provider block and variables in `terraform/`.

## Repo layout

```
terraform/        vSphere provider config — provisions k3s node VMs
k8s/base/          Core Kubernetes manifests (namespace, deployment, service)
docs/roadmap.md    Build phases and design notes
threat-intel/      A real workload running on this cluster — see below
```

## What's actually running on it

Infra you can `terraform apply` is one thing; infra doing something is
another. [`threat-intel/`](./threat-intel) is a k3s CronJob pulling the
URLhaus and Feodo Tracker threat-intel feeds and forwarding them into a
NetWitness instance for correlation. The first version used a custom
NetWitness parser that looked right but silently extracted zero fields —
the fix (CEF over syslog, picked up by NetWitness's stock CEF parser
instead) and the reasoning behind it are written up in that folder's
README.

## Getting started

```bash
cd terraform
terraform init
terraform plan   # review before applying
terraform apply
```

Then install k3s on the provisioned VMs and apply the manifests in
`k8s/base/`. See `docs/roadmap.md` for the build phases.
