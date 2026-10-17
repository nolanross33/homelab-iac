# Build phases

## Phase 1 — Terraform

Provisions k3s node VMs on the vSphere/ESXi host via the Terraform vSphere
provider (`terraform/`). State is currently local; a remote backend
(S3-compatible or similar, with state locking) would be the next step for
anything beyond a single-operator lab.

## Phase 2 — k3s on the provisioned VMs

k3s installed on the Terraform-provisioned VMs (control-plane + workers),
with base manifests in `k8s/base/` — namespace, deployment, and service for
a small sanity-check workload (`hello-web`).

## Phase 3 — RBAC, NetworkPolicies, Secrets

- **RBAC** — a ServiceAccount scoped to only what a workload needs
  (Role/RoleBinding), not cluster-admin by default.
- **NetworkPolicies** — default-deny in the `lab-apps` namespace, with
  explicit allow rules for only the traffic `hello-web` actually needs.
- **Secrets** — Kubernetes Secrets are base64-encoded, not encrypted, at
  rest by default; worth pairing with Sealed Secrets, Vault, or SOPS for
  anything beyond a lab.

## Phase 4 — Terraform managing the Kubernetes layer

The `kubernetes` provider block in `main.tf` lets Terraform manage
cluster-side resources (starting with the namespace) alongside the vSphere
VMs, instead of `kubectl apply` as a separate step — one state file for
infra and workloads.
