# MagikUp — Kubernetes deployment template

Every project under `kubernetes/` is a kustomize **base + overlay**:

```
kubernetes/<project>/
├── base/                     # cluster-agnostic workload
│   ├── kustomization.yaml
│   ├── rbac.yaml             # ServiceAccount
│   ├── deployment.yaml       # image = bare repo name; tag set by the overlay
│   └── pvc.yaml              # PVCs, no storageClassName
└── overlays/<env>/           # the real per-cluster values
    ├── kustomization.yaml    # namespace, image tag, StorageClass patch, resources
    ├── configmap.yaml        # config.ini (pg_dump path, etc.)
    ├── service.yaml          # or service-lb.yaml (LoadBalancer)
    └── ingress.yaml          # exposure (omit where a LoadBalancer is used)
```

`template/` is the **only** project tracked in git — a blanked skeleton with
placeholders. The real projects live on disk, **untracked** (see `/.gitignore`):

```
kubernetes/
├── template/            ✅ committed. overlays/example with placeholders.
├── panservice-servizi/  ⬜ untracked. overlays/prod  (RKE2)
├── vetri_speciali_gcp/  ⬜ untracked. overlays/prod  (GKE, LoadBalancer)
├── testdialberto/       ⬜ untracked. overlays/test  (Rancher)
└── skf-pume-dev/        ⬜ untracked. overlays/dev   (AKS/Arc, ns d2w-test)
```

## Create a new environment

1. Copy the whole template project (it will be gitignored):

   ```bash
   cp -r kubernetes/template kubernetes/<my-cluster>
   ```

   > If the name isn't already covered by `/.gitignore`, add it — real cluster
   > values must never be committed.

2. Fill in the placeholders in `overlays/example/` (rename it to your env, e.g.
   `overlays/prod`):

   | Placeholder         | Where                          | Example                        |
   |---------------------|--------------------------------|--------------------------------|
   | `namespace`         | `overlays/<env>/kustomization` | `magikup`                      |
   | `__IMAGE_TAG__`     | `overlays/<env>/kustomization` (`images.newTag`) | `4.4.1`      |
   | `__INGRESS_HOST__`  | `overlays/<env>/ingress.yaml`  | `magikup.decisyon.com`         |
   | `__CLUSTER_ISSUER__`| `overlays/<env>/ingress.yaml`  | `letsencrypt-prod` (uncomment) |
   | `__STORAGE_CLASS__` | `overlays/<env>/kustomization` (PVC patch) | `auto-ebs-gp3` (uncomment) or omit |

   Also decide on the **NetworkPolicy** (uncomment `networkpolicy.yaml` in the
   overlay only where ingress-nginx uses normal pod networking — not on
   hostNetwork controllers like RKE2) and the **Service** (`service.yaml`
   ClusterIP + Ingress, or `service-lb.yaml` for a LoadBalancer with no Ingress).

3. Create the Secret out-of-band (never committed):

   ```bash
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   # put it in a copy of secret.yaml.example, then:
   kubectl --context <ctx> -n <ns> apply -f secret.yaml
   ```

   > ⚠️ On a cluster that already runs MagikUp, the existing `magikup-secret`
   > decrypts the stored endpoint passwords — **do not overwrite it**.

4. Deploy the overlay:

   ```bash
   kubectl --context <ctx> apply -k kubernetes/<my-cluster>/overlays/<env>
   # or: ./scripts/deploy.sh -e <my-cluster>/overlays/<env>
   ```

## Why base + overlay per project

`base/` is the stable workload (ServiceAccount, Deployment, PVCs) — it rarely
changes. The overlay carries everything cluster-specific: namespace, image tag,
StorageClass, config, and exposure. Bumping the image is a one-line change to
`images.newTag` in the overlay; the base is untouched.
