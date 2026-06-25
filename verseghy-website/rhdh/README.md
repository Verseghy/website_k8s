# Red Hat Developer Hub (RHDH)

Internal developer portal that catalogs and documents the Verseghy platform. Runs on
the hub cluster (OKD, `apps.okd4.home.zoltanszepesi.com`) in the `verseghy` namespace,
deployed by the RHDH Operator and managed by Argo CD.

- URL: https://rhdh.apps.okd4.home.zoltanszepesi.com
- Operator CRD: `backstages.rhdh.redhat.com` (RHDH 1.9)
- Catalog content: [`/catalog`](../../catalog)

## Files

| File | Purpose |
|------|---------|
| `backstage.yaml` | `Backstage` CR — wires the app-config + dynamic-plugins ConfigMaps, the env secrets (`rhdh-secrets`, `rhdh-k8s-reader-token`, the operator-managed `backstage-local-user`), and the Route |
| `app-config.yaml` | `app-config-rhdh` — GitHub integration + sign-in, catalog location, Argo CD plugin, Kubernetes/Tekton plugin, TechDocs |
| `dynamic-plugins.yaml` | `dynamic-plugins-rhdh` — enables the Argo CD, Kubernetes, and Tekton plugins |
| `rbac.yaml` | `rhdh-k8s-reader` ServiceAccount + token + read-only `ClusterRole` (pods/log, deployments, routes, `tekton.dev`, `shipwright.io`) |
| `../applications/rhdh.yaml` | Argo CD `Application` (app-of-apps child, `in-cluster` → `verseghy`) |
| `../eso-in-cluster/rhdh-externalsecret.yaml` | `rhdh-secrets` synced from 1Password by ESO |

Secret values are env-var references and never committed: `${GITHUB_APP_ID}` etc.
from 1Password via ESO, `${token}` (Kubernetes reader) and `${apiToken}` (Argo CD
read-only) from operator-managed secrets in this namespace.

## Plugins

Enabled in `dynamic-plugins.yaml` using the Operator format (bare `includes:`/`plugins:`,
not the Helm `global.dynamic` wrapper).

| Plugin | Package (preinstalled in the 1.9 image) |
|--------|------------------------------------------|
| Argo CD UI / backend | `backstage-community-plugin-redhat-argocd` / `-backend` |
| Kubernetes UI / backend | `backstage-plugin-kubernetes` / `backstage-plugin-kubernetes-backend-dynamic` |
| Tekton CI | `backstage-community-plugin-tekton` |

GitHub integration, GitHub sign-in, the static catalog location, and TechDocs are core
backend features — no plugin entry needed.

## How entities bind to live data

- **Argo CD** — each `Application` in `../applications/` carries a
  `verseghy.net/component: <name>` label; entities select it with
  `argocd/app-selector: verseghy.net/component=<name>` + `argocd/instance-name: verseghy`.
- **Kubernetes / Tekton** — the plugin reads the hub cluster
  (`https://kubernetes.default.svc`) with the `rhdh-k8s-reader` ServiceAccount token.
  Entities match build resources with
  `backstage.io/kubernetes-label-selector` against the PAC label
  `pipelinesascode.tekton.dev/repository=<repo>`, scoped by
  `backstage.io/kubernetes-namespace: verseghy`. `janus-idp.io/tekton: <name>` enables
  the CI card. Builds run on this hub, so no per-PipelineRun changes are needed.

## Sign-in

`auth.environment: production` + `signInPage: github` make GitHub the only sign-in.
The `usernameMatchingUserEntityName` resolver matches the GitHub login to a `User`
entity in [`/catalog/org.yaml`](../../catalog/org.yaml).
