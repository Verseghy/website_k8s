# Software catalog

Backstage/RHDH catalog entities for the Verseghy platform.

Entities reach the catalog two ways:

- **Static `Location`** — the files in this directory, registered via a single
  `catalog.locations` entry in
  [`../verseghy-website/rhdh/app-config.yaml`](../verseghy-website/rhdh/app-config.yaml)
  pointing at `all.yaml`. This holds the org, domain, systems, resources, APIs,
  platform plumbing, and the one component without a source repo (`website-static`).
- **GitHub discovery** — the `github` provider (configured in
  [`../verseghy-website/rhdh/dynamic-plugins.yaml`](../verseghy-website/rhdh/dynamic-plugins.yaml))
  scans `Verseghy/website_*` repos for a root `catalog-info.yaml` and ingests it.
  `website-frontend`, `website-backend`, and `website-backend2` are defined this
  way — the Component entity lives next to its code.

## Model

```
Domain: verseghy
├─ System: verseghy-website            (the public site)
│  ├─ Component website-frontend  (type: website)  → repo website_frontend
│  ├─ Component website-backend   (type: service)  → repo website_backend   → mysql
│  ├─ Component website-backend2  (type: service)  → repo website_backend2  → mysql, backend2-redis
│  ├─ Component website-static    (type: website)  → repo website_static
│  ├─ Resource  mysql             (type: database)
│  └─ Resource  backend2-redis    (type: cache)
└─ System: verseghy-platform           (build & delivery plumbing)
   ├─ Component prow                  (type: service)
   ├─ Component argocd-image-updater  (type: service)
   └─ Resource  onepassword-store     (type: secret-store)
Group: verseghy  (owner of everything; members TwoDCube, smrtrfszm)
```

## Files

| File | Entities |
|------|----------|
| `all.yaml` | `Location` listing the files below |
| `org.yaml` | `Group` verseghy (ownership). `User`s + team `Group`s are ingested from the Verseghy GitHub org by the github-org provider (`dynamic-plugins.yaml`); sign-in is restricted to those org members |
| `systems.yaml` | `Domain` + the two `System`s |
| `resources.yaml` | `mysql`, `backend2-redis`, `onepassword-store` |
| `components.yaml` | `website-static` only (no source repo). `website-frontend`, `website-backend`, `website-backend2` live in each repo's own `catalog-info.yaml` and are auto-discovered |
| `platform.yaml` | `prow`, `argocd-image-updater` |

## Annotation conventions

| Annotation | Purpose |
|------------|---------|
| `github.com/project-slug` | links the source repo |
| `argocd/instance-name` + `argocd/app-selector` | Argo CD sync/health card |
| `janus-idp.io/tekton` + `backstage.io/kubernetes-label-selector` + `backstage.io/kubernetes-namespace` | Tekton CI card from PAC builds |
| `backstage.io/techdocs-ref` | renders docs from the source repo |

A component's Argo CD `Application` must carry the matching
`verseghy.net/component: <name>` label. Data dependencies use
`spec.dependsOn: [resource:<name>]`.
