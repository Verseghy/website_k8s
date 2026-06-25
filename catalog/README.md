# Software catalog

Backstage/RHDH catalog entities for the Verseghy platform. RHDH ingests these via a
single static `Location` configured in
[`../verseghy-website/rhdh/app-config.yaml`](../verseghy-website/rhdh/app-config.yaml)
(`catalog.locations` → `all.yaml`).

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
| `components.yaml` | the four website components |
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
