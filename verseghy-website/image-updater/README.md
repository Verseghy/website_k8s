# Argo CD Image Updater

Auto-promotes container images into this repo via pull requests, run by the
`verseghy/argocd` instance.

## Managed images

| App | Image | Strategy |
|-----|-------|----------|
| frontend, backend, backend2 | `ghcr.io/verseghy/website_*` | newest-build (commit-SHA tags) |
| mysql | `mysql` | semver, 8.4 patch line |
| backend2-redis | `redis` | semver, 6.2-alpine patch line |

Each managed app has a `kustomization.yaml` holding the `images:` entry that
Image Updater rewrites.

## Credentials

- Registry read: `ghcr-pull-secret`
- Git push + PR: `image-updater-git-creds` (Prow GitHub App), from
  `../eso-in-cluster/image-updater-externalsecret.yaml`

## Not managed

`static`, Prow CronJob images.
