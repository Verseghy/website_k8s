# Automatic image builds (Pipelines-as-Code → Shipwright)

The Shipwright `Build` objects in this directory (`frontend`, `backend2`) define
*how* the images are built. This README documents how they are **triggered
automatically on every push to `master`**, instead of being kicked off by hand.

## How it works

```
git push master ──▶ GitHub App (PAC, app-id 1271459)
                        │  webhook
                        ▼
        pipelines-as-code-controller (openshift-pipelines)
                        │  matches event URL to a Repository CR
                        ▼
        Repository CR (this dir) ── routes into namespace `verseghy`
                        │  reads .tekton/push.yaml from the pushed commit
                        ▼
        PipelineRun (build-frontend / build-backend2)
                        │  oc create buildrun + poll
                        ▼
        Shipwright BuildRun ──▶ pushes ghcr.io/verseghy/<image>
```

Two pieces are needed per repository:

| Piece | Lives in | File |
|-------|----------|------|
| `Repository` CR (opt-in + namespace routing) | this repo (GitOps) | `pac-repository-frontend.yaml`, `pac-repository-backend2.yaml` |
| `PipelineRun` trigger (`.tekton/`) | the **source** repo's `master` branch | `website_frontend/.tekton/push.yaml`, `website_backend2/.tekton/push.yaml` |

The PipelineRun does not rebuild the image itself; it creates a Shipwright
`BuildRun` for the existing `Build` and waits for it, so the result is reported
back onto the commit as a GitHub check.

## Notes / caveats

- **Revision:** the Shipwright `Build` pins no git revision, so a `BuildRun`
  always builds current `master` HEAD. For a push event that is the triggering
  commit; the SHA is recorded as a label (`pipelinesascode.tekton.dev/sha`) for
  traceability. Rapid back-to-back pushes may both build the newer HEAD —
  `concurrency_limit: 1` on the Repository serializes them.
- **Auth:** uses the cluster-global PAC GitHub App; no per-repo secret needed.
  The App must be **installed on each source repo** in the GitHub org for events
  to flow.
- **RBAC:** the PipelineRun runs as the `pipeline` ServiceAccount in `verseghy`,
  which already has `create/get` on `buildruns.shipwright.io` via the
  `openshift-pipelines-edit` (ClusterRole/edit) binding.
- **PR builds (optional):** to also build on pull requests, add a
  `.tekton/pull-request.yaml` with `on-event: "[pull_request]"`.
