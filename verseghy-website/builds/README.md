# Automatic image builds (Pipelines-as-Code → Shipwright)

Pushes to `master` on the website source repos automatically build their
container images with Shipwright, triggered by Pipelines-as-Code (PAC). This
directory holds the PAC `Repository` bindings; the actual build recipe lives in
each source repo (see below).

## How it works

```
git push master ──▶ GitHub App (PAC, app-id 1271459)
                        │  webhook
                        ▼
        pipelines-as-code-controller (openshift-pipelines)
                        │  matches event URL to a Repository CR (this dir)
                        ▼
        PipelineRun from <source-repo>/.tekton/push.yaml  (runs in `verseghy`)
                        │  oc create buildrun + poll
                        ▼
        Shipwright BuildRun (self-contained, pinned to pushed SHA)
                        │
                        ▼
        ghcr.io/verseghy/<image>
```

Two pieces per repository:

| Piece | Lives in | File |
|-------|----------|------|
| PAC `Repository` (opt-in + namespace routing) | this repo (GitOps) | `pac-repository-frontend.yaml`, `pac-repository-backend2.yaml` |
| `PipelineRun` trigger **and the full build recipe** | the **source** repo's `master` branch | `website_frontend/.tekton/push.yaml`, `website_backend2/.tekton/push.yaml` |

## Why there is no `Build` CR here

The `PipelineRun` creates a Shipwright `BuildRun` with an **embedded build spec**
(`spec.build.spec`) rather than referencing a standalone `Build` by name. That
makes each `.tekton/push.yaml` the single source of truth for how its image is
built, and — crucially — lets it **pin `source.git.revision` to the exact pushed
commit** for reproducible, per-commit builds. (A `BuildRun` that references a
`Build` by *name* cannot override the revision; only an embedded spec can.)

Trade-offs of dropping the standalone `Build` CRs: there is no `oc get builds`
entry and no apply-time build validation, and a manual one-off build now means
crafting a full `BuildRun` (copy the `spec.build.spec` block from the repo's
`.tekton/push.yaml`).

## Notes

- **Auth:** the cluster-global PAC GitHub App; no per-repo secret. The App must
  be installed on each source repo.
- **RBAC:** the `PipelineRun` runs as the `pipeline` ServiceAccount in `verseghy`,
  which has `create/get` on `buildruns.shipwright.io` via the
  `openshift-pipelines-edit` (ClusterRole/edit) binding.
- **Concurrency:** `concurrency_limit: 1` on each `Repository` serializes builds
  so rapid pushes don't race.
- **PR builds (optional):** add a `.tekton/pull-request.yaml` with
  `on-event: "[pull_request]"` to also build on pull requests.
