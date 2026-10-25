# website_k8s

This repository is the GitOps source of the Verseghy website platform: the
Argo CD Applications and the manifests they sync, the Prow configuration, the
Pipelines-as-Code (PAC) `Repository` CRs and the Shipwright build strategy. A
wrong command or a wrong merge here changes running clusters, so the rules
below win over generic advice.

The decisions behind them are the ADRs of the public website_backend3
repository; this file summarises them and links to them ([ADR 0024] section 2).
Read the linked ADR before you act on a rule.

## Platform invariants

- **Use `oc`, never `kubectl`. Never force-delete pods.** Delete a pod
  normally and let it terminate; if it does not, stop and ask the maintainer.
- **Never delete a PersistentVolumeClaim, PersistentVolume or Argo CD
  Application** unless the volume's reclaim policy is `Retain` and a verified
  backup exists. Deleting an Application deletes its resources: the
  Applications here carry the `resources-finalizer.argocd.argoproj.io`
  finalizer. Agents never do it; a human does, after both checks.
- **A new app's first image tag is set by hand in its kustomization**
  (`images:` with `newTag`; for an image that PAC builds, the full
  40-character commit SHA). Argo CD Image Updater moves the later tags and
  opens the bump PRs here (`verseghy-website/image-updater/`); for the images
  PAC builds it accepts only `^[0-9a-f]{40}$` tags. ([ADR 0022])
- **A new repository's PAC `Repository` CR merges before the first push to
  `master` that carries `.tekton/push.yaml`.** PAC builds only for a
  repository whose CR already exists (`verseghy-website/builds/`).
  ([ADR 0022]; [ADR 0012] section 1)
- **The `buildah-ubi9` BuildStrategy documents its changes from upstream in
  its header and is diffed again after every operator upgrade**
  (`verseghy-website/builds/buildstrategy-buildah-ubi9.yaml`; its header says
  how). ([ADR 0022] section 1)
- **CI job names are branch-protection contracts.** Required contexts are
  listed by name in `verseghy-website/prow/configmaps.yaml`
  (`branch-protection`) and in GitHub rulesets. Renaming a job and changing
  the Prow configuration happen together, or the repository can no longer
  merge. ([ADR 0022] section 3)
- **The `verseghy-prow` app must be a bypass actor on any ruleset that
  requires reviews** (app id 2748019, `bypass_mode: always`); otherwise Tide
  can never merge. ([ADR 0012] section 2)
- **Red Hat documentation is read for the version that is actually running,
  confirmed from the live system,** never from a cluster or host name, a
  search result or memory: for OpenShift the release image
  (`oc get clusterversion version -o jsonpath='{.status.desired.image}'`) and
  the version (the same with `{.status.desired.version}`), for an operator its
  CSV (`oc get csv -n <namespace>`), for MicroShift `microshift version` on the
  host. Pin the docs to that version and name it when you quote them.

## Guardrails

Two layers stop destructive commands before they run ([ADR 0024] section 4).
Do not try to get around them; if one blocks legitimate work, stop and ask the
maintainer.

1. **Deny rules** in `.claude/settings.json`: `oc delete` of PVCs, PVs and
   Argo CD Applications, `--force --grace-period=0`, `kubectl`, and
   `cargo loco db reset`.
2. **The hook** `.claude/hooks/guard-bash.sh` checks every Bash command,
   including `sh -c` wrappers, other spellings and commands run through
   `oc exec`, `oc rsh` or `oc debug`. It blocks `kubectl`; force deletion
   (`--force` on `oc delete` or `oc replace`, or with `--grace-period=0`);
   `oc delete` of a PVC, PV, Application or ApplicationSet; Loco's `db reset`,
   `db down`, `db truncate` and `db seed --reset` in every form;
   `sea-orm-cli migrate fresh|refresh|reset|down`; and `psql`, `pg_restore`,
   `mysql` and `sea-orm-cli` aimed at a database that is not local
   (localhost, 127.0.0.1, ::1 or a Unix socket) or run inside the cluster. It
   fails closed when `jq` is missing, and its message says what to do instead.

Both layers match command text, and this repository has no code-level guard,
so a destructive cluster change still depends on these rules and on human
review. Neither layer covers:

- commands that come from files or scripts, for example `oc delete -f` or
  `oc apply -k`;
- resource names that another command produces, for example
  `oc delete $(oc get pvc -o name)` or `oc get pvc -o name | xargs oc delete`;
- indirect paths to the same damage: deleting a namespace or project (it
  deletes every PVC in it), `argocd app delete`, an `oc patch` that removes
  finalizers or sets a reclaim policy to `Delete`, and a cluster database
  reached through `oc port-forward`, which then looks local;
- database clients the hook does not list, for example `mariadb`.

The invariants above still apply to all of them.

The hook also blocks a little too much: a database command name anywhere after
`oc exec`, `oc rsh` or `oc debug` counts, the pod or workload name included,
so `oc exec deploy/mysql -- df -h` is blocked although it does not run
`mysql`. Name the pod instead (`oc get pods -l app=mysql -o name`, then
`oc exec pod/mysql-<suffix> -- df -h`).

Claude Code reads `.claude/settings.json` from the directory a session starts
in, so start sessions at the repository root. Personal
`.claude/settings.local.json` files stay untracked (`.gitignore`); they may add
rules but cannot remove the committed deny rules, because deny rules are
checked first.

The hook is adapted from website_backend3's `.claude/hooks/guard-bash.sh`; a
fix to its shell parser or to check 1 belongs in both repositories. Its tests
need bash and jq, and no network or cluster access; CI runs them in the `check`
job of `.github/workflows/ci.yaml`. Run them before you change the hook or the
settings:

```sh
bash scripts/tests/test-guard-bash.sh
```

A change that alters a rule, a command or the layout updates this file in the
same PR.

[ADR 0012]: https://github.com/Verseghy/website_backend3/blob/master/docs/design/adr/0012-delivery-review-commits-and-licensing.md
[ADR 0022]: https://github.com/Verseghy/website_backend3/blob/master/docs/design/adr/0022-builds-and-ci-pac-for-production-images-github-actions-for-p.md
[ADR 0024]: https://github.com/Verseghy/website_backend3/blob/master/docs/design/adr/0024-ai-maintainability-instruction-files-the-loco-skill-guardrai.md
