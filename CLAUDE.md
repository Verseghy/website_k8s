# website_k8s

This repository is the GitOps source of the Verseghy website platform. The
Argo CD instance in the hub's `verseghy` namespace syncs every Application
defined here automatically, and every one except `microshift-infra-eso-operator`
(an upstream Helm chart whose version is pinned in
`microshift-infra/applications/eso.yaml`) takes its manifests from `master`, so
a merge changes running clusters. The rules below win over generic advice; each
one says why it holds.

## Where things run

- **Hub** (Argo CD destination `in-cluster`): OpenShift Container Platform.
  Argo CD, Prow (`verseghy-website/prow/`), the PAC and Shipwright builds
  (`verseghy-website/builds/`), Argo CD Image Updater
  (`verseghy-website/image-updater/`), Red Hat Developer Hub with its
  PostgreSQL (`verseghy-website/rhdh/`) and `verseghy-website/eso-in-cluster/`.
- **Edge** (destination `verseghy-microshift`): MicroShift. The sites
  (`frontend`, `backend`, `backend2`, `backend2-redis`, `mysql`, `static`,
  `eso` under `verseghy-website/`) and `microshift-infra/`.
- `verseghy-website/application.yaml` and `microshift-infra/application.yaml`
  are the roots; they sync the Applications in their `applications/`
  directories. Each Application's `spec.destination` names its cluster.
- `catalog/` holds the Developer Hub catalog entities. Developer Hub reads
  `catalog/all.yaml` from `master` (the `catalog.locations` entry in
  `verseghy-website/rhdh/app-config.yaml`); Argo CD does not sync it.
- `services/`, `microk8s/` and the top-level `config.yaml` are not the source
  of any Application.

## Cluster access

- **Use `oc`, never `kubectl`.** Both clusters are OpenShift distributions, and
  the guardrails below parse `oc` command lines, so the hook blocks `kubectl`
  outright.
- **Never force-delete a pod** (`--force`, `--grace-period=0`). Force deletion
  removes the pod from the API before its containers stop, so a replacement can
  start while the old one still writes to the same ReadWriteOnce volume, such
  as MySQL's (`verseghy-website/mysql/`). Delete the pod normally; if it does
  not terminate, stop and ask the maintainer.
- **Never delete a PersistentVolumeClaim, PersistentVolume, Argo CD Application
  or ApplicationSet.** The PVs bound to the PVCs in the hub's `verseghy`
  namespace have reclaim policy `Delete`, and every Application here carries the
  `resources-finalizer.argocd.argoproj.io` finalizer, so a deletion destroys
  the data or every resource the Application manages (a root takes all of its
  Applications with it). A human does it, after checking that the reclaim
  policy is `Retain` and that a verified backup exists.
- **Change the clusters through a pull request, not with `oc apply`, `edit`,
  `patch` or `scale`.** Auto-sync applies `master` again after the next merge
  and replaces a manual change, which nobody reviewed either. Read-only
  commands (`oc get`, `describe`, `logs`, `diff`, `kustomize`,
  `apply --dry-run=server`) are fine.
- **Removing a manifest does not delete its resource.** Auto-sync runs without
  `prune`, so the resource stays and its Application shows `OutOfSync` until a
  human prunes it.
- **Never run a command that reads or writes the databases this repository
  deploys** (MySQL on the edge, which `backend` and `backend2` use, and
  Developer Hub's PostgreSQL on the hub): no database client, and no
  application command such as `php artisan migrate`, `db:seed` or `db:wipe` in
  the Laravel `backend` pod, neither through `oc exec`, `oc rsh` or `oc debug`
  nor through a remote host. They hold live data, and a human operates them.

## Builds and images

- **Production images are built only by Pipelines-as-Code (PAC) and Shipwright
  on the hub, never by GitHub Actions**, which is for PR checks such as this
  repository's `check`. Each build pins its source to the pushed commit
  (`verseghy-website/builds/README.md`), and the source repository's
  `.tekton/push.yaml` tags the image with that commit's full SHA
  (`ghcr.io/verseghy/<repository>:<SHA>`), so every tag that Image Updater
  promotes names the commit it was built from.
- **A new repository's PAC `Repository` CR
  (`verseghy-website/builds/pac-repository-<name>.yaml`) merges before the
  first push to its `master` that carries `.tekton/push.yaml`.** PAC ignores the
  events of a repository without a CR, so a push that lands first builds no
  image.
- **Image Updater promotes PAC-built images only to full 40-character commit
  SHA tags** (`newest-build` with `allowTags: regexp:^[0-9a-f]{40}$` in
  `verseghy-website/image-updater/imageupdater.yaml`), so a `latest` or short
  tag can never reach the sites. `mysql` and `redis` each follow one semver
  patch line instead.
- **A new app's first image tag is set by hand** in the `images:` entry of its
  `kustomization.yaml` (for a PAC-built image, the full SHA of a commit whose
  build succeeded), and the app gets its entry in `imageupdater.yaml`. Image
  Updater only updates an image that the Application already runs
  (`forceUpdate` is not set and keeps its default, `false`), so it never makes
  the first deployment; afterwards it opens the bump PRs here.
- **`verseghy-website/builds/buildstrategy-buildah-ubi9.yaml` lists its
  differences from the Builds operator's `buildah` ClusterBuildStrategy in its
  header and is diffed against it after every operator upgrade** (the header
  says how). It is a copy that the operator does not reconcile, kept because the
  operator's UBI 10 image needs x86-64-v3 CPUs that the hub lacks, so it does
  not pick up the operator's changes by itself.

## Review and merge

- **Every pull request here waits for a human `lgtm`.** Tide merges a
  website_k8s PR only with both `lgtm` and `approved` (the org-wide query in
  `verseghy-website/prow/configmaps.yaml`), and a merge is deployed at once.
  An agent never applies `lgtm` or `approved` itself, by command or by label,
  and never merges; Image Updater's bump PRs wait for the same review.
- **CI job names are branch-protection contracts.** Required contexts are listed
  by name in the `branch-protection` section of
  `verseghy-website/prow/configmaps.yaml` and in each repository's GitHub
  ruleset, and Tide waits for every one, so a renamed job whose old context is
  still required blocks every merge in that repository. Rename both in the
  same change. Here only `tide` is required today; `check`
  (`.github/workflows/ci.yaml`) is not.
- **The `verseghy-prow` GitHub App (id 2748019) stays a bypass actor
  (`bypass_mode: always`) on every ruleset that requires reviews.** Tide
  merges as that app, and Prow's `lgtm` and `approved` are labels, not GitHub
  reviews, so without the bypass the ruleset refuses every Tide merge (this
  repository's `master` ruleset requires a code-owner review).

## Red Hat documentation

Read the docs for the version that is running, confirmed from the live system,
never from a host name, a search result or memory: Red Hat versions each product
and each minor separately, and a search often lands on another one. The hub's
release image decides its product
(`oc get clusterversion version -o jsonpath='{.status.desired.image}'`): it is
`ocp-release`, so read the OCP docs, although the hub's host names say `okd4`;
`{.status.desired.version}` gives the version. An operator's version is its CSV
(`oc get csv -n <namespace>`), the edge's is `microshift version` on the host.
Pin the docs to that version with the version selector, and name the product
and version when you quote them.

## Guardrails

Two layers stop destructive commands before they run. Do not work around them;
if one blocks legitimate work, stop and ask the maintainer.

1. **Deny rules** in `.claude/settings.json`: `oc delete` of PVCs, PVs and
   Argo CD Applications, `--force --grace-period=0`, and `kubectl`.
2. **The hook** `.claude/hooks/guard-bash.sh` checks every Bash command,
   including `sh -c` wrappers, here-strings, heredocs that a shell reads, other
   spellings and commands run through `oc exec`, `oc rsh` or `oc debug`. It
   blocks `kubectl`; force deletion (`--force` on `oc delete` or `oc replace`,
   or with `--grace-period=0`); `oc delete` of a PVC, PV, Application or
   ApplicationSet; the data-wiping commands of application CLIs in every form:
   Laravel's `artisan migrate:fresh`, `migrate:refresh`, `migrate:reset`,
   `migrate:rollback` and `db:wipe` (also abbreviated, as in `m:fr`) and the
   `db reset`, `db down`, `db truncate` and `db seed --reset` subcommands of
   any program; and `psql`, `pg_restore` and `mysql` aimed at a database that
   is not local (localhost, 127.0.0.1, ::1 or a Unix socket) or run inside a
   cluster. It fails closed when `jq` is missing, and its message says what to
   do instead.

Both layers match command text, and this repository has no code-level guard, so
a destructive cluster change still depends on the rules above and on human
review. Neither layer covers:

- commands that come from files or scripts, for example `oc delete -f` or
  `oc apply -k`;
- resource names that another command produces, for example
  `oc delete $(oc get pvc -o name)` or `oc get pvc -o name | xargs oc delete`;
- a script piped into a shell in a pod
  (`echo 'psql ...' | oc exec -i <pod> -- sh`, `printf 'mysql ...' | oc rsh <pod>`):
  its database clients are checked as local commands;
- indirect paths to the same damage: deleting a namespace or project (it
  deletes every PVC in it), `argocd app delete`, an `oc patch` that removes
  finalizers or sets a reclaim policy to `Delete`, and a cluster database
  reached through `oc port-forward`, which then looks local;
- database clients the hook does not list, for example `mariadb` or
  `redis-cli`;
- application commands that write to a database without wiping it, for
  example `oc exec deploy/backend -- php artisan migrate`, `db:seed` or
  `tinker`.

The rules above still apply to all of them.

The hook also blocks a little too much, which fails safe:

- a database client name anywhere after `oc exec`, `oc rsh` or `oc debug`
  counts, the pod or workload name included, so `oc exec deploy/mysql -- df -h`
  is blocked although it does not run `mysql`. Name the pod instead
  (`oc get pods -l app=mysql -o name`, then
  `oc exec pod/mysql-<suffix> -- df -h`);
- every word after `artisan` that is not an option counts as its command name,
  so `php artisan help migrate:fresh` is blocked too.

Claude Code reads `.claude/settings.json` from the directory a session starts
in, so start sessions at the repository root. Personal
`.claude/settings.local.json` files stay untracked (`.gitignore`); they may add
rules but cannot remove the committed deny rules, because deny rules are
checked first.

The hook's tests need bash and jq, and no network or cluster access; CI runs
them in the `check` job of `.github/workflows/ci.yaml`. Run them before you
change the hook or the settings:

```sh
bash scripts/tests/test-guard-bash.sh
```

A change that alters a rule, a command or the layout updates this file in the
same PR.
