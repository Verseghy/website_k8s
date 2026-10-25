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
  (`frontend`, `backend`, `backend2`, `backend2-redis`, `mysql`, `postgres`,
  `static`, `eso` under `verseghy-website/`) and `microshift-infra/`.
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
  deploys** (MySQL on the edge, which `backend` and `backend2` use,
  backend3's PostgreSQL on the edge, and Developer Hub's PostgreSQL on the
  hub): no database client, and no
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
  patch line instead, and `postgres` the minor releases of PostgreSQL 18.
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

1. **Deny rules** in `.claude/settings.json`: `oc delete` of PVCs, PVs, Argo CD
   Applications, namespaces and projects; `argocd app delete`,
   `argocd app delete-resource`, `argocd app confirm-deletion` and
   `argocd appset delete`; `oc patch` and `argocd app patch-resource` of
   finalizers or to a `Delete` or `Recycle` reclaim policy; Argo CD's
   `deletion-approved` annotation in an `argocd`, `oc patch` or
   `oc annotate` command; `--force --grace-period=0`; and `kubectl`. A Redis
   client in a cluster has no deny rule, as the database clients have none;
   the hook checks it.
2. **The hook** `.claude/hooks/guard-bash.sh` checks every Bash command,
   including `sh -c` wrappers, here-strings, heredocs and piped `echo` or
   `printf` scripts that a shell reads, `echo` or `printf` output that the
   shell runs from a substitution (`bash <(echo ...)`, `eval "$(echo ...)"`,
   `"$(echo oc)" delete ...`), text that `xargs` or `parallel` pass on as
   arguments (`echo confirm-deletion <app> | xargs argocd app`), other
   spellings (`$'...'` quoting included), options before the `oc` verb
   (`oc --wait ns delete web` runs `oc delete ns web`) and commands run
   through `oc exec`, `oc rsh` or `oc debug`. It blocks `kubectl`; force
   deletion (`--force` on `oc delete` or `oc replace`, or with
   `--grace-period=0`); `oc delete` of a PVC, PV, Application, ApplicationSet,
   namespace or project, also when its arguments come from an `oc get` of one
   through `$(...)`, `xargs` or `-f -`, and every `oc delete --raw`;
   `argocd app delete`, `argocd app delete-resource`,
   `argocd app confirm-deletion` (which approves the deletions that a
   `Prune=confirm` or `Delete=confirm` sync option holds back) and
   `argocd appset delete`, also under argocd's download names
   (`argocd-linux-amd64`); an `oc patch` or `argocd app patch-resource` that
   changes finalizers or sets a reclaim policy to `Delete` or `Recycle`, also
   through JSON or YAML escapes (`f\u0069nalizers`), or that replaces or
   removes a whole object or its metadata, or that holds a YAML binary tag
   (`!!binary`), a tag with a `%` escape or a `%TAG` directive, behind which
   kubectl decodes text that the hook does not read (setting `Retain` is not
   blocked);
   an `oc annotate`, `oc patch` or `argocd` command that names Argo CD's
   `argocd.argoproj.io/deletion-approved` annotation, which approves the
   same held-back deletions; the data-wiping commands of application
   CLIs in every form: Laravel's `artisan migrate:fresh`, `migrate:refresh`,
   `migrate:reset`, `migrate:rollback` and `db:wipe` (also abbreviated, as in
   `m:fr`) and the `db reset`, `db down`, `db truncate` and `db seed --reset`
   subcommands of any program; `sea-orm-cli migrate fresh`,
   `migrate refresh`, `migrate reset` and `migrate down` against any
   database, a local one included, because a database that answers on
   localhost here may be a cluster's one behind a port-forward or an ssh
   tunnel, also under sea-orm-cli's other program name `sea`
   (`sea migrate fresh`; the package installs both names) and with grouped
   short options (`sea-orm-cli migrate -vu <URL> fresh`), while read-only
   commands such as `sea-orm-cli migrate status` stay allowed against a local
   database; `oc port-forward` to a PostgreSQL,
   MySQL, MariaDB or Redis port, because the forwarded database then answers
   on localhost; and `psql`, `pg_restore`, `mysql`, `mariadb` and
   `sea-orm-cli` (or `sea`) aimed at a database that is not local (localhost,
   127.0.0.1, ::1 or a Unix socket), or run inside a cluster (in the command
   part of `oc exec`, `oc rsh` or `oc debug`, or in a script piped or fed to
   them); and `redis-cli` and `redis-benchmark` (which runs any command it is
   given) run inside a cluster the same way, whatever their command
   (`redis-cli ping` too). A Redis client on this host is not checked: the
   clusters' Redis answers here only through a port-forward, which is
   blocked. Its message says what to do instead.

   For a client run inside a cluster, the Redis clients included, the hook
   reads only the command that runs in the pod: the words after `--` for
   `oc exec` and `oc debug`, and for `oc rsh` the words after the pod and the
   program its `--shell` names.
   A pod, container or namespace whose name looks like a client does not
   count, and neither does a data path, so
   `oc exec -n verseghy deploy/mysql -- df -h` and
   `oc rsh deploy/mysql ls -l /var/lib/mysql` are allowed, while
   `oc exec postgres-0 -- sh -c 'cd /tmp;psql'` is blocked.

Two standing rules come with these checks, next to the ones under "Cluster
access": **never approve a deletion that Argo CD holds back**, in any way
(`argocd app confirm-deletion`, or the `deletion-approved` annotation set by
a command, a patch or a manifest), and **never run a Redis client against
the clusters' Redis** (`redis-backend2` on the edge). A human approves a
held deletion, after checking what Argo CD would then delete and that a
verified backup exists. Both rules hold where the hook does not look.

The hook fails closed: it blocks the command when `jq` is missing, when it
cannot read its input and on any error of its own, and `"onFailure": "block"`
on its entry in `.claude/settings.json` blocks the command when the hook cannot
start, crashes or times out. That field needs Claude Code v2.1.295 or later;
an older client ignores it, and then such a failure lets the command run. The
entry runs the hook in exec form (`"args": []`, no shell), so a project path
with spaces needs no quoting. A client older than v2.1.139 ignores `"args"`
and runs the entry in shell form, where a project path with a blank does not
start the hook at all, so the command runs unchecked.

Both layers match command text, and this repository has no code-level guard, so
a destructive cluster change still depends on the rules above and on human
review. Neither layer covers:

- commands that come from files or scripts, for example `oc delete -f`,
  `oc apply -k`, `oc patch --patch-file` or `oc exec -i <pod> -- sh < script.sh`;
- resource names that another command produces when the command line runs no
  `oc get` of a protected kind, for example `oc delete $(cat names.txt)`, and
  text that only a shell run computes: a variable's value
  (`P=psql; oc exec <pod> -- $P`), `printf` formats, `echo -e` escapes,
  brace expansion (`deletion-appro{v,}ed`), globs or decoded output
  (`base64 -d`), and a substitution that fills in only part of the command
  name (`o$(echo c) delete ...`) or a double-quoted one with double quotes
  inside (`"$(echo "oc")" delete ...`);
- a heredoc that `xargs` or `parallel` read (`xargs oc <<'EOF'`), a
  here-string that `cat` passes on through a pipe
  (`cat <<< '...' | xargs oc`, `cat <<< '...' | oc exec -i <pod> -- sh`), and
  a `db` subcommand that `xargs` or `parallel` pass to a program the hook
  does not list (`echo reset | xargs app-cli db`);
- a Redis client in a pod that the agent starts
  (`oc run ... -- redis-cli -h <service>`, `oc create job`), Redis clients
  other than `redis-cli` and `redis-benchmark` (`valkey-cli`, `keydb-cli`),
  and other database clients and tools the hook does not list, in any pod, the
  MySQL and PostgreSQL ones included
  (`oc exec deploy/mysql -- mysqladmin -u root -f drop <database>`,
  `oc exec deploy/postgres -- dropdb <database>`), and a database served on a
  port that the port-forward check does not know;
- the other ways to drop finalizers or replace an object: `oc replace`,
  `oc apply` and `oc edit` (for example
  `oc get pvc data -o json | jq 'del(.metadata.finalizers)' | oc replace -f -`),
  `oc replace --raw`, and `argocd app patch` of an Application's own
  finalizers;
- Argo CD's `deletion-approved` annotation in a manifest that `oc apply`,
  `oc create` or `oc replace` reads, from a file or inline as a heredoc or
  piped text, or that an editor writes (`oc edit`, `argocd app edit`);
- `argocd app sync --prune` or `argocd app set --auto-prune`, which delete
  what the manifests no longer hold;
- an ssh tunnel to a database (`ssh -L 15432:<db>:5432 <host>`), which makes
  it answer on localhost as a port-forward does;
- file commands in a pod, for example
  `oc exec <pod> -- rm -rf /var/lib/postgresql/data` or
  `oc exec deploy/mysql -- rm -rf /var/lib/mysql`;
- commands that an interpreter runs (`python3 -c 'import os; os.system(...)'`)
  and output redirected into a process substitution (`echo '...' > >(bash)`);
- application commands that write to a database without wiping it, for
  example `oc exec deploy/backend -- php artisan migrate`, `db:seed` or
  `tinker`.

The rules above still apply to all of them.

The hook also blocks a little too much, which fails safe:

- every `oc patch` or `argocd app patch-resource` that names finalizers is
  blocked, additions included, because the hook cannot tell every removal
  from an addition; adding a finalizer is a task for a human. So is every
  strategic merge `$patch: replace`, `$patch: delete` or `$retainKeys` in
  such a patch, wherever in the patch it stands; every `path` set to `""`,
  `/metadata`, a YAML block scalar, an alias or a tag whose value starts on
  the next line; every YAML alias used as a key (`*k: ...`), and text in a
  value that looks like one; every YAML binary tag (`!!binary`), tag with a
  `%` escape and `%TAG` directive, whatever its text decodes to; an escape
  behind an escaped backslash
  (`\\u0066inalizers`, which the hook reads as finalizers); and every
  `oc delete --raw`;
- any word that names `deletion-approved` in an `oc annotate`, an `oc patch`
  or any `argocd` command is blocked, also in a command that only prints the
  key (`argocd app list --selector deletion-approved=yes`) or in which
  `argocd` is only an argument (`grep -rn argocd docs/deletion-approved.md`),
  and any name that starts with `argocd-`, `argocd_` or `argocd.` counts as
  argocd there. Read the annotation with `oc get` or `oc describe`, or pipe
  `argocd app get <app> -o json` to `jq` or `grep`;
- `argocd app delete-resource` is blocked for every kind, because the hook
  cannot tell a PVC from a pod there; delete a pod with `oc delete pod`;
- the port-forward check knows databases by their ports: a port-forward to
  5432, 3306, 33060, 6379 or 26379, or to a named port that contains
  `postgres`, `mariadb`, `sql`, `redis` or `sentinel` or is `db`, is blocked,
  whatever the service is, while the pod or service name does not count
  (`oc port-forward -n verseghy svc/postgres 19187:metrics` is allowed);
- an option that the hook does not know, right before an `argocd app` or
  `argocd appset` subcommand, may take the next word as its value, so the
  positional word after that one counts as the subcommand too:
  `argocd app --new-option get delete` is blocked for an Application named
  `delete`. An `oc` verb is read the same way: an option before it that the
  hook does not know may take the next word, so
  `oc --new-option get delete pvc` is blocked, although oc refuses it;
- text that `oc exec`, `oc rsh` or `oc debug` reads on stdin counts as a
  script that runs in the cluster, even when the program in the pod is not a
  shell, and `echo` or `printf` output in a process substitution counts as a
  script whenever a shell gets it, also as an argument of a script
  (`bash run.sh <(echo ...)`);
- a word counts as a command in more places than a shell runs it: the word
  after any `-c` option is read as a command line, so
  `grep -c kubectl CLAUDE.md` is blocked (use the Grep tool); an `oc` word
  anywhere in a command counts (`echo oc delete ns web`); a substitution
  after a runner word counts as the command name, also after the runner's
  own options (`sudo -u root $(echo oc) delete ...`); and in the command
  part of `oc exec`, `oc rsh` or `oc debug`, a client's path in a bin
  directory counts (`ls /usr/lib/postgresql/18/bin/psql`);
- a PR body or comment that quotes a whole in-cluster command
  (`gh pr comment <n> --body 'oc exec deploy/redis-backend2 -- redis-cli FLUSHALL'`)
  is blocked, as the command itself is; pass such text with `--body-file`
  (`gh pr create --body-file <file>`, `git commit -F <file>`);
- every word after `artisan` that is not an option counts as its command name,
  so `php artisan help migrate:fresh` is blocked too, and a sea-orm-cli wipe
  subcommand counts whatever options follow it, so
  `sea-orm-cli migrate fresh --help` is blocked
  (`sea-orm-cli migrate help fresh` is not).

Claude Code reads `.claude/settings.json` from the directory a session starts
in, so start sessions at the repository root. Personal
`.claude/settings.local.json` files stay untracked (`.gitignore`); they may add
rules but cannot remove the committed deny rules, because deny rules are
checked first.

The hook's tests need bash and jq, and no network or cluster access; CI runs
them in the `check` job of `.github/workflows/ci.yaml`. When the oc 4.22
client is on PATH, one case also compares the hook's list of oc options that
take a value with that client's help (offline). Run them before you change
the hook or the settings:

```sh
bash scripts/tests/test-guard-bash.sh
```

A change that alters a rule, a command or the layout updates this file in the
same PR.
