#!/usr/bin/env bash
# test-guard-bash.sh: tests for .claude/hooks/guard-bash.sh, the PreToolUse
# hook of the guardrails (layer 2), and for the committed
# .claude/settings.json that holds the deny rules and wires the hook up
# (layer 1). CLAUDE.md, "Guardrails", describes both layers.
#
# Why it exists
#   The hook runs before every Bash command an agent runs in this repository.
#   A bug in it either lets a destructive command through or blocks legitimate
#   work, so every rule is pinned here: the deny rules and the hook wiring in
#   .claude/settings.json, and that the hook blocks a sample of every deny
#   rule; that personal settings stay untracked; each check 1 command, also in
#   its oc exec, oc rsh and oc debug forms; each check 2 target source (inline
#   variables, -h, -d URIs, host= strings, positional URIs, the environment,
#   plus PGHOSTADDR and PGSERVICE); a command with no target; wrapped forms
#   (sh -c, also with `--` and other options, here-strings, scripts piped into
#   a shell, heredocs, also those that oc exec, oc rsh or oc debug run in the
#   cluster); allowed commands; a missing jq; and the cost of long commands.
#
# Origin
#   Adapted, with its fixtures and .claude/settings.json, from
#   Verseghy/website_backend3's scripts/tests/test-guard-bash.sh (commit
#   4e7fb76). Licence: that repository is AGPL-3.0-only; the original's only
#   human author is a maintainer of both repositories and, by merging the
#   adaptation here (#54), licensed it under this repository's MPL-2.0
#   (LICENSE).
#
# How it works
#   Each case builds a PreToolUse payload with jq (the shape Claude Code sends,
#   see scripts/tests/fixtures/guard-bash/), pipes it into the hook with a
#   controlled environment and asserts the exit code: 0 allows, 2 blocks. For
#   blocked commands it also asserts that stderr carries the hook's reason.
#   It prints one TAP-style "ok N" or "not ok N" line per case.
#
# Usage
#   bash scripts/tests/test-guard-bash.sh     (from the repository root)
#   It needs bash and jq, and no network or cluster access. It exits non-zero
#   if any case fails. CI runs it in the "check" job (.github/workflows/ci.yaml).

# The cases are literal command text for the hook to inspect, so $(...),
# backticks and "$VAR" inside single quotes must stay unexpanded. (Placed
# before the first command, the directive covers the whole file.)
# shellcheck disable=SC2016

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
hook="$repo_root/.claude/hooks/guard-bash.sh"
fixtures="$repo_root/scripts/tests/fixtures/guard-bash"

if ! command -v jq >/dev/null 2>&1; then
  echo "test-guard-bash.sh: jq is required to build the test payloads; install jq and retry." >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

passed=0
failed=0

# Records one result and prints one TAP-style line.
#   $1 - "ok" or "fail";
#   $2 - the case description (newlines are shown as \n);
#   $3 - details printed for a failure.
report() {
  local n=$((passed + failed + 1)) desc="${2//$'\n'/\\n}"
  if [[ "$1" == ok ]]; then
    passed=$((passed + 1))
    printf 'ok %d - %s\n' "$n" "${desc:0:160}"
  else
    failed=$((failed + 1))
    printf 'not ok %d - %s\n%s\n' "$n" "${desc:0:160}" "$3" | sed '2,$s/^/    # /'
  fi
}

# Builds the PreToolUse payload for one Bash command. The command goes in on
# stdin, not as an argument, because one argument is limited to 128 KiB.
#   $1 - the command text.
payload_for() {
  printf '%s' "$1" | jq -Rs '. as $c | {
    session_id: "00000000-0000-0000-0000-000000000000",
    transcript_path: "transcript.jsonl",
    cwd: ".",
    permission_mode: "default",
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_input: {command: $c, description: "test", timeout: 120000, run_in_background: false},
    tool_use_id: "toolu_test"
  }'
}

# Runs the hook on a payload file with a clean database environment: every
# variable that check 2 reads from the environment is unset first, so a value
# in the caller's shell cannot change a verdict.
#   $1    - the payload file;
#   $2... - extra VAR=value assignments for the hook's environment.
# Sets: status (the exit code) and the files "$work/out" and "$work/err".
run_hook_file() {
  local file="$1"
  shift
  set +e
  env -u DATABASE_URL -u PGHOST -u PGHOSTADDR -u PGSERVICE -u MYSQL_HOST "$@" \
    "$hook" <"$file" >"$work/out" 2>"$work/err"
  status=$?
  set -e
}

# Asserts the hook's verdict for one command.
#   $1    - the expected exit code (0 allow, 2 block);
#   $2    - the command text;
#   $3... - extra VAR=value assignments for the hook's environment.
expect() {
  local expected="$1" cmd="$2"
  shift 2
  local label="$cmd"
  (($# > 0)) && label="[$*] $cmd"
  payload_for "$cmd" >"$work/payload.json"
  run_hook_file "$work/payload.json" "$@"
  if [[ "$status" != "$expected" ]]; then
    report fail "exit $expected for: $label" "  got exit $status; stderr: $(cat "$work/err")"
  elif [[ "$expected" == 2 ]] && ! grep -q '^Blocked by .claude/hooks/guard-bash.sh' "$work/err"; then
    report fail "reason on stderr for: $label" "  stderr was: $(cat "$work/err")"
  elif [[ "$expected" == 0 ]] && [[ -s "$work/err" || -s "$work/out" ]]; then
    report fail "silent allow for: $label" "  stdout: $(cat "$work/out"); stderr: $(cat "$work/err")"
  else
    report ok "$label" ""
  fi
}

# Shorthands for expect.
#   $1    - the command text;
#   $2... - extra VAR=value assignments for the hook's environment.
blocks() { expect 2 "$@"; }
allows() { expect 0 "$@"; }

# Asserts that a blocked command's reason contains a text.
#   $1 - the command text;
#   $2 - a fixed string the reason must contain.
reason_mentions() {
  payload_for "$1" >"$work/payload.json"
  run_hook_file "$work/payload.json"
  if [[ "$status" == 2 ]] && grep -qF -- "$2" "$work/err"; then
    report ok "reason for '$1' mentions '$2'" ""
  else
    report fail "reason for '$1' mentions '$2'" "  exit $status; stderr: $(cat "$work/err")"
  fi
}

remote_pg="postgres://app:app@db.example.org:5432/website"
local_pg="postgres://app:app@localhost:5432/website_test"
remote_mysql="mysql://root@legacy.example.org:3306/legacy"
local_mysql="mysql://root@127.0.0.1:3306/legacy"

# ------------------------------------------------------------- the file itself

if [[ -x "$hook" ]]; then
  report ok "the hook is executable" ""
else
  report fail "the hook is executable" "  chmod +x .claude/hooks/guard-bash.sh"
fi

# ------------------------------------------------------------- the wiring in .claude/settings.json

settings="$repo_root/.claude/settings.json"
# The committed settings must equal this block, so that dropping a deny rule
# or unwiring the hook is a deliberate edit to both files, which a reviewer
# sees, and never a silent one. CLAUDE.md, "Guardrails", lists the same rules.
expected_settings="$(
  cat <<'JSON'
{
  "permissions": {
    "deny": [
      "Bash(oc delete pvc *)",
      "Bash(oc delete pvc/*)",
      "Bash(oc delete persistentvolumeclaim *)",
      "Bash(oc delete pv *)",
      "Bash(oc delete pv/*)",
      "Bash(oc delete persistentvolume *)",
      "Bash(oc delete application *)",
      "Bash(oc delete applications *)",
      "Bash(oc delete applications.argoproj.io *)",
      "Bash(* --force --grace-period=0*)",
      "Bash(* --grace-period=0 --force*)",
      "Bash(kubectl *)"
    ]
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/guard-bash.sh" }
        ]
      }
    ]
  }
}
JSON
)"
if [[ "$(jq -S . <<<"$expected_settings")" == "$(jq -S . "$settings")" ]]; then
  report ok ".claude/settings.json holds the expected deny rules and hook wiring" ""
else
  report fail ".claude/settings.json holds the expected deny rules and hook wiring" \
    "  diff: $(diff <(jq -S . <<<"$expected_settings" 2>&1) <(jq -S . "$settings" 2>&1) || true)"
fi
# Layer 2 covers layer 1: the hook blocks a sample command for every deny
# rule, so the wrapped and reordered forms of that command, which the rule
# itself misses, are guarded too. A new deny rule without a matching hook
# check fails here. The sample replaces a leading `* ` with a pod deletion,
# and a trailing ` *`, `/*` or `*` with a name.
while IFS= read -r rule; do
  sample="$(sed -e 's/^Bash(//' -e 's/)$//' -e 's/^\* /oc delete pod web-0 /' \
    -e 's/ \*$/ data/' -e 's|/\*$|/data|' -e 's/\*$//' <<<"$rule")"
  payload_for "$sample" >"$work/payload.json"
  run_hook_file "$work/payload.json"
  if [[ "$status" == 2 ]]; then
    report ok "the hook also blocks deny rule $rule ($sample)" ""
  else
    report fail "the hook also blocks deny rule $rule ($sample)" "  exit $status; stderr: $(cat "$work/err")"
  fi
done < <(jq -r '.permissions.deny[]' "$settings")
# Claude Code runs a shell-form hook command with `sh -c` and exports
# CLAUDE_PROJECT_DIR (Claude Code docs, "Hooks reference"); do the same.
hook_command="$(jq -r '.hooks.PreToolUse[] | select(.matcher == "Bash") | .hooks[0].command' "$settings")"
set +e
CLAUDE_PROJECT_DIR="$repo_root" sh -c "$hook_command" <"$fixtures/pretooluse-bash-kubectl.json" >/dev/null 2>&1
wired_block=$?
CLAUDE_PROJECT_DIR="$repo_root" sh -c "$hook_command" <"$fixtures/pretooluse-bash-allowed.json" >/dev/null 2>&1
wired_allow=$?
set -e
if [[ "$wired_block" == 2 && "$wired_allow" == 0 ]]; then
  report ok "the hook command in settings.json runs the hook under sh -c" ""
else
  report fail "the hook command in settings.json runs the hook under sh -c" \
    "  command: $hook_command; exits: $wired_block (want 2) and $wired_allow (want 0)"
fi

# Personal settings stay untracked: the repository's own .gitignore must
# ignore .claude/settings.local.json, also for contributors without a global
# excludes file, so the global one is switched off here.
# --no-index reports the ignore rule even if the file were tracked.
if git -C "$repo_root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  if git -C "$repo_root" -c core.excludesFile=/dev/null check-ignore -q --no-index .claude/settings.local.json; then
    report ok ".gitignore ignores .claude/settings.local.json" ""
  else
    report fail ".gitignore ignores .claude/settings.local.json" \
      "  add '/.claude/settings.local.json' to .gitignore"
  fi
else
  report ok ".gitignore ignores .claude/settings.local.json # SKIP not a git work tree" ""
fi

# ------------------------------------------------------------- hook input

# Asserts the exit code of the last run_hook_file.
#   $1 - the case name; $2 - the expected exit code.
expect_status() {
  if [[ "$status" == "$2" ]]; then
    report ok "$1" ""
  else
    report fail "$1" "  exit $status, expected $2; stderr: $(cat "$work/err")"
  fi
}

run_hook_file "$fixtures/pretooluse-bash-kubectl.json"
expect_status "full payload fixture with kubectl is blocked" 2
run_hook_file "$fixtures/pretooluse-bash-allowed.json"
expect_status "full payload fixture with oc get is allowed" 0
run_hook_file "$fixtures/pretooluse-write-tool.json"
expect_status "a payload for another tool is allowed" 0
run_hook_file "$fixtures/pretooluse-bash-no-command.json"
expect_status "a Bash payload without a command is allowed" 0
run_hook_file "$fixtures/invalid-json.txt"
if [[ "$status" == 2 ]] && grep -q 'could not read the hook input as JSON' "$work/err"; then
  report ok "invalid JSON input fails closed" ""
else
  report fail "invalid JSON input fails closed" "  exit $status; $(cat "$work/err")"
fi
: >"$work/empty"
run_hook_file "$work/empty"
expect_status "empty input fails closed" 2

# Missing jq: a PATH that holds bash (for the #!/usr/bin/env bash line) and
# nothing else, so `command -v jq` fails inside the hook.
mkdir -p "$work/nojq-bin"
ln -s "$(command -v bash)" "$work/nojq-bin/bash"
set +e
PATH="$work/nojq-bin" "$hook" <"$fixtures/pretooluse-bash-allowed.json" >"$work/out" 2>"$work/err"
status=$?
set -e
if [[ "$status" == 2 ]] && grep -q 'jq is not installed or not on PATH' "$work/err"; then
  report ok "a missing jq fails closed with an actionable reason" ""
else
  report fail "a missing jq fails closed with an actionable reason" "  exit $status; $(cat "$work/err")"
fi

# ------------------------------------------------------------- allowed commands

# The everyday commands of this repository.
allows 'git status'
allows 'ls -la'
allows 'oc get pods -n web'
allows 'oc get applications -n openshift-gitops'
allows 'oc describe pvc data -n web'
allows 'oc logs deploy/backend2 -n web'
allows 'oc kustomize verseghy-website/backend'
allows 'oc diff -f verseghy-website/backend/deployment.yaml'
allows 'oc apply --dry-run=server -f verseghy-website/builds/buildstrategy-buildah-ubi9.yaml'
allows "yq '.images' verseghy-website/backend/kustomization.yaml"
allows 'jq -S . .claude/settings.json'
allows 'bash scripts/tests/test-guard-bash.sh'
allows "echo 'hello world' | wc -c"

# ------------------------------------------------------------- block reasons

# Every reason points at the guardrails section of this repository's CLAUDE.md,
# and says what to do instead.
reason_mentions 'kubectl get pods' 'CLAUDE.md, section "Guardrails"'
reason_mentions 'oc delete pvc data' 'do not work around a block'
reason_mentions 'oc delete pvc data' 'Stop and ask the maintainer'

# ------------------------------------------------------------- check 1: kubectl

blocks 'kubectl get pods'
blocks '/usr/local/bin/kubectl get pods'
blocks 'KUBECONFIG=kubeconfig kubectl get ns'
blocks 'sudo kubectl get pods'
blocks 'xargs -n1 kubectl delete pod'
blocks 'timeout 30 kubectl get pods'
blocks 'echo start && kubectl apply -f deploy.yaml'
blocks "sh -c 'kubectl delete pod web-0'"
blocks 'bash -lc "kubectl get pods"'
blocks 'echo "$(kubectl version)"'
blocks 'echo `kubectl version`'
blocks "ku''bectl get pods"
blocks 'oc exec web-0 -- kubectl get pods'
blocks "watch 'kubectl get pods'"
blocks 'for p in a b; do kubectl delete pod "$p"; done'
allows 'grep -rn kubectl verseghy-website'
allows "grep -rn 'kubectl get' verseghy-website"
allows "git commit -m 'repo: say use oc, never kubectl'"
allows 'oc get pods'
reason_mentions 'kubectl get pods' 'run with oc, never kubectl'

# ------------------------------------------------------------- check 1: force delete

blocks 'oc delete pod web-0 --force --grace-period=0'
blocks 'oc delete pod web-0 --grace-period=0 --force'
blocks 'oc delete pod web-0 --grace-period 0 --force'
blocks "sh -c 'oc delete pod web-0 --force --grace-period=0'"
allows 'oc delete pod web-0'
blocks 'oc delete pod web-0 --force'
allows 'oc delete pod web-0 --grace-period=30'
allows 'git push --force-with-lease'
# kubectl turns --force without a grace period into --grace-period=0
# (k8s.io/kubectl pkg/cmd/delete), and pflag reads bool values with
# strconv.ParseBool, so every true spelling counts.
blocks 'oc delete pod web-0 --force --grace-period=-1'
blocks 'oc -n web delete pod web-0 --force'
blocks 'oc delete --force pod/web-0'
for spelling in 1 t T TRUE true True; do
  blocks "oc delete pod web-0 --force=$spelling --grace-period=0"
  blocks "oc delete pod web-0 --force=$spelling"
done
blocks 'oc replace --force -f pod.yaml'
blocks "sh -c -- 'oc delete pod web-0 --force'"
allows 'oc delete pod web-0 --force=false'
allows 'oc delete pod web-0 --force=0'
allows 'git push --force'
allows 'podman rm --force web'
allows 'oc adm drain edge --force --grace-period=30'
reason_mentions 'oc delete pod web-0 --force --grace-period=0' 'Force-deleting pods is never allowed'

# ------------------------------------------------------------- check 1: oc delete of PVC, PV, Application

blocks 'oc delete pvc data-postgres-0'
blocks 'oc delete pvc/data-postgres-0'
blocks 'oc delete pvcs --all -n web'
blocks 'oc delete persistentvolumeclaim data'
blocks 'oc delete PersistentVolumeClaims data'
blocks 'oc delete persistentvolumeclaim.v1/data'
blocks 'oc -n web delete pv pv-1'
blocks 'oc delete pv/pv-1'
blocks 'oc delete persistentvolume pv-1'
blocks 'oc delete persistentvolumes pv-1'
blocks 'oc delete application verseghy-website-mysql -n verseghy'
blocks 'oc delete applications verseghy-website-frontend'
blocks 'oc delete applications.argoproj.io verseghy-website-static'
blocks 'oc delete app verseghy-website'
blocks 'oc delete applicationset website'
blocks 'oc delete appset website'
blocks 'oc delete appsets --all -n verseghy'
blocks 'oc delete applicationsets.argoproj.io website'
blocks 'oc delete applicationset/website -n verseghy'
blocks 'oc delete pods,pvc --all'
blocks 'oc delete --wait=false -n web pvc data'
blocks "bash -c 'oc delete pvc data'"
blocks 'oc exec toolbox -- oc delete pvc data'
allows 'oc delete pod web-0'
allows 'oc get pvc'
allows 'oc describe pvc data'
allows 'oc delete deployment.apps/web'
allows 'oc delete pod pv-builder'
allows 'oc delete pod web -n apps'
allows 'oc delete configmap application-config'
blocks 'oc delete pod/web-0 pvc/data'
blocks 'oc delete pods/web-0,pvc/data'
blocks 'oc --cache-dir .kube-cache delete pvc data'
blocks 'oc --profile cpu delete pvc data'
blocks 'oc --log-flush-frequency 5s delete pvc data'
blocks 'oc --as-user-extra k=v --kuberc kuberc.yaml delete pv pv-1'
allows 'oc delete deployment app -n verseghy'
allows 'oc delete deployment pvc'
allows 'oc delete configmap app pv pvc'
reason_mentions 'oc delete pvc data' 'reclaim policy is Retain'
reason_mentions 'oc delete app verseghy-website' 'change the manifests under verseghy-website/ or microshift-infra/'

# ------------------------------------------------------------- check 1: data-wiping db subcommands

# Every data-wiping subcommand in every form: run directly, in the cluster
# through oc exec, oc rsh or oc debug (where it would wipe a database this
# repository deploys), and behind the wrappers the parser unwraps. `app-cli`
# stands for any application CLI that has these subcommands.
db_subcommands=('db reset' 'db down' 'db down 2' 'db truncate' 'db seed --reset' 'db seed -r' 'db seed --from src/fixtures -r')
db_forms=(
  'app-cli %s'
  './bin/app-cli %s'
  'APP_ENV=production /app/app-cli %s'
  'app-cli -e production %s'
  'oc exec deploy/web -- app-cli %s'
  'oc exec -it web-0 -c web -- /app/app-cli %s'
  'oc rsh web-0 /app/app-cli %s'
  'oc rsh -n verseghy web-0 app-cli %s'
  'oc debug deploy/web -- /app/app-cli %s'
  "sh -c 'app-cli %s'"
  'bash -lc "app-cli %s"'
  'echo go && app-cli %s'
  "oc exec deploy/web -- sh -c 'app-cli %s'"
  "sh -c -- 'app-cli %s'"
  "bash <<< 'app-cli %s'"
  "echo 'app-cli %s' | sh"
  "oc exec -i deploy/web -- sh <<< 'app-cli %s'"
  "echo 'app-cli %s' | oc exec -i web-0 -- sh"
  $'oc rsh web-0 <<\'EOF\'\napp-cli %s\nEOF'
)
for sub in "${db_subcommands[@]}"; do
  for form in "${db_forms[@]}"; do
    # shellcheck disable=SC2059 # the form is the format string by design
    blocks "$(printf "$form" "$sub")"
  done
done
blocks 'app-cli db --environment development reset'
blocks 'app-cli db -e test truncate'
blocks 'echo "$(app-cli db reset)"'
blocks "eval 'app-cli db reset'"
blocks "ssh bastion 'app-cli db truncate'"
blocks 'timeout 60 app-cli db reset'
blocks $'bash <<\'EOF\'\napp-cli db reset\nEOF'
blocks $'cat <<\'EOF\' | sh\napp-cli db reset\nEOF'
blocks $'cat <<EOF\n$(app-cli db reset)\nEOF'
# Only the data-wiping subcommands are matched.
allows 'app-cli db migrate'
allows 'app-cli db status'
allows 'app-cli db seed'
allows 'app-cli db seed --dump'
allows 'app-cli db create'
allows "git commit -m 'repo: block db reset in every form'"
allows "grep -rn 'db reset' ."
allows $'git commit -F - <<\'EOF\'\nrepo: block db reset\n\nkubectl is banned; oc delete pvc too.\nEOF'
allows $'git commit -m "$(cat <<\'EOF\'\nci: mention app-cli db reset\n\nEOF\n)"'
allows $'cat > notes.md <<\'EOF\'\n- `kubectl get pods`\n- app-cli db reset\nEOF'
reason_mentions 'app-cli db reset' 'Agents never run them from website_k8s'
reason_mentions 'app-cli db truncate' 'db truncate'
reason_mentions 'app-cli db seed --reset' 'db seed --reset'

# ------------------------------------------------------------- check 1: data-wiping artisan commands

# Laravel's data-wiping artisan commands, in full, abbreviated (Symfony's
# console runs any unambiguous abbreviation, in any case) and with options
# before or after the name, in every form. The backend Deployment
# (verseghy-website/backend/, container `app`) is the Laravel app here.
artisan_commands=('migrate:fresh' 'migrate:fresh --seed --force' 'migrate:refresh' 'migrate:reset'
  'migrate:rollback --step=1' 'db:wipe --force' 'm:fr' ':wipe' 'MIGRATE:Reset' 'mig:roll')
artisan_forms=(
  'php artisan %s'
  './artisan %s'
  'php /opt/app-root/src/artisan %s'
  'php -d memory_limit=-1 artisan --env=production %s'
  'php artisan --env production %s'
  'oc exec deploy/backend -- php artisan %s'
  'oc exec -n verseghy deploy/backend -c app -- php artisan %s'
  'oc rsh deploy/backend php artisan %s'
  'oc debug deploy/backend -- php artisan %s'
  "sh -c 'php artisan %s'"
  "oc exec deploy/backend -- sh -c 'cd /opt/app-root/src && php artisan %s'"
  "bash <<< 'php artisan %s'"
  "echo 'php artisan %s' | oc exec -i deploy/backend -- sh"
  $'oc rsh deploy/backend <<\'EOF\'\nphp artisan %s\nEOF'
)
for sub in "${artisan_commands[@]}"; do
  for form in "${artisan_forms[@]}"; do
    # shellcheck disable=SC2059 # the form is the format string by design
    blocks "$(printf "$form" "$sub")"
  done
done
# An ambiguous abbreviation, which Laravel refuses, and a name that is only
# an argument both fail safe.
blocks 'php artisan m:r'
blocks 'php artisan help migrate:fresh'
# Only the data-wiping commands are matched.
allows 'php artisan migrate:status'
allows 'php artisan migrate:install'
allows 'php artisan make:migration add_index_to_posts'
allows 'php artisan db:seed'
allows 'php artisan route:list'
allows 'php artisan list'
allows "git commit -m 'docs: never run php artisan migrate:fresh'"
allows $'cat > notes.md <<\'EOF\'\n- php artisan db:wipe\nEOF'
reason_mentions 'oc exec deploy/backend -- php artisan db:wipe' 'the backend Deployment (verseghy-website/backend/)'
reason_mentions 'php artisan m:fr' '`artisan m:fr`'

# ------------------------------------------------------------- check 2: inline variables

blocks "PGHOST=db.example.org psql -c 'select 1'"
blocks "DATABASE_URL=$remote_pg psql"
blocks "PGHOST=db.example.org pg_restore -d website backup.dump"
blocks "MYSQL_HOST=legacy.example.org mysql -e 'select 1'"
blocks "export DATABASE_URL=$remote_pg; psql \"\$DATABASE_URL\""
blocks "env DATABASE_URL=$remote_pg psql"
blocks 'DATABASE_URL="$PROD_DATABASE_URL" psql'
blocks "DATABASE_URL=$local_pg psql -h db.example.org"
blocks "PGHOST=localhost psql $remote_pg"
allows "PGHOST=localhost psql -c 'select 1'"
allows "PGHOST=/var/run/postgresql psql -c 'select 1'"
allows "DATABASE_URL=$local_pg psql"
allows 'DATABASE_URL=postgres://app:app@127.0.0.1:5432/website_test psql'
allows 'DATABASE_URL=postgres://app:app@[::1]:5432/website_test psql'
allows "MYSQL_HOST=127.0.0.1 mysql -e 'select 1'"
reason_mentions "PGHOST=db.example.org psql" "an inline PGHOST= assignment"

# ------------------------------------------------------------- check 2: -h / --host

blocks 'psql -h db.example.org -U app website'
blocks 'psql -hdb.example.org'
blocks 'psql --host=db.example.org'
blocks 'psql --host db.example.org'
blocks 'psql -h localhost,db.example.org'
blocks 'psql -h "$DB_HOST"'
blocks 'pg_restore -h db.example.org -d website backup.dump'
blocks 'mysql -h legacy.example.org -u root legacy'
blocks 'mysql -hlegacy.example.org legacy'
allows 'psql -h localhost -U app website_development'
allows 'psql -h LOCALHOST'
allows 'psql -h 127.0.0.1'
allows 'psql -h ::1'
allows 'psql -h /var/run/postgresql'
allows 'pg_restore -h localhost -d website_development backup.dump'
allows 'mysql -h 127.0.0.1 -u root legacy'
allows 'mysql --host=localhost legacy'
reason_mentions 'psql -h db.example.org' 'from the -h option'

# ------------------------------------------------------------- check 2: -d / --dbname URIs

blocks 'psql -d postgres://app@db.example.org/website'
blocks 'psql --dbname=postgresql://app:app@db.example.org:5432/website'
blocks 'psql -dpostgres://db.example.org/website'
blocks 'pg_restore -d postgres://db.example.org/website backup.dump'
blocks 'psql -d "$DATABASE"'
allows 'psql -d postgresql://app:app@localhost:5432/website_development'
allows 'pg_restore -d website_development backup.dump'
allows 'psql -d website_development'

# ------------------------------------------------------------- check 2: host= connection strings

blocks 'psql "host=db.example.org dbname=website"'
blocks "psql -d 'dbname=website host=db.example.org user=app'"
blocks "psql --dbname='hostaddr=192.0.2.10 dbname=website'"
blocks "pg_restore -d 'host=db.example.org dbname=website' backup.dump"
allows 'psql "host=localhost dbname=website_development"'
allows "psql -d 'host=/var/run/postgresql dbname=website_development'"
allows "psql \"host='localhost' dbname=website_development\""
reason_mentions 'psql "host=db.example.org dbname=website"' 'a host= connection key'

# ------------------------------------------------------------- check 2: positional URIs

blocks "psql $remote_pg"
blocks "psql 'postgres://app@localhost/website?host=db.example.org'"
blocks "psql 'postgresql://localhost,db.example.org/website'"
blocks "psql 'postgres://app:p%40ss@db.example.org/website'"
blocks "mysql $remote_mysql"
allows "psql $local_pg"
allows "psql 'postgres://app@[::1]:5432/website_test'"
allows "psql 'postgres:///website_test?host=/var/run/postgresql'"
allows "psql 'postgresql://%2Fvar%2Frun%2Fpostgresql/website_test'"
allows "mysql $local_mysql"
reason_mentions "psql $remote_pg" 'a connection URI'

# ------------------------------------------------------------- check 2: the environment

blocks "psql -c 'select 1'" "DATABASE_URL=$remote_pg"
blocks 'psql "$DATABASE_URL"' "DATABASE_URL=$remote_pg"
blocks 'psql' 'PGHOST=db.example.org'
blocks 'pg_restore -d website backup.dump' 'PGHOST=db.example.org'
blocks "mysql -e 'select 1'" 'MYSQL_HOST=legacy.example.org'
blocks "mysql -e 'select 1'" "DATABASE_URL=$remote_mysql"
allows "psql -c 'select 1'" 'MYSQL_HOST=legacy.example.org'
allows 'psql "$DATABASE_URL"' "DATABASE_URL=$local_pg"
allows "DATABASE_URL=$local_pg psql" "DATABASE_URL=$remote_pg"
allows 'psql -h localhost' "DATABASE_URL=$remote_pg"
allows 'git status' "DATABASE_URL=$remote_pg"
allows 'oc get pods -n web' "DATABASE_URL=$remote_pg"
blocks "psql 'postgres:///website_test'" 'PGHOST=db.example.org'
allows "psql 'postgres:///website_test'" 'PGHOST=/var/run/postgresql'
allows "psql 'postgres:///website_test'"
reason_mentions_env() {
  payload_for "$1" >"$work/payload.json"
  run_hook_file "$work/payload.json" "$2"
  if [[ "$status" == 2 ]] && grep -qF -- "$3" "$work/err"; then
    report ok "reason for '$1' with $2 mentions '$3'" ""
  else
    report fail "reason for '$1' with $2 mentions '$3'" "  exit $status; stderr: $(cat "$work/err")"
  fi
}
reason_mentions_env "psql -c 'select 1'" "DATABASE_URL=$remote_pg" "the environment's DATABASE_URL"

# A local inline value never hides a remote environment value that the client
# itself reads: psql connects to PGHOST, whatever DATABASE_URL says, unless a
# host is given explicitly.
blocks "DATABASE_URL=$local_pg psql" 'PGHOST=db.example.org'
allows 'psql -h localhost' 'PGHOST=db.example.org'
# PGHOSTADDR, PGSERVICE and libpq key/value spellings.
blocks 'psql "dbname=x host = db.example.org"'
blocks "psql 'dbname=x hostaddr= 192.0.2.10'"
blocks 'PGHOSTADDR=10.0.0.1 psql'
blocks 'PGHOST=localhost PGHOSTADDR=10.0.0.1 psql'
blocks 'psql -h localhost' 'PGHOSTADDR=10.0.0.1'
blocks 'psql service=prod'
blocks "psql 'postgres:///website?service=prod'"
blocks 'PGSERVICE=prod psql'
blocks 'psql' 'PGSERVICE=prod'
allows "psql 'host = localhost dbname=website_development'"
# Assignments apply where the shell applies them: later segments and nested
# command strings see them, earlier segments do not, and the latest wins.
blocks "PGHOST=db.example.org bash -c 'psql -l'"
blocks "export PGHOST=db.example.org && sh -c 'psql -c \"select 1\"'"
blocks "psql -l; export PGHOST=db.example.org; psql -l"
blocks "export PGHOST=db.example.org; psql -c 'select 1'"
allows "export PGHOST=db.example.org; export PGHOST=localhost; psql -l"
allows "psql -l; export PGHOST=db.example.org"

# ------------------------------------------------------------- check 2: only the listed clients

# Check 2 reads the target of psql, pg_restore and mysql only. Another program
# next to one of them does not hide it, and an assignment in front of the
# other program still reaches the client in a later segment.
blocks "make lint && psql -h db.example.org"
blocks "DATABASE_URL=$remote_pg make lint && psql"
allows "DATABASE_URL=$remote_pg make lint"

# ------------------------------------------------------------- check 2: no target

allows "psql -c 'select 1'"
allows 'pg_restore -d website_development backup.dump'
allows "mysql -e 'select 1'"

# ------------------------------------------------------------- check 2: run in the cluster

blocks "oc exec postgres-0 -- psql -h localhost -c 'select 1'"
blocks 'oc exec -n web postgres-0 -- psql'
blocks 'oc rsh postgres-0 psql'
blocks 'oc rsh -n web postgres-0 psql -h 127.0.0.1'
blocks 'oc debug node/edge -- chroot /host psql -h 127.0.0.1'
blocks "oc exec -n web deploy/web -- sh -c 'psql -h localhost'"
blocks "oc exec mysql-0 -- mysql -h 127.0.0.1 -e 'select 1'"
blocks 'oc exec deploy/web -- pg_restore -d website backup.dump'
# The databases this repository deploys: Developer Hub's PostgreSQL on the hub
# and MySQL on the MicroShift edge.
blocks 'oc exec -n verseghy backstage-psql-developer-hub-0 -- psql -U postgres'
blocks "oc -n verseghy rsh backstage-psql-developer-hub-0 psql -c 'select 1'"
blocks "oc exec -n verseghy deploy/mysql -- mysql -u root -e 'show databases'"
blocks "oc exec -i -n verseghy pod/mysql-6c9d4 -- sh <<< 'mysql -u root'"
allows 'oc exec -n verseghy backstage-psql-developer-hub-0 -- df -h'
# The known false positive: a workload named after a client counts as the
# client. The reason gives the workaround, and naming the pod works.
blocks 'oc exec -n verseghy deploy/mysql -- df -h'
reason_mentions 'oc exec deploy/mysql -- df -h' 'name the pod instead'
allows 'oc exec -n verseghy pod/mysql-6c9d4 -- df -h'
allows 'oc exec postgres-0 -- ls'
allows 'oc logs postgres-0'
allows 'oc exec postgres-0 -- cat /etc/hostname | psql -h localhost'
reason_mentions 'oc rsh postgres-0 psql' 'runs inside the cluster through `oc rsh`'

# ------------------------------------------------------------- check 2: wrapped forms

blocks 'bash -c "psql -h db.example.org"'
blocks "sh -c 'PGHOST=db.example.org psql'"
blocks 'timeout 30 psql -h db.example.org'
blocks 'echo ok && psql -h db.example.org'
blocks "ssh bastion 'psql -h db.example.org'"
blocks "watch 'psql -h db.example.org -c \"select 1\"'"
blocks $'bash <<\'EOF\'\npsql -h db.example.org\nEOF'
allows "bash -c 'psql -h localhost'"

# ------------------------------------------------------------- a long command stays cheap

long_body="$(for i in $(seq 1 3000); do printf 'line %d: plain text that mentions oc and psql\n' "$i"; done)"
# EPOCHREALTIME (bash 5) gives the time for the log line; it is informative
# only, so older shells just skip it.
start="${EPOCHREALTIME:-}"
allows "cat > notes.txt <<'EOF'"$'\n'"$long_body"$'\n'"EOF"
if [[ -n "$start" ]]; then
  end="${EPOCHREALTIME}"
  elapsed_ms=$(((${end/[.,]/} - ${start/[.,]/}) / 1000))
  printf '# a %d-byte heredoc command took %d ms\n' "${#long_body}" "$elapsed_ms"
fi

# Many segments with inline assignments: each segment checks only the
# assignments in scope for it, so the work grows linearly. (When every segment
# walked every assignment of the whole command, 1600 such lines took about
# 100 s, longer than a hook may run.) The bound is generous for slow CI
# runners and still far below that cost.
assign_body="$(for i in $(seq 1 1600); do printf 'echo step %d && DATABASE_URL=%s psql -d website_%d -l;\n' "$i" "$local_pg" "$i"; done)"
start="${EPOCHREALTIME:-}"
allows "$assign_body"
if [[ -n "$start" ]]; then
  end="${EPOCHREALTIME}"
  elapsed_ms=$(((${end/[.,]/} - ${start/[.,]/}) / 1000))
  printf '# a %d-byte command with 1600 inline assignments took %d ms\n' "${#assign_body}" "$elapsed_ms"
  if ((elapsed_ms < 30000)); then
    report ok "1600 segments with inline assignments are checked in under 30 s" ""
  else
    report fail "1600 segments with inline assignments are checked in under 30 s" "  took ${elapsed_ms} ms"
  fi
fi

# ------------------------------------------------------------- summary

printf '# %d passed, %d failed\n' "$passed" "$failed"
if ((failed > 0)); then
  exit 1
fi
