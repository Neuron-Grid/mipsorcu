#!/usr/bin/env bash
set -euo pipefail
umask 077

mode="${1:-demo}"
if [[ "$#" -gt 1 || ( "$mode" != demo && "$mode" != postgres-tests ) ]]; then
    printf '%s\n' 'Usage: bash scripts/test-orchestrator-offline-container.sh [demo|postgres-tests]' >&2
    exit 1
fi

image='rust@sha256:d7482085ff5b415f84dba5647ae71606650bdef00db7aeb69f4b3d170c3e4082'
postgres_image='postgres@sha256:a77aa70e641402a21411b92b721c58d10f23b50ae5fdd2333efd22d166e1e5f7'
uid="$(id -u)"
gid="$(id -g)"
if [[ "$uid" == 0 ]]; then
    printf '%s\n' 'Refusing to run this demonstration as host root' >&2
    exit 1
fi
for tool in cargo docker python3 perl openssl; do
    command -v "$tool" >/dev/null || { printf 'Required command is missing: %s\n' "$tool" >&2; exit 1; }
done
python3 -c 'import sys; sys.version_info >= (3, 11) or sys.exit("Python 3.11 or newer is required")'
if [[ -n "${DOCKER_HOST+x}${DOCKER_CONTEXT+x}${DOCKER_TLS_VERIFY+x}${DOCKER_CERT_PATH+x}" ]]; then
    printf '%s\n' 'Refusing ambient Docker connection overrides' >&2
    exit 1
fi
task_docker_context="$(command docker context show)"
task_docker_endpoint="$(command docker context inspect "$task_docker_context" --format '{{.Endpoints.docker.Host}}')"
if [[ "$task_docker_endpoint" != unix:///* || ! -S "${task_docker_endpoint#unix://}" ]]; then
    printf '%s\n' 'Refusing Docker context without a local Unix socket' >&2
    exit 1
fi
docker() {
    command docker --host "$task_docker_endpoint" "$@"
}
bounded_docker_control() {
    local timeout_seconds="$1"
    shift
    [[ "$timeout_seconds" =~ ^[1-9][0-9]*$ ]] || return 125
    local replace_shell=0
    if [[ "${1:-}" == --exec ]]; then
        replace_shell=1
        shift
    fi
    local -a control_command=(perl -e '
        use POSIX qw(WNOHANG);
        my $seconds = shift;
        my $pid = fork();
        defined $pid or exit 125;
        if (!$pid) { exec @ARGV; exit 127; }
        my $stop = sub { my $code = shift; kill 9, $pid; waitpid($pid, WNOHANG); exit $code; };
        $SIG{ALRM} = sub { $stop->(124); };
        $SIG{TERM} = sub { $stop->(143); };
        $SIG{INT} = sub { $stop->(130); };
        alarm $seconds;
        my $result = waitpid($pid, 0);
        my $status = $?;
        alarm 0;
        exit 125 if $result != $pid;
        exit(($status & 127) ? 128 + ($status & 127) : $status >> 8);
    ' "$timeout_seconds" "$(type -P docker)" --host "$task_docker_endpoint" "$@")
    if (( replace_shell )); then
        exec "${control_command[@]}"
    fi
    "${control_command[@]}"
}

image_platform="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$image")"
case "$image_platform" in
    linux/arm64) target='aarch64-unknown-linux-gnu' ;;
    linux/amd64) target='x86_64-unknown-linux-gnu' ;;
    *) printf 'Cached Rust image has unsupported platform: %s\n' "$image_platform" >&2; exit 1 ;;
esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
orchestrator="$repo_root/orchestrator"
[[ -f "$orchestrator/Cargo.toml" && -f "$orchestrator/Cargo.lock" && -d "$orchestrator/src" ]] || {
    printf '%s\n' 'Orchestrator source inputs are incomplete' >&2
    exit 1
}

task_tmp_root="$(cd "${TMPDIR:-/tmp}" && pwd -P)"
task_dir="$(mktemp -d "$task_tmp_root/mipsorcu-orchestrator-offline.XXXXXXXX")"
if ! chmod 700 "$task_dir" || ! python3 - "$task_dir" "$uid" <<'PY'
import os
import sys
info = os.stat(sys.argv[1])
if info.st_uid != int(sys.argv[2]) or info.st_mode & 0o777 != 0o700:
    raise SystemExit(1)
PY
then
    rmdir "$task_dir" 2>/dev/null || true
    printf '%s\n' 'Could not establish a private, owner-controlled staging directory' >&2
    exit 1
fi
run_id="$(openssl rand -hex 12)"
builder="mipsorcu-offline-build-$run_id"
runner="mipsorcu-offline-demo-$run_id"
builder_id=''
runner_id=''
builder_created=0
runner_created=0
postgres_id=''
postgres_created=0
watchdog_pid=''
capture_pid=''
attach_pid=''

cleanup() {
    local status=$?
    trap - EXIT
    if [[ -n "$watchdog_pid" ]]; then
        kill "$watchdog_pid" >/dev/null 2>&1 || true
        wait "$watchdog_pid" 2>/dev/null || true
    fi
    if [[ -n "$capture_pid" ]]; then
        kill "$capture_pid" >/dev/null 2>&1 || true
        wait "$capture_pid" 2>/dev/null || true
    fi
    if (( runner_created )); then bounded_docker_control 20 rm -f "$runner_id" >/dev/null || status=1; fi
    if [[ -n "$attach_pid" ]]; then
        kill "$attach_pid" >/dev/null 2>&1 || true
        wait "$attach_pid" 2>/dev/null || true
    fi
    if (( builder_created )); then bounded_docker_control 20 rm -f "$builder_id" >/dev/null || status=1; fi
    if (( postgres_created )); then bounded_docker_control 20 rm -fv "$postgres_id" >/dev/null || status=1; fi
    if [[ "$task_dir" == "$task_tmp_root"/mipsorcu-orchestrator-offline.* && -d "$task_dir" && ! -L "$task_dir" ]]; then
        rm -rf -- "$task_dir" || status=1
    else
        printf '%s\n' 'Refusing cleanup because the private staging path changed' >&2
        status=1
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -m 700 "$task_dir/source" "$task_dir/registry" "$task_dir/output"
source_manifest() {
    python3 - "$1" "$mode" <<'PY'
import hashlib
import os
import stat
import sys

root = os.path.abspath(sys.argv[1])
mode = sys.argv[2]
roots = ("src", "tests", "migrations") if mode == "postgres-tests" else ("src",)
records = []
def add(relative):
    path = os.path.join(root, relative)
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode):
        raise SystemExit(f"Refusing symlink in source tree: {relative}")
    if stat.S_ISDIR(info.st_mode):
        if not any(relative == root or relative.startswith(root + "/") for root in roots):
            raise SystemExit(f"Refusing unexpected source directory: {relative}")
        for name in sorted(os.listdir(path)):
            add(os.path.join(relative, name))
    elif stat.S_ISREG(info.st_mode):
        digest = hashlib.sha256()
        with open(path, "rb") as source_file:
            for chunk in iter(lambda: source_file.read(1024 * 1024), b""):
                digest.update(chunk)
        records.append((relative.replace(os.sep, "/"), digest.hexdigest()))
    else:
        raise SystemExit(f"Refusing non-regular source file: {relative}")

for relative in ("Cargo.toml", "Cargo.lock", *roots):
    add(relative)
print("\n".join(f"{path}\t{digest}" for path, digest in sorted(records)))
PY
}

source_manifest "$orchestrator" > "$task_dir/source.before"
cp "$orchestrator/Cargo.toml" "$orchestrator/Cargo.lock" "$task_dir/source/"
cp -R "$orchestrator/src" "$task_dir/source/src"
if [[ "$mode" == postgres-tests ]]; then
    cp -R "$orchestrator/tests" "$orchestrator/migrations" "$task_dir/source/"
fi
source_manifest "$orchestrator" > "$task_dir/source.after-copy"
source_manifest "$task_dir/source" > "$task_dir/staged.after-copy"
cmp -s "$task_dir/source.before" "$task_dir/source.after-copy" &&
    cmp -s "$task_dir/source.before" "$task_dir/staged.after-copy" || {
    printf '%s\n' 'Orchestrator source changed while staging; refusing to continue' >&2
    exit 1
}

task_cargo_home="${CARGO_HOME:-$HOME/.cargo}"
[[ -d "$task_cargo_home/registry/index" && -d "$task_cargo_home/registry/cache" ]] || {
    printf '%s\n' 'Cargo registry index/cache is unavailable locally; offline replay cannot continue' >&2
    exit 1
}
metadata_cargo_home="$task_dir/metadata-cargo"
mkdir -m 700 "$metadata_cargo_home"
config_dir="$task_dir"
while :; do
    [[ ! -e "$config_dir/.cargo/config" && ! -e "$config_dir/.cargo/config.toml" ]] || {
        printf 'Refusing ancestor Cargo config that could inject wrappers: %s/.cargo\n' "$config_dir" >&2
        exit 1
    }
    [[ "$config_dir" != / ]] || break
    config_dir="$(dirname "$config_dir")"
done
trusted_cargo_dir="$(dirname "$(command -v cargo)")"
trusted_path="$trusted_cargo_dir:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
python3 - "$task_cargo_home" "$task_dir/source/Cargo.lock" "$metadata_cargo_home" <<'PY'
import hashlib
import os
import re
import shutil
import sys
import tomllib

source_home, lock_path, destination = sys.argv[1:]
with open(lock_path, "rb") as lock_file:
    lock = tomllib.load(lock_file)
registry = os.path.join(source_home, "registry")
indexes = [os.path.join(registry, "index", name) for name in os.listdir(os.path.join(registry, "index"))]
indexes = [path for path in indexes if os.path.isfile(os.path.join(path, "config.json")) and os.path.isdir(os.path.join(path, ".cache"))]
if len(indexes) != 1:
    raise SystemExit("Expected exactly one local sparse registry index")
index = indexes[0]
if os.path.islink(os.path.join(index, "config.json")):
    raise SystemExit("Refusing a symlinked registry config")
index_name = os.path.basename(index)
source_cache = os.path.join(registry, "cache", index_name)
index_target = os.path.join(destination, "registry", "index", index_name)
cache_target = os.path.join(destination, "registry", "cache", index_name)
os.makedirs(index_target)
os.makedirs(cache_target)
shutil.copy2(os.path.join(index, "config.json"), index_target)

def index_path(name):
    name = name.lower()
    if len(name) == 1:
        return os.path.join("1", name)
    if len(name) == 2:
        return os.path.join("2", name)
    if len(name) == 3:
        return os.path.join("3", name[0], name)
    return os.path.join(name[:2], name[2:4], name)

for package in lock.get("package", []):
    source = package.get("source")
    if source is None:
        continue
    if source != "registry+https://github.com/rust-lang/crates.io-index":
        raise SystemExit(f"Refusing non-crates.io package source: {package['name']}")
    name, version = package["name"], package["version"]
    if not re.fullmatch(r"[A-Za-z0-9_-]+", name) or not re.fullmatch(r"[A-Za-z0-9.+_-]+", version):
        raise SystemExit("Refusing invalid Cargo.lock package identity")
    if not re.fullmatch(r"[0-9a-f]{64}", package.get("checksum", "")):
        raise SystemExit("Refusing invalid Cargo.lock checksum")
    entry = os.path.join(index, ".cache", index_path(name))
    if (not os.path.isfile(entry) or os.path.islink(entry)
            or not os.path.realpath(entry).startswith(os.path.realpath(os.path.join(index, ".cache")) + os.sep)):
        raise SystemExit(f"Sparse index entry is missing: {name}")
    staged_entry = os.path.join(index_target, ".cache", index_path(name))
    os.makedirs(os.path.dirname(staged_entry), exist_ok=True)
    if not os.path.exists(staged_entry):
        shutil.copy2(entry, staged_entry)
    archive_name = f"{name}-{version}.crate"
    archive = os.path.join(source_cache, archive_name)
    if os.path.isfile(archive) and not os.path.islink(archive):
        digest = hashlib.sha256()
        with open(archive, "rb") as archive_file:
            for chunk in iter(lambda: archive_file.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != package.get("checksum"):
            raise SystemExit(f"Cached crate checksum does not match Cargo.lock: {archive_name}")
        shutil.copy2(archive, os.path.join(cache_target, archive_name))
PY
(cd "$task_dir" && env -i PATH="$trusted_path" HOME="$HOME" CARGO_HOME="$metadata_cargo_home" \
    RUSTUP_HOME="$HOME/.rustup" CARGO_NET_OFFLINE=true \
    cargo metadata --offline --locked --format-version 1 --filter-platform "$target" \
    --manifest-path source/Cargo.toml) > "$task_dir/metadata.json"

python3 - "$metadata_cargo_home" "$task_dir/source" "$task_dir/metadata.json" "$task_dir/registry" <<'PY'
import hashlib
import json
import os
import shutil
import sys
import tomllib

cargo_home, source_dir, metadata_file, destination = sys.argv[1:]
with open(os.path.join(source_dir, "Cargo.lock"), "rb") as lock_file:
    lock = tomllib.load(lock_file)
with open(metadata_file, encoding="utf-8") as metadata_file_handle:
    metadata = json.load(metadata_file_handle)
nodes = metadata.get("resolve", {}).get("nodes")
if not nodes:
    raise SystemExit("Cargo metadata did not provide a resolved dependency graph")
selected = {node["id"] for node in nodes}
packages = {package["id"]: package for package in metadata["packages"] if package["id"] in selected}
locked = {}
for package in lock.get("package", []):
    if package.get("source") == "registry+https://github.com/rust-lang/crates.io-index":
        locked[(package["name"], package["version"])] = package.get("checksum")

indexes = [os.path.join(cargo_home, "registry", "index", name) for name in os.listdir(os.path.join(cargo_home, "registry", "index"))]
indexes = [path for path in indexes if os.path.isfile(os.path.join(path, "config.json")) and os.path.isdir(os.path.join(path, ".cache"))]
if len(indexes) != 1:
    raise SystemExit("Expected exactly one local sparse registry index")
index = indexes[0]
index_name = os.path.basename(index)
cache_root = os.path.join(cargo_home, "registry", "cache", index_name)
if not os.path.isdir(cache_root):
    raise SystemExit("Crates.io archive cache does not match the local sparse index")

index_destination = os.path.join(destination, "index", index_name)
cache_destination = os.path.join(destination, "cache", index_name)
os.makedirs(index_destination)
os.makedirs(cache_destination)
shutil.copy2(os.path.join(index, "config.json"), index_destination)
for crate_name in {name.lower() for name, _ in locked}:
    if len(crate_name) == 1:
        sparse_path = os.path.join("1", crate_name)
    elif len(crate_name) == 2:
        sparse_path = os.path.join("2", crate_name)
    elif len(crate_name) == 3:
        sparse_path = os.path.join("3", crate_name[0], crate_name)
    else:
        sparse_path = os.path.join(crate_name[:2], crate_name[2:4], crate_name)
    index_entry = os.path.join(index, ".cache", sparse_path)
    if not os.path.isfile(index_entry) or os.path.islink(index_entry):
        raise SystemExit(f"Sparse index entry is missing: {crate_name}")
    staged_entry = os.path.join(index_destination, ".cache", sparse_path)
    os.makedirs(os.path.dirname(staged_entry), exist_ok=True)
    shutil.copy2(index_entry, staged_entry)
copied = 0
for package in packages.values():
    source = package.get("source")
    if source is None:
        if os.path.realpath(package["manifest_path"]) != os.path.realpath(os.path.join(source_dir, "Cargo.toml")):
            raise SystemExit(f"Refusing a local dependency outside staged source: {package['name']}")
        continue
    if source != "registry+https://github.com/rust-lang/crates.io-index":
        raise SystemExit(f"Refusing non-crates.io package source: {package['name']}")
    key = (package["name"], package["version"])
    checksum = locked.get(key)
    if checksum is None:
        raise SystemExit(f"Cargo.lock checksum is missing for {key[0]} {key[1]}")
    archive = f"{key[0]}-{key[1]}.crate"
    archive_path = os.path.join(cache_root, archive)
    if not os.path.isfile(archive_path) or os.path.islink(archive_path):
        raise SystemExit(f"Offline crate archive is missing: {archive}")
    digest = hashlib.sha256()
    with open(archive_path, "rb") as archive_file:
        for chunk in iter(lambda: archive_file.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != checksum:
        raise SystemExit(f"Cached crate checksum does not match Cargo.lock: {archive}")
    shutil.copy2(archive_path, os.path.join(cache_destination, archive))
    copied += 1
if copied == 0:
    raise SystemExit("No target-selected registry archives were staged")
print(f"Prepared {copied} target-selected crates.io archives; all SHA-256 checksums match Cargo.lock")
PY

assert_container() {
    local name="$1" kind="$2" memory pids mounts tmpfs isolation security
    if [[ "$kind" == build ]]; then memory=2147483648; pids=128
    else memory=268435456; pids=32
    fi
    isolation="$(docker inspect --format '{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.Config.User}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.Memory}}|{{.HostConfig.PidsLimit}}|{{join .HostConfig.CapDrop ","}}|{{.HostConfig.Privileged}}|{{.HostConfig.LogConfig.Type}}' "$name")"
    security="$(docker inspect --format '{{join .HostConfig.SecurityOpt ","}}' "$name")"
    [[ "$isolation" == "none|true|$uid:$gid|1000000000|$memory|$pids|ALL|false|none" &&
        ( "$security" == no-new-privileges || "$security" == no-new-privileges:true ) ]] || {
        printf 'Container isolation or resource limits differ from policy: %s\n' "$name" >&2; return 1;
    }
    if [[ "$kind" == build && "$(docker inspect --format '{{.HostConfig.Init}}' "$name")" != true ]]; then
        printf '%s\n' 'Build container init is not enabled' >&2
        return 1
    fi
    mounts="$(docker inspect --format '{{json .Mounts}}' "$name")"
    python3 - "$mounts" "$kind" "$task_dir" <<'PY'
import json
import sys
mounts, kind, stage = sys.argv[1:]
actual = {(item["Destination"], item["Source"], item["RW"]) for item in json.loads(mounts)}
expected = (
    {("/input/source", f"{stage}/source", False), ("/input/registry", f"{stage}/registry", False)}
    if kind == "build" else
    {("/work/mipsorcu-orchestrator", f"{stage}/output/mipsorcu-orchestrator", False)}
)
if actual != expected or len(json.loads(mounts)) != len(expected):
    raise SystemExit("Container mounts differ from the exact allowed set")
PY
    tmpfs="$(docker inspect --format '{{json .HostConfig.Tmpfs}}' "$name")"
    python3 - "$tmpfs" "$kind" "$uid" "$gid" <<'PY'
import json
import sys
mounts, kind, uid, gid = sys.argv[1:]
mounts = json.loads(mounts)
common = {"rw", "nosuid", "nodev", f"uid={uid}", f"gid={gid}", "mode=0700"}
expected = {"/tmp": common | ({"exec", "size=2g"} if kind == "build" else {"noexec", "size=16m"})}
if kind == "build":
    expected["/output"] = common | {"noexec", "size=512m"}
if set(mounts) != set(expected) or any(
        len(mounts[path].split(",")) != len(options) or set(mounts[path].split(",")) != options
        for path, options in expected.items()):
    raise SystemExit("Temporary filesystems differ from policy")
PY
}

if [[ "$mode" == postgres-tests ]]; then
    build_command='exec 3>&1 1>&2; touch /output/.uid-probe; rm /output/.uid-probe; mkdir -p /tmp/cargo; cp -R /input/registry /tmp/cargo/registry
        cargo build --offline --locked --release --bin mipsorcu-artifact-stream
        cargo test --offline --locked --release --no-run --lib --test postgres_integration --test engine_postgres
        for spec in "mipsorcu_orchestrator:mock::tests::postgres_mock_loop_survives_child_process_crash_and_scripted_ci_repair" "postgres_integration:postgres_claim_idempotency_expiry_fencing_and_recovery" "engine_postgres:real_engine_rejects_stale_base_and_does_not_reexecute_ambiguous_stage_after_restart"; do
            prefix=${spec%%:*}; test_name=${spec#*:}; count=0; selected=
            for candidate in /tmp/target/release/deps/"$prefix"-*; do
                if [ -f "$candidate" ] && [ -x "$candidate" ] && listing="$("$candidate" --list 2>/dev/null)" && printf "%s\n" "$listing" | grep -Fx "$test_name: test" >/dev/null; then
                    count=$((count + 1)); selected=$candidate; selected_listing=$listing
                fi
            done
            [ "$count" -eq 1 ] || exit 1
            if [ "$prefix" = mipsorcu_orchestrator ]; then
                printf "%s\n" "$selected_listing" | grep -Fx "docker_preflight::tests::invokes_explicit_cli_with_clean_environment_and_accepts_synthetic_response: test" >/dev/null
                printf "%s\n" "$selected_listing" | grep -Fx "docker_preflight::tests::timeout_leaves_the_gate_closed_when_a_pipe_holding_grandchild_outlives_cli: test" >/dev/null
                printf "%s\n" "$selected_listing" | grep -Fx "docker_preflight::tests::socket_preflight_uses_one_fixed_get_without_auth_and_accepts_valid_info: test" >/dev/null
                printf "%s\n" "$selected_listing" | grep -Fx "docker_preflight::tests::socket_preflight_cancellation_releases_the_gate: test" >/dev/null
                printf "%s\n" "$selected_listing" | grep -Fx "docker_preflight::tests::container_inspect_reads_only_matching_id_and_running_state: test" >/dev/null
                printf "%s\n" "$selected_listing" | grep -Fx "docker_preflight::tests::container_inspect_rejects_ambiguous_or_unbounded_responses: test" >/dev/null
                printf "%s\n" "$selected_listing" | grep -Fx "github::tests::observes_one_stable_pull_request_candidate_without_granting_authority: test" >/dev/null
                printf "%s\n" "$selected_listing" | grep -Fx "github::tests::candidate_observation_requires_list_and_detail_bodies_to_match: test" >/dev/null
                printf "%s\n" "$selected_listing" | grep -Fx "github::tests::branch_post_success_then_child_crash_recovers_ambiguous_without_replay: test" >/dev/null
                printf "%s\n" "$selected_listing" | grep -Fx "engine::tests::postgres_issue_close_child_crash_recovers_without_replay: test" >/dev/null
                printf "%s\n" "$selected_listing" | grep -Fx "supervisor_lock::tests::serializes_processes_and_releases_after_process_death: test" >/dev/null
                printf "%s\n" "$selected_listing" | grep -Fx "supervisor_lock::tests::persisted_intent_remains_single_slot_after_process_kill: test" >/dev/null
                printf "%s\n" "$selected_listing" | grep -Fx "supervisor_lock::tests::read_intent_rejects_malformed_and_oversized_records: test" >/dev/null
                printf "%s\n" "$selected_listing" | grep -Fx "source_snapshot::tests::nonblocking_stdio_returns_when_escaped_child_holds_descriptors: test" >/dev/null
                printf "%s\n" "$selected_listing" | grep -Fx "workspace::tests::captures_subprocess_output_on_linux: test" >/dev/null
                printf "%s\n" "$selected_listing" | grep -Fx "artifact_receiver::tests::producer_binary_round_trips_worktree_into_verified_staging_when_configured: test" >/dev/null
                printf "%s\n" "$selected_listing" | grep -Fx "artifact_receiver::tests::malformed_or_truncated_streams_do_not_create_staging: test" >/dev/null
                printf "%s\n" "$selected_listing" | grep -Fx "artifact_receiver::tests::producer_rejects_metadata_paths_and_symlinks_before_emitting: test" >/dev/null
                printf "%s\n" "$selected_listing" | grep -Fx "artifact_receiver::tests::malformed_tree_records_are_rejected_before_staging: test" >/dev/null
                printf "%s\n" "$selected_listing" | grep -Fx "artifact_receiver::tests::producer_rejects_hardlinked_files_and_staged_reads_detect_tampering: test" >/dev/null
                printf "%s\n" "$selected_listing" | grep -Fx "artifact_receiver::tests::completed_staging_reopens_after_process_restart_and_rejects_tampering: test" >/dev/null
                "$selected" docker_preflight::tests --test-threads=1
                "$selected" artifact_receiver::tests --test-threads=1
                MIPSORCU_ARTIFACT_PRODUCER=/tmp/target/release/mipsorcu-artifact-stream "$selected" artifact_receiver::tests::producer_binary_round_trips_worktree_into_verified_staging_when_configured --exact --ignored
                "$selected" artifact_receiver::tests::completed_staging_reopens_after_process_restart_and_rejects_tampering --exact --ignored
                "$selected" github::tests::observes_one_stable_pull_request_candidate_without_granting_authority --exact
                "$selected" github::tests::candidate_observation --test-threads=1
                "$selected" supervisor_lock::tests --test-threads=1
                "$selected" source_snapshot::tests::nonblocking_stdio --test-threads=1
                "$selected" --exact workspace::tests::captures_subprocess_output_on_linux
            fi
            if [ "$prefix" = postgres_integration ]; then
                printf "%s\n" "$selected_listing" | grep -Fx "postgres_server_crash_seed: test" >/dev/null
                printf "%s\n" "$selected_listing" | grep -Fx "postgres_server_crash_recover: test" >/dev/null
            fi
            if [ "$prefix" = engine_postgres ]; then
                printf "%s\n" "$selected_listing" | grep -Fx "postgres_active_server_crash: test" >/dev/null
                printf "%s\n" "$selected_listing" | grep -Fx "postgres_active_server_recover: test" >/dev/null
            fi
            install -m 0500 "$selected" "/output/$prefix"
        done
        tar --format=ustar -C /output -cf - mipsorcu_orchestrator postgres_integration engine_postgres >&3'
else
    build_command='exec 3>&1 1>&2; touch /output/.uid-probe; rm /output/.uid-probe; mkdir -p /tmp/cargo; cp -R /input/registry /tmp/cargo/registry; cargo build --offline --locked --release --bin mipsorcu-orchestrator; install -m 0500 /tmp/target/release/mipsorcu-orchestrator /output/mipsorcu-orchestrator; tar --format=ustar -C /output -cf - mipsorcu-orchestrator >&3'
fi
builder_id="$(docker create --pull=never --name "$builder" --init --network none --read-only --user "$uid:$gid" --log-driver none \
    --cap-drop ALL --security-opt no-new-privileges --pids-limit 128 --cpus 1 --memory 2g \
    --tmpfs "/tmp:rw,exec,nosuid,nodev,uid=$uid,gid=$gid,mode=0700,size=2g" \
    --tmpfs "/output:rw,noexec,nosuid,nodev,uid=$uid,gid=$gid,mode=0700,size=512m" \
    --mount "type=bind,src=$task_dir/source,dst=/input/source,readonly" \
    --mount "type=bind,src=$task_dir/registry,dst=/input/registry,readonly" \
    -e HOME=/tmp -e CARGO_HOME=/tmp/cargo -e CARGO_TARGET_DIR=/tmp/target -e CARGO_NET_OFFLINE=true \
    --workdir /input/source "$image" /bin/sh -ec "$build_command")"
builder_created=1
assert_container "$builder_id" build

capture_bounded() {
    TASK_REDACT="${1:-}" TASK_CAPTURE_SECONDS="${2:-0}" python3 -c '
import os, signal, sys
seconds = int(os.environ["TASK_CAPTURE_SECONDS"])
if seconds:
    def timeout(_signal, _frame):
        raise TimeoutError
    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(seconds)
try:
    data = sys.stdin.buffer.read(4 * 1024 * 1024 + 1)
except TimeoutError:
    raise SystemExit(1)
if len(data) > 4 * 1024 * 1024:
    raise SystemExit(1)
secret = os.environ["TASK_REDACT"].encode()
sys.stdout.buffer.write(data.replace(secret, b"[REDACTED]") if secret else data)
'
}

receive_artifacts() {
    if ! python3 -I "$1" "$2" "$3"; then
        docker kill "$4" >/dev/null 2>&1 || true
        return 1
    fi
}

run_bounded() {
    local name="$1" seconds="$2" output_file="$3"
    local -a statuses
    perl -e 'my ($seconds, @command) = @ARGV; sleep $seconds; exec @command' \
        "$seconds" docker --host "$task_docker_endpoint" kill "$name" >/dev/null 2>&1 &
    watchdog_pid=$!
    set +e
    docker start --attach "$name" 2>&1 | capture_bounded > "$output_file"
    statuses=("${PIPESTATUS[@]}")
    set -e
    kill "$watchdog_pid" >/dev/null 2>&1 || true
    wait "$watchdog_pid" 2>/dev/null || true
    watchdog_pid=''
    local state
    state="$(docker inspect --format '{{.State.Status}}:{{.State.ExitCode}}' "$name")"
    if [[ "$state" != exited:0 || "${statuses[0]}" != 0 || "${statuses[1]}" != 0 ]]; then
        printf 'Container failed or exceeded its %s-second timeout (state %s)\n' "$seconds" "$state" >&2
        return 1
    fi
}

mkfifo -m 600 "$task_dir/build-stderr"
capture_bounded < "$task_dir/build-stderr" > "$task_dir/build.log" &
capture_pid=$!
perl -e 'my ($seconds, @command) = @ARGV; sleep $seconds; exec @command' \
    600 docker --host "$task_docker_endpoint" kill "$builder_id" >/dev/null 2>&1 &
watchdog_pid=$!
set +e
docker start --attach "$builder_id" 2> "$task_dir/build-stderr" | \
    receive_artifacts "$repo_root/scripts/receive-orchestrator-artifacts.py" "$mode" "$task_dir/output" "$builder_id"
build_statuses=("${PIPESTATUS[@]}")
wait "$capture_pid"
capture_status=$?
set -e
capture_pid=''
kill "$watchdog_pid" >/dev/null 2>&1 || true
wait "$watchdog_pid" 2>/dev/null || true
watchdog_pid=''
state="$(docker inspect --format '{{.State.Status}}:{{.State.ExitCode}}' "$builder_id")"
[[ "${build_statuses[0]}" == 0 && "${build_statuses[1]}" == 0 && "$capture_status" == 0 && "$state" == exited:0 ]] || {
    printf 'Build or bounded artifact transfer failed (state %s)\n' "$state" >&2
    exit 1
}
source_manifest "$orchestrator" > "$task_dir/source.after-build"
source_manifest "$task_dir/source" > "$task_dir/staged.after-build"
cmp -s "$task_dir/source.before" "$task_dir/source.after-build" &&
    cmp -s "$task_dir/source.before" "$task_dir/staged.after-build" || {
    printf '%s\n' 'Orchestrator source changed during the build; refusing to accept its output' >&2
    exit 1
}
if [[ "$mode" == demo ]]; then
[[ -f "$task_dir/output/mipsorcu-orchestrator" && ! -L "$task_dir/output/mipsorcu-orchestrator" ]] || {
    printf '%s\n' 'Build did not produce the expected executable' >&2
    exit 1
}

runner_id="$(docker create --pull=never --name "$runner" --network none --read-only --user "$uid:$gid" --log-driver none \
    --cap-drop ALL --security-opt no-new-privileges --pids-limit 32 --cpus 1 --memory 256m \
    --tmpfs "/tmp:rw,noexec,nosuid,nodev,uid=$uid,gid=$gid,mode=0700,size=16m" \
    --mount "type=bind,src=$task_dir/output/mipsorcu-orchestrator,dst=/work/mipsorcu-orchestrator,readonly" \
    -e HOME=/tmp "$image" /work/mipsorcu-orchestrator demo)"
runner_created=1
assert_container "$runner_id" runtime
run_bounded "$runner_id" 60 "$task_dir/demo.log"

for expected in \
    'mock engine crash point: operation completed; state save failed' \
    'mock engine replay: state=Paused, checkpoint=Some(Validating), plan executions=1, total executions=2' \
    'mock engine resumed: state=Completed, simulated merge=true, stage executions=4' \
    'simulation only: no PostgreSQL, external GitHub, Git, filesystem write, or model was used'; do
    [[ "$(grep -Fxc -- "$expected" "$task_dir/demo.log")" == 1 ]] || {
        printf 'Mock demo did not produce exactly one expected result: %s\n' "$expected" >&2
        exit 1
    }
done

printf 'Offline %s build succeeded from checksum-verified cached crates.\n' "$image_platform"
printf '%s\n' 'The isolated demo process reached COMPLETED and reported simulation only.'
printf '%s\n' 'Containers used network=none, read-only rootfs, host-mapped non-root UID/GID, dropped capabilities, no-new-privileges, resource limits, and timeouts.'
printf '%s\n' 'This does not establish that the host Docker daemon is rootless.'
fi

if [[ "$mode" == postgres-tests ]]; then
    wait_for_test_postgres() {
        local deadline=$((SECONDS + 60)) remaining
        while (( SECONDS < deadline )); do
            remaining=$((deadline - SECONDS))
            (( remaining > 0 )) || break
            (( remaining <= 5 )) || remaining=5
            if bounded_docker_control "$remaining" exec "$postgres_id" pg_isready -U postgres -d postgres >/dev/null 2>&1; then
                return 0
            fi
            sleep 1
        done
        return 1
    }
    recover_named_container() {
        local observed
        observed="$(docker inspect --format '{{.Id}}|{{index .Config.Labels "mipsorcu.offline-run"}}' "$1" 2>/dev/null || true)"
        if [[ "$observed" =~ ^([0-9a-f]{64})\|${run_id}$ ]]; then
            printf '%s\n' "${BASH_REMATCH[1]}"
        fi
    }
    for artifact in mipsorcu_orchestrator postgres_integration engine_postgres; do
        [[ -f "$task_dir/output/$artifact" && ! -L "$task_dir/output/$artifact" ]] || {
            printf '%s\n' 'Build did not produce the expected test executable' >&2
            exit 1
        }
    done
    docker image inspect "$postgres_image" >/dev/null
    task_pg_password="$(openssl rand -hex 24)"
    postgres_name="mipsorcu-offline-postgres-$run_id"
    if ! postgres_id="$(POSTGRES_PASSWORD="$task_pg_password" docker create --pull=never --name "$postgres_name" \
        --label "mipsorcu.offline-run=$run_id" \
        --network none --memory 512m --cpus 1 --pids-limit 128 --log-driver none \
        --security-opt no-new-privileges --cap-drop ALL \
        --cap-add CHOWN --cap-add SETUID --cap-add SETGID --cap-add DAC_OVERRIDE \
        -e POSTGRES_PASSWORD "$postgres_image" postgres -c listen_addresses=127.0.0.1 2>/dev/null)"; then
        postgres_id="$(recover_named_container "$postgres_name")"
        [[ -z "$postgres_id" ]] || postgres_created=1
        printf '%s\n' 'Could not create disposable PostgreSQL' >&2
        exit 1
    fi
    if [[ ! "$postgres_id" =~ ^[0-9a-f]{64}$ ]]; then
        postgres_id="$(recover_named_container "$postgres_name")"
        [[ -z "$postgres_id" ]] || postgres_created=1
        printf '%s\n' 'PostgreSQL container identity is invalid' >&2
        exit 1
    fi
    postgres_created=1
    postgres_settings="$(docker inspect --format '{{.Id}}|{{.Name}}|{{.Config.Image}}|{{.HostConfig.NetworkMode}}|{{len .HostConfig.PortBindings}}|{{.HostConfig.LogConfig.Type}}|{{range .Mounts}}{{.Type}}:{{.Destination}}:{{.RW}},{{end}}' "$postgres_id")"
    [[ "$postgres_settings" == "$postgres_id|/$postgres_name|$postgres_image|none|0|none|volume:/var/lib/postgresql/data:true," ]] || {
        printf '%s\n' 'PostgreSQL container does not match the isolated configuration' >&2
        exit 1
    }
    postgres_host_config="$(docker inspect --format '{{json .HostConfig}}' "$postgres_id")"
    python3 - "$postgres_host_config" <<'PY'
import json
import sys
config = json.loads(sys.argv[1])
adds = config.get("CapAdd") or []
drops = config.get("CapDrop") or []
security = config.get("SecurityOpt") or []
if (config.get("NanoCpus") != 1_000_000_000 or config.get("Memory") != 536_870_912
        or config.get("PidsLimit") != 128 or config.get("Privileged") is not False
        or config.get("Binds") not in (None, []) or set(drops) != {"ALL"}
        or len(adds) != 4 or {value.removeprefix("CAP_") for value in adds} != {"CHOWN", "DAC_OVERRIDE", "SETGID", "SETUID"}
        or security not in (["no-new-privileges"], ["no-new-privileges:true"])):
    raise SystemExit("PostgreSQL resource or security settings differ from policy")
PY
    docker start "$postgres_id" >/dev/null
    wait_for_test_postgres || { printf '%s\n' 'Disposable PostgreSQL did not become ready' >&2; exit 1; }
    POSTGRES_PASSWORD="$task_pg_password" docker exec -i -e POSTGRES_PASSWORD "$postgres_id" \
        psql -U postgres -d postgres -v ON_ERROR_STOP=1 >/dev/null 2>&1 <<'SQL'
\getenv password POSTGRES_PASSWORD
CREATE ROLE orchestrator_test LOGIN PASSWORD :'password';
CREATE DATABASE orchestrator_test_mock OWNER orchestrator_test;
CREATE DATABASE orchestrator_test_store OWNER orchestrator_test;
CREATE DATABASE orchestrator_test_engine OWNER orchestrator_test;
CREATE DATABASE orchestrator_test_crash OWNER orchestrator_test;
CREATE DATABASE orchestrator_test_active_crash OWNER orchestrator_test;
CREATE DATABASE orchestrator_test_github_crash OWNER orchestrator_test;
CREATE DATABASE orchestrator_test_engine_issue_close_crash OWNER orchestrator_test;
SQL

    crash_test_postgres() {
        local identity
        identity="$(docker inspect --format '{{.Id}}|{{.Name}}|{{index .Config.Labels "mipsorcu.offline-run"}}|{{.State.Running}}' "$postgres_id")"
        [[ "$identity" == "$postgres_id|/$postgres_name|$run_id|true" ]] || {
            printf '%s\n' 'Refusing to interrupt a PostgreSQL container with an unexpected identity' >&2
            return 1
        }
        original_mounts="$(docker inspect --format '{{json .Mounts}}' "$postgres_id")"
        original_start="$(docker inspect --format '{{.State.StartedAt}}' "$postgres_id")"
        bounded_docker_control 20 kill --signal KILL "$postgres_id" >/dev/null
        [[ "$(bounded_docker_control 20 wait "$postgres_id")" == 137 ]] || {
            printf '%s\n' 'Disposable PostgreSQL did not terminate with SIGKILL' >&2
            return 1
        }
    }

    restart_test_postgres() {
        bounded_docker_control 20 start "$postgres_id" >/dev/null
        [[ "$(docker inspect --format '{{json .Mounts}}' "$postgres_id")" == "$original_mounts" && \
           "$(docker inspect --format '{{.State.StartedAt}}' "$postgres_id")" != "$original_start" ]] || {
            printf '%s\n' 'PostgreSQL restarted with an unexpected volume or process' >&2
            return 1
        }
        wait_for_test_postgres || { printf '%s\n' 'Disposable PostgreSQL did not recover after SIGKILL' >&2; return 1; }
    }

    for spec in \
        'mipsorcu_orchestrator:orchestrator_test_mock:mock::tests::postgres_mock_loop_survives_child_process_crash_and_scripted_ci_repair' \
        'postgres_integration:orchestrator_test_store:postgres_claim_idempotency_expiry_fencing_and_recovery' \
        'engine_postgres:orchestrator_test_engine:real_engine_rejects_stale_base_and_does_not_reexecute_ambiguous_stage_after_restart' \
        'mipsorcu_orchestrator:orchestrator_test_github_crash:github::tests::branch_post_success_then_child_crash_recovers_ambiguous_without_replay' \
        'mipsorcu_orchestrator:orchestrator_test_engine_issue_close_crash:engine::tests::postgres_issue_close_child_crash_recovers_without_replay' \
        'postgres_integration:orchestrator_test_crash:postgres_server_crash_seed' \
        'postgres_integration:orchestrator_test_crash:postgres_server_crash_recover' \
        'engine_postgres:orchestrator_test_active_crash:postgres_active_server_crash' \
        'engine_postgres:orchestrator_test_active_crash:postgres_active_server_recover'; do
        artifact="${spec%%:*}"
        remainder="${spec#*:}"
        database="${remainder%%:*}"
        test_name="${remainder#*:}"
        runner="mipsorcu-offline-pg-$artifact-$run_id"
        runner_url="postgresql://orchestrator_test:${task_pg_password}@127.0.0.1:5432/${database}"
        if ! runner_id="$(MIPSORCU_ORCHESTRATOR_TEST_DATABASE_URL="$runner_url" docker create --pull=never --name "$runner" \
            --label "mipsorcu.offline-run=$run_id" \
            --network "container:$postgres_id" --read-only --user "$uid:$gid" --log-driver none \
            --cap-drop ALL --security-opt no-new-privileges --pids-limit 32 --cpus 1 --memory 256m \
            --tmpfs "/tmp:rw,noexec,nosuid,nodev,uid=$uid,gid=$gid,mode=0700,size=16m" \
            --mount "type=bind,src=$task_dir/output/$artifact,dst=/work/test,readonly" \
            -e HOME=/tmp -e MIPSORCU_ORCHESTRATOR_TEST_DATABASE_URL \
            "$image" /bin/sh -ec 'test ! -S /var/run/docker.sock; test "$(wc -l < /proc/net/route)" -eq 1; exec /work/test "$@"' \
            sh "$test_name" --ignored --exact 2>/dev/null)"; then
            runner_id="$(recover_named_container "$runner")"
            [[ -z "$runner_id" ]] || runner_created=1
            printf '%s\n' 'Could not create isolated PostgreSQL test runner' >&2
            exit 1
        fi
        if [[ ! "$runner_id" =~ ^[0-9a-f]{64}$ ]]; then
            runner_id="$(recover_named_container "$runner")"
            [[ -z "$runner_id" ]] || runner_created=1
            printf '%s\n' 'PostgreSQL test runner identity is invalid' >&2
            exit 1
        fi
        runner_created=1
        runner_settings="$(docker inspect --format '{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.Config.User}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.Memory}}|{{.HostConfig.PidsLimit}}|{{join .HostConfig.CapDrop ","}}|{{join .HostConfig.SecurityOpt ","}}|{{.HostConfig.LogConfig.Type}}|{{.HostConfig.Privileged}}' "$runner_id")"
        [[ "$runner_settings" == "container:$postgres_id|true|$uid:$gid|1000000000|268435456|32|ALL|no-new-privileges|none|false" || \
           "$runner_settings" == "container:$postgres_id|true|$uid:$gid|1000000000|268435456|32|ALL|no-new-privileges:true|none|false" ]] || {
            printf '%s\n' 'Test runner does not match the isolated configuration' >&2
            exit 1
        }
        mounts="$(docker inspect --format '{{json .Mounts}}' "$runner_id")"
        python3 - "$mounts" "$task_dir/output/$artifact" <<'PY'
import json
import sys
mounts = json.loads(sys.argv[1])
if len(mounts) != 1 or (mounts[0]["Source"], mounts[0]["Destination"], mounts[0]["RW"]) != (sys.argv[2], "/work/test", False):
    raise SystemExit("Test runner mounts do not match the allowed executable")
PY
        tmpfs="$(docker inspect --format '{{index .HostConfig.Tmpfs "/tmp"}}' "$runner_id")"
        [[ "$tmpfs" == *"uid=$uid"* && "$tmpfs" == *"gid=$gid"* && "$tmpfs" == *mode=0700* && \
           "$tmpfs" == *nosuid* && "$tmpfs" == *nodev* && "$tmpfs" == *noexec* && "$tmpfs" == *size=* ]] || {
            printf '%s\n' 'Test runner temporary filesystem differs from policy' >&2
            exit 1
        }
        perl -e 'my ($seconds, @command) = @ARGV; sleep $seconds; exec @command' \
            120 docker --host "$task_docker_endpoint" kill "$runner_id" >/dev/null 2>&1 &
        watchdog_pid=$!
        if [[ "$test_name" == postgres_active_server_crash ]]; then
            mkfifo -m 600 "$task_dir/active-test.fifo"
            capture_bounded "$task_pg_password" 130 < "$task_dir/active-test.fifo" > "$task_dir/$artifact.log" &
            capture_pid=$!
            bounded_docker_control 120 --exec start --attach "$runner_id" > "$task_dir/active-test.fifo" 2>&1 &
            attach_pid=$!
            marker_sql="SELECT count(*) FROM orchestrator.test_active_engine_crash_markers m JOIN orchestrator.task_operations o ON o.operation_key=m.operation_key AND o.task_id=m.task_id AND o.fencing_token=m.fencing_token JOIN orchestrator.tasks t ON t.id=m.task_id JOIN orchestrator.execution_lease l ON l.task_id=m.task_id AND l.fencing_token=m.fencing_token WHERE m.task_id='20261121-0002-0000-0000-000000000001'::uuid AND t.status::text='planning' AND o.operation='plan' AND o.result IS NULL AND l.owner='postgres-active-crash-worker' AND l.expires_at > clock_timestamp()"
            marker_ready=0
            marker_deadline=$((SECONDS + 40))
            while (( SECONDS < marker_deadline )); do
                if bounded_docker_control 5 exec "$runner_id" /bin/sh -c 'test -f /tmp/mipsorcu-active-crash-ready && test ! -L /tmp/mipsorcu-active-crash-ready' >/dev/null 2>&1; then
                    marker="$(bounded_docker_control 5 exec --user postgres "$postgres_id" psql -X -qAt -v ON_ERROR_STOP=1 -d orchestrator_test_active_crash -c "$marker_sql" 2>/dev/null || true)"
                    if [[ "$marker" == 1 ]]; then
                        marker_ready=1
                        break
                    fi
                fi
                runner_state="$(bounded_docker_control 5 inspect --format '{{.State.Status}}' "$runner_id")"
                [[ "$runner_state" == created || "$runner_state" == running ]] || break
                sleep 0.2
            done
            [[ "$marker_ready" == 1 ]] || {
                printf '%s\n' 'Active Engine did not publish a matching durable operation and lease' >&2
                exit 1
            }
            [[ "$(bounded_docker_control 20 inspect --format '{{.State.Status}}' "$runner_id")" == running ]] || {
                printf '%s\n' 'Active Engine test runner exited before fault injection' >&2
                exit 1
            }
            crash_test_postgres
            set +e
            wait "$attach_pid"
            attach_status=$?
            attach_pid=''
            wait "$capture_pid"
            capture_status=$?
            capture_pid=''
            set -e
            statuses=("$attach_status" "$capture_status")
        else
            set +e
            docker start --attach "$runner_id" 2>&1 | capture_bounded "$task_pg_password" > "$task_dir/$artifact.log"
            statuses=("${PIPESTATUS[@]}")
            set -e
        fi
        kill "$watchdog_pid" >/dev/null 2>&1 || true
        wait "$watchdog_pid" 2>/dev/null || true
        watchdog_pid=''
        state="$(docker inspect --format '{{.State.Status}}:{{.State.ExitCode}}' "$runner_id")"
        [[ "${statuses[0]}" == 0 && "${statuses[1]}" == 0 && "$state" == exited:0 ]] || {
            printf 'Isolated PostgreSQL test failed or timed out: %s\n' "$test_name" >&2
            python3 - "$task_dir/$artifact.log" <<'PY'
import re
import sys

with open(sys.argv[1], "rb") as log:
    data = log.read()
match = re.search(rb"panicked at ([A-Za-z0-9_./-]+\.rs:[0-9]+:[0-9]+)", data)
if match:
    print("Test panic location:", match.group(1).decode("ascii"), file=sys.stderr)
status = re.search(rb"ISSUE_CLOSE_CHILD_STATUS=([0-9]{1,3})", data)
if status:
    print("Test child exit status:", status.group(1).decode("ascii"), file=sys.stderr)
PY
            exit 1
        }
        grep -Fxq 'running 1 test' "$task_dir/$artifact.log" && \
            grep -Fxq "test $test_name ... ok" "$task_dir/$artifact.log" && \
            grep -Eq '^test result: ok\. 1 passed; 0 failed; 0 ignored;' "$task_dir/$artifact.log" || {
            printf 'Isolated PostgreSQL test did not run exactly once: %s\n' "$test_name" >&2
            exit 1
        }
        docker rm -f "$runner_id" >/dev/null
        runner_created=0
        printf 'Isolated PostgreSQL test passed: %s\n' "$test_name"
        if [[ "$test_name" == postgres_server_crash_seed ]]; then
            crash_test_postgres
            restart_test_postgres
        elif [[ "$test_name" == postgres_active_server_crash ]]; then
            restart_test_postgres
        fi
    done
    printf '%s\n' 'The test containers shared only the network-none PostgreSQL namespace and received no host credentials or container socket.'
    printf '%s\n' 'The Docker daemon rootless mode and resistance to container escape were not verified.'
fi
