#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ -n "${DOCKER_HOST+x}${DOCKER_CONTEXT+x}${DOCKER_TLS_VERIFY+x}${DOCKER_CERT_PATH+x}" ]]; then
    printf '%s\n' 'Refusing ambient Docker connection overrides' >&2
    exit 1
fi
docker_path="$(command -v docker)"
python_path="$(command -v python3)"
task_docker_context="$(command docker context show)"
task_docker_endpoint="$(command docker context inspect "$task_docker_context" --format '{{.Endpoints.docker.Host}}')"
if [[ "$task_docker_endpoint" != unix:///* || ! -S "${task_docker_endpoint#unix://}" ]]; then
    printf '%s\n' 'Refusing Docker context without a local Unix socket' >&2
    exit 1
fi

docker() {
    "$docker_path" --host "$task_docker_endpoint" "$@"
}

image='postgres@sha256:a77aa70e641402a21411b92b721c58d10f23b50ae5fdd2333efd22d166e1e5f7'
run_id="$(openssl rand -hex 12)"
container="mipsorcu-orchestrator-test-${run_id}"
container_id=''
container_created=0
proxy_pid=''
temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/mipsorcu-orchestrator.XXXXXXXX")"

cleanup() {
    local status=$?
    trap - EXIT
    if [[ -n "$proxy_pid" ]] && kill -0 "$proxy_pid" 2>/dev/null; then
        kill -TERM "$proxy_pid" 2>/dev/null || true
        for _ in {1..20}; do
            kill -0 "$proxy_pid" 2>/dev/null || break
            sleep 0.1
        done
        if kill -0 "$proxy_pid" 2>/dev/null; then
            kill -KILL "$proxy_pid" 2>/dev/null || true
        fi
        wait "$proxy_pid" 2>/dev/null || true
    fi
    if (( container_created )); then
        if ! "$python_path" - "$docker_path" "$task_docker_endpoint" "$container_id" <<'PY'
import subprocess
import sys

docker_path, endpoint, container_id = sys.argv[1:]
try:
    subprocess.run([docker_path, "--host", endpoint, "rm", "-fv", container_id],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   timeout=20, env={"PATH": "/usr/bin:/bin"})
except (OSError, subprocess.SubprocessError):
    raise SystemExit(1)
PY
        then
            printf '%s\n' 'Could not clean up disposable PostgreSQL within 20 seconds' >&2
            status=1
        fi
    fi
    rm -f "$temp_dir/port"
    rmdir "$temp_dir" 2>/dev/null || status=1
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if ! docker image inspect "$image" >/dev/null 2>&1; then
    printf '%s\n' 'Pinned PostgreSQL image is not available locally' >&2
    exit 1
fi
recover_unreported_container() {
    local identity
    identity="$(docker inspect --format '{{.Id}}|{{index .Config.Labels "mipsorcu.orchestrator-test"}}' "$container" 2>/dev/null || true)"
    if [[ "$identity" =~ ^([0-9a-f]{64})\|${run_id}$ ]]; then
        container_id="${BASH_REMATCH[1]}"
        container_created=1
    fi
}
POSTGRES_PASSWORD="$(openssl rand -hex 24)"
created_id="$(POSTGRES_PASSWORD="$POSTGRES_PASSWORD" docker create --pull=never --name "$container" \
    --label "mipsorcu.orchestrator-test=${run_id}" --network none \
    --memory 512m --cpus 1 --pids-limit 128 \
    --security-opt no-new-privileges --cap-drop ALL \
    --cap-add CHOWN --cap-add SETUID --cap-add SETGID --cap-add DAC_OVERRIDE \
    -e POSTGRES_PASSWORD "$image" postgres -c listen_addresses=127.0.0.1 2>/dev/null)" || {
    recover_unreported_container
    printf '%s\n' 'Could not create the disposable PostgreSQL container' >&2
    exit 1
}
if [[ ! "$created_id" =~ ^[0-9a-f]{64}$ ]]; then
    recover_unreported_container
    printf '%s\n' 'Docker returned an invalid disposable container identity' >&2
    exit 1
fi
container_id="$created_id"
container_created=1

identity="$(docker inspect --format '{{.Id}}|{{.Name}}|{{.Config.Image}}|{{.HostConfig.NetworkMode}}|{{len .HostConfig.PortBindings}}|{{if .HostConfig.Binds}}{{len .HostConfig.Binds}}{{else}}0{{end}}|{{range .Mounts}}{{.Type}}:{{.Destination}}:{{.RW}},{{end}}|{{index .Config.Labels "mipsorcu.orchestrator-test"}}' "$container_id" 2>/dev/null)" || {
    printf '%s\n' 'Could not verify the disposable PostgreSQL container' >&2
    exit 1
}
expected_identity="${container_id}|/${container}|${image}|none|0|0|volume:/var/lib/postgresql/data:true,|${run_id}"
if [[ "$identity" != "$expected_identity" ]]; then
    printf '%s\n' 'Disposable PostgreSQL container identity or isolation settings changed' >&2
    exit 1
fi

docker start "$container_id" >/dev/null 2>&1 || {
    printf '%s\n' 'Could not start the disposable PostgreSQL container' >&2
    exit 1
}

ready=0
for _ in {1..60}; do
    if docker exec "$container_id" pg_isready -U postgres -d postgres >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 1
done
if (( ! ready )); then
    printf '%s\n' 'Disposable PostgreSQL did not become ready' >&2
    exit 1
fi

setup_output=''
if ! setup_output="$(POSTGRES_PASSWORD="$POSTGRES_PASSWORD" docker exec -i -e POSTGRES_PASSWORD "$container_id" psql -U postgres -d postgres -v ON_ERROR_STOP=1 2>&1 <<'SQL'
\getenv password POSTGRES_PASSWORD
CREATE ROLE orchestrator_test LOGIN PASSWORD :'password';
CREATE DATABASE orchestrator_test_mock OWNER orchestrator_test;
CREATE DATABASE orchestrator_test_store OWNER orchestrator_test;
CREATE DATABASE orchestrator_test_engine OWNER orchestrator_test;
SQL
)"; then
    printf '%s\n' 'Could not initialize disposable PostgreSQL roles and databases' >&2
    printf '%s\n' "${setup_output//"$POSTGRES_PASSWORD"/[REDACTED]}" >&2
    exit 1
fi

"$python_path" - "$docker_path" "$task_docker_endpoint" "$container_id" "$temp_dir/port" <<'PY' &
import os
import signal
import socket
import subprocess
import sys
import threading

docker_path, docker_endpoint, container_id, port_path = sys.argv[1:]
stopping = threading.Event()
guard = threading.Lock()
clients = set()
children = set()

def stop(_signum, _frame):
    stopping.set()

signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)

listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", 0))
listener.listen(64)
listener.settimeout(0.25)
with open(port_path, "x", encoding="ascii") as port_file:
    port_file.write(f"{listener.getsockname()[1]}\n")

def send_all(pipe, data):
    view = memoryview(data)
    while view:
        written = pipe.write(view)
        if written is None:
            pipe.flush()
            return
        view = view[written:]
    pipe.flush()

def handle(client):
    child = None
    try:
        with guard:
            if stopping.is_set():
                return
            child = subprocess.Popen(
                [docker_path, "--host", docker_endpoint, "exec", "-i", container_id,
                 "nc", "127.0.0.1", "5432"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/tmp")},
                close_fds=True,
            )
            children.add(child)

        def to_container():
            try:
                while not stopping.is_set():
                    data = client.recv(65536)
                    if not data:
                        break
                    send_all(child.stdin, data)
            except (BrokenPipeError, OSError):
                pass
            finally:
                try:
                    child.stdin.close()
                except (AttributeError, OSError):
                    pass

        upstream = threading.Thread(target=to_container, daemon=True)
        upstream.start()
        while not stopping.is_set():
            data = os.read(child.stdout.fileno(), 65536)
            if not data:
                break
            client.sendall(data)
        upstream.join(timeout=1)
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    finally:
        try:
            client.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        client.close()
        if child is not None:
            try:
                child.terminate()
                child.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    child.kill()
                    child.wait(timeout=2)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            with guard:
                children.discard(child)
        with guard:
            clients.discard(client)

try:
    while not stopping.is_set():
        try:
            client, _ = listener.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        with guard:
            if stopping.is_set() or len(clients) >= 32:
                client.close()
                continue
            clients.add(client)
        threading.Thread(target=handle, args=(client,), daemon=True).start()
finally:
    stopping.set()
    listener.close()
    with guard:
        active_clients = tuple(clients)
        active_children = tuple(children)
    for client in active_clients:
        try:
            client.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        client.close()
    for child in active_children:
        try:
            child.terminate()
        except OSError:
            pass
    for child in active_children:
        try:
            child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                child.kill()
                child.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                pass
PY
proxy_pid=$!

for _ in {1..50}; do
    if [[ -s "$temp_dir/port" ]]; then
        break
    fi
    if ! kill -0 "$proxy_pid" 2>/dev/null; then
        printf '%s\n' 'Local PostgreSQL proxy failed to start' >&2
        exit 1
    fi
    sleep 0.1
done
if [[ ! -s "$temp_dir/port" ]]; then
    printf '%s\n' 'Local PostgreSQL proxy startup timed out' >&2
    exit 1
fi
IFS= read -r port < "$temp_dir/port"
if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
    printf '%s\n' 'Local PostgreSQL proxy returned an invalid port' >&2
    exit 1
fi
if ! "$python_path" - "$port" <<'PY'
import socket
import struct
import sys

port = int(sys.argv[1])
startup = (struct.pack("!I", 196608) + b"user\0orchestrator_test\0"
           + b"database\0orchestrator_test_mock\0\0")
packet = struct.pack("!I", len(startup) + 4) + startup
try:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
        connection.settimeout(5)
        connection.sendall(packet)
        header = bytearray()
        while len(header) < 9:
            chunk = connection.recv(9 - len(header))
            if not chunk:
                raise ValueError("truncated startup response")
            header.extend(chunk)
    if header[0] != ord("R") or struct.unpack("!I", header[1:5])[0] < 8:
        raise ValueError("unexpected startup response")
except (OSError, ValueError, struct.error):
    raise SystemExit(1)
PY
then
    printf '%s\n' 'Local PostgreSQL proxy relay check failed' >&2
    exit 1
fi
printf '%s\n' 'Local PostgreSQL proxy relay verified'

run_test() {
    local database="$1" target="$2" test_name="$3" output
    if ! output="$(POSTGRES_PASSWORD="$POSTGRES_PASSWORD" "$python_path" - "$database" "$target" "$test_name" "$port" <<'PY'
import os
import subprocess
import sys

database, target, test_name, port = sys.argv[1:]
password = os.environ["POSTGRES_PASSWORD"]
env = {
    "PATH": os.environ["PATH"],
    "HOME": os.environ["HOME"],
    "MIPSORCU_ORCHESTRATOR_TEST_DATABASE_URL":
        f"postgresql://orchestrator_test:{password}@127.0.0.1:{port}/{database}",
}
try:
    result = subprocess.run(
        ["cargo", "test", "--locked", "--manifest-path", "orchestrator/Cargo.toml",
         target, test_name, "--", "--ignored", "--exact"],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
    )
except OSError:
    print("Could not start the PostgreSQL test", file=sys.stderr)
    raise SystemExit(1)
sys.stdout.buffer.write(result.stdout.replace(password.encode(), b"[REDACTED]"))
raise SystemExit(result.returncode)
PY
)"; then
        printf 'PostgreSQL test failed: %s\n' "$test_name" >&2
        printf '%s\n' "${output//"$POSTGRES_PASSWORD"/[REDACTED]}" >&2
        return 1
    fi
    if [[ "$output" != *'running 1 test'* || "$output" != *"test ${test_name} ... ok"* || \
          "$output" != *'test result: ok. 1 passed; 0 failed; 0 ignored'* ]]; then
        printf 'PostgreSQL test did not run exactly once: %s\n' "$test_name" >&2
        return 1
    fi
    printf 'PostgreSQL test passed: %s\n' "$test_name"
}

run_test orchestrator_test_mock --lib 'mock::tests::postgres_mock_loop_survives_child_process_crash_and_scripted_ci_repair'
run_test orchestrator_test_store --test=postgres_integration 'postgres_claim_idempotency_expiry_fencing_and_recovery'
run_test orchestrator_test_engine --test=engine_postgres 'real_engine_rejects_stale_base_and_does_not_reexecute_ambiguous_stage_after_restart'
