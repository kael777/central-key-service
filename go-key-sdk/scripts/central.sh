#!/usr/bin/env bash
# Central Key Service - Linux start/stop helper.
#
#   ./scripts/central.sh start|stop|restart|status|logs|check
#
# Configuration is read from the JSON file passed to the binary (-config).
# Order: $CONFIG env -> config.local.json -> config.example.json
# KEK:   $KEY_KEK env -> data/kek.hex
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$BASE_DIR"

CMD="${1:-}"
shift || true

# allow: ./scripts/central.sh start --config /etc/central-key/config.json
while [ $# -gt 0 ]; do
  case "$1" in
    --config) CONFIG="$2"; shift 2 ;;
    --config=*) CONFIG="${1#*=}"; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ -z "${CONFIG:-}" ]; then
  if [ -f /etc/central-key/config.json ]; then
    CONFIG=/etc/central-key/config.json
  elif [ -f config.local.json ]; then
    CONFIG=config.local.json
  elif [ -f config.example.json ]; then
    CONFIG=config.example.json
  else
    echo "config file not found (/etc/central-key/config.json, config.local.json, config.example.json)" >&2
    exit 1
  fi
fi

BIN="${BIN:-$BASE_DIR/bin/central}"
PID_FILE="${PID_FILE:-$BASE_DIR/run/central.pid}"
LOG_FILE="${LOG_FILE:-$BASE_DIR/logs/central.log}"

mkdir -p "$(dirname "$PID_FILE")" "$(dirname "$LOG_FILE")"

# KEK 來源：環境變數 > /etc/central-key/env > data/kek.hex
if [ -z "${KEY_KEK:-}" ] && [ -f /etc/central-key/env ]; then
  set -a
  # shellcheck disable=SC1091
  . /etc/central-key/env
  set +a
fi
if [ -z "${KEY_KEK:-}" ] && [ -f "$BASE_DIR/data/kek.hex" ]; then
  KEY_KEK="$(tr -d '[:space:]' < "$BASE_DIR/data/kek.hex")"
  export KEY_KEK
fi

is_running() {
  [ -f "$PID_FILE" ] || return 1
  local pid
  pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  [ -n "$pid" ] || return 1
  kill -0 "$pid" 2>/dev/null
}

health() {
  local ca="$BASE_DIR/certs/ca.crt"
  if command -v curl >/dev/null 2>&1; then
    if [ -f "$ca" ]; then
      curl -sS --cacert "$ca" "https://127.0.0.1:8443/healthz" 2>/dev/null || echo "(healthz unreachable)"
    else
      curl -sk "https://127.0.0.1:8443/healthz" 2>/dev/null || echo "(healthz unreachable)"
    fi
  else
    echo "(curl not installed)"
  fi
}

start() {
  if is_running; then
    echo "already running (pid $(cat "$PID_FILE"))"
    return 0
  fi
  if [ ! -x "$BIN" ]; then
    echo "binary not found: $BIN" >&2
    echo "build it first: go build -o bin/central ./cmd/central" >&2
    exit 1
  fi
  echo "starting with config: $CONFIG"
  nohup "$BIN" -config "$CONFIG" >>"$LOG_FILE" 2>&1 &
  echo $! >"$PID_FILE"
  sleep 1
  if is_running; then
    echo "started (pid $(cat "$PID_FILE")), log: $LOG_FILE"
    health
  else
    echo "failed to start, last log lines:" >&2
    tail -n 20 "$LOG_FILE" >&2 || true
    rm -f "$PID_FILE"
    exit 1
  fi
}

stop() {
  if ! is_running; then
    echo "not running"
    rm -f "$PID_FILE"
    return 0
  fi
  local pid
  pid="$(cat "$PID_FILE")"
  echo "stopping pid $pid"
  kill "$pid" 2>/dev/null || true
  for _ in $(seq 1 20); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.5
  done
  if kill -0 "$pid" 2>/dev/null; then
    echo "force killing"
    kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$PID_FILE"
  echo "stopped"
}

status() {
  if is_running; then
    echo "running (pid $(cat "$PID_FILE"))"
    health
  else
    echo "not running"
    return 3
  fi
}

logs() {
  tail -n 50 -f "$LOG_FILE"
}

check() {
  health
}

case "$CMD" in
  start) start ;;
  stop) stop ;;
  restart) stop; start ;;
  status) status ;;
  logs) logs ;;
  check) check ;;
  *)
    echo "usage: $0 {start|stop|restart|status|logs|check} [--config FILE]" >&2
    exit 2
    ;;
esac
