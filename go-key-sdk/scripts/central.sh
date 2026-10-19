#!/usr/bin/env bash
# Central Key Service - Linux start/stop helper.
#
#   ./scripts/central.sh start|stop|restart|status|logs|check
#
# Configuration is read from the JSON file passed to the binary (-config).
# Order: $CONFIG env -> config.local.json -> config.example.json
# KEK:   $KEY_KEK env -> data/kek.hex
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ "$(basename "$SCRIPT_DIR")" = "scripts" ]; then
  BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"   # 源碼目錄：go-key-sdk/scripts/
else
  BASE_DIR="$SCRIPT_DIR"                      # 部署目錄：腳本與執行檔同層
fi
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

# 設定檔：--config / $CONFIG 最優先；否則找程式旁邊的 config.json
if [ -z "${CONFIG:-}" ]; then
  for candidate in \
    "$BASE_DIR/config.json" \
    "$BASE_DIR/bin/config.json" \
    "$BASE_DIR/config.local.json" \
    "/etc/central-key/config.json" \
    "$BASE_DIR/config.example.json"; do
    if [ -f "$candidate" ]; then
      CONFIG="$candidate"
      break
    fi
  done
fi
if [ -z "${CONFIG:-}" ]; then
  echo "config not found. put config.json next to bin/, or pass --config /path/to/config.json" >&2
  exit 1
fi

if [ -z "${BIN:-}" ]; then
  if [ -x "$BASE_DIR/bin/central" ]; then
    BIN="$BASE_DIR/bin/central"
  else
    BIN="$BASE_DIR/central"
  fi
fi
PID_FILE="${PID_FILE:-$BASE_DIR/run/central.pid}"
LOG_FILE="${LOG_FILE:-$BASE_DIR/logs/central.log}"

mkdir -p "$(dirname "$PID_FILE")" "$(dirname "$LOG_FILE")"

# KEK 來源：環境變數 > 程式旁邊的 env > /etc/central-key/env > kek.hex
if [ -z "${KEY_KEK:-}" ]; then
  for envfile in "$BASE_DIR/env" "/etc/central-key/env"; do
    if [ -f "$envfile" ]; then
      set -a
      # shellcheck disable=SC1090
      . "$envfile"
      set +a
      break
    fi
  done
fi
if [ -z "${KEY_KEK:-}" ]; then
  for kekfile in "$BASE_DIR/kek.hex" "$BASE_DIR/data/kek.hex"; do
    if [ -f "$kekfile" ]; then
      KEY_KEK="$(tr -d '[:space:]' < "$kekfile")"
      export KEY_KEK
      break
    fi
  done
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
