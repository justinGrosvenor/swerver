#!/bin/bash
# httparena/entrypoint.sh
#
# Starts two swerver processes in the same container:
#   - :8080 plaintext HTTP/1.1 + HTTP/2 (upgrade)
#   - :8443 TLS HTTP/1.1 + HTTP/2 + QUIC HTTP/3
#
# swerver binds exactly one TCP + one UDP listener per process, so
# a dual-protocol submission to HttpArena needs two processes until
# multi-listener support lands upstream. Each process's workers are
# set to 1 for predictability; tune via the config files at submit
# time.
#
# The container exits if either process exits (using `wait -n`), so
# crash loops surface immediately in the benchmark harness.

set -e

/usr/local/bin/swerver --config /etc/swerver/config-h1.json &
H1_PID=$!

/usr/local/bin/swerver --config /etc/swerver/config-tls.json &
TLS_PID=$!

shutdown() {
    kill "$H1_PID" "$TLS_PID" 2>/dev/null || true
    wait "$H1_PID" 2>/dev/null || true
    wait "$TLS_PID" 2>/dev/null || true
    exit 0
}
trap shutdown TERM INT

# Exit as soon as either process dies so the container doesn't
# linger with one listener down.
wait -n "$H1_PID" "$TLS_PID"
echo "swerver: one process exited, terminating container" >&2
shutdown
exit 1
