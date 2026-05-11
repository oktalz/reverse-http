#!/usr/bin/env bash
# Generate the mTLS material required by a reverse-http deployment:
#
#   * a self-signed CA (one-off; signs every worker cert)
#   * one client cert per worker
#
# The library refuses to run without these, and HAProxy with
# "verify required ca-file" enforces them at TLS handshake.
#
# Usage:
#   ./gen-certs.sh                       # CA + one cert with CN "rhttp-worker"
#   ./gen-certs.sh worker-1 worker-2     # CA + two named worker certs
#   ./gen-certs.sh -d ./pki worker-1     # custom output dir
#   ./gen-certs.sh -c my-internal-ca -d ./pki worker-1
#   ./gen-certs.sh -h                    # help
#
# The script is idempotent: an existing workers-ca.crt+workers-ca.key in the
# output dir is reused, so re-running it just mints more worker certs from
# the same root.

set -euo pipefail

# Newly created files (private keys especially) must not be world- or
# group-readable, even briefly between `openssl … -out` and the explicit
# `chmod 600` below.
umask 077

OUT_DIR=./rhttp-certs
CA_CN=rhttp-ca
CA_DAYS=3650
WORKER_DAYS=365

usage() {
    sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while getopts "d:c:h" opt; do
    case "$opt" in
        d) OUT_DIR=$OPTARG ;;
        c) CA_CN=$OPTARG ;;
        h) usage 0 ;;
        *) usage 1 ;;
    esac
done
shift $((OPTIND - 1))

WORKERS=("$@")
if [[ ${#WORKERS[@]} -eq 0 ]]; then
    WORKERS=(rhttp-worker)
fi

# CNs become both X.509 subject components and output filenames. Restrict to
# a safe character class so a malicious arg can't inject extra DN attributes
# (e.g. `foo/O=Acme/`) or traverse out of OUT_DIR (e.g. `../etc/x`).
for cn in "${WORKERS[@]}"; do
    [[ "$cn" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "invalid CN: $cn (allowed: A-Z a-z 0-9 . _ -)" >&2; exit 1; }
done

command -v openssl >/dev/null || { echo "openssl: command not found" >&2; exit 1; }

mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

# ── CA ────────────────────────────────────────────────────────────────
# Generated once. workers-ca.key is the long-term secret — every worker cert is
# signed by it. Treat it like a password: back it up, don't commit it,
# don't ship it to either server. Only this script needs it.
if [[ -f workers-ca.crt && -f workers-ca.key ]]; then
    echo "==> Reusing existing CA in $(pwd)/"
else
    echo "==> Minting CA ($CA_CN, ${CA_DAYS} days)"
    openssl ecparam -name prime256v1 -genkey -noout -out workers-ca.key
    chmod 600 workers-ca.key
    openssl req -x509 -new -key workers-ca.key -days "$CA_DAYS" \
        -subj "/CN=${CA_CN}" \
        -addext "basicConstraints=critical,CA:true,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -out workers-ca.crt
fi

# ── Worker certs ──────────────────────────────────────────────────────
# One per worker. CN must match whatever your HAProxy ACL is checking
# (typically ssl_c_s_dn(CN) -m str <name>). The extendedKeyUsage tells
# clients this cert is for client-auth, not server-auth.
for cn in "${WORKERS[@]}"; do
    if [[ -f "${cn}.crt" && -f "${cn}.key" ]]; then
        echo "==> Skipping ${cn}: certificate already exists"
        continue
    fi
    echo "==> Minting worker cert (CN=${cn}, ${WORKER_DAYS} days)"
    openssl ecparam -name prime256v1 -genkey -noout -out "${cn}.key"
    chmod 600 "${cn}.key"
    openssl req -new -key "${cn}.key" \
        -subj "/CN=${cn}" \
        -out "${cn}.csr"
    openssl x509 -req -in "${cn}.csr" \
        -CA workers-ca.crt -CAkey workers-ca.key -CAcreateserial \
        -days "$WORKER_DAYS" \
        -extfile <(printf "extendedKeyUsage=clientAuth\n") \
        -out "${cn}.crt"
    rm -f "${cn}.csr"
done
# Keep workers-ca.srl between runs. openssl uses it to track the next serial
# number; deleting it would restart serials at 1 and let two batches mint
# certs with the same issuer+serial pair, which breaks any CRL/audit tooling
# that relies on (issuer, serial) being a unique cert identifier.

# ── Summary ───────────────────────────────────────────────────────────
cat <<EOF

Done. Generated in $(pwd):

  workers-ca.crt         → copy to HAProxy box (e.g. /etc/haproxy/workers-ca.crt),
                   referenced from your bind line as:
                     bind ... ca-file /etc/haproxy/workers-ca.crt verify required

  workers-ca.key         ← KEEP OFFLINE. Only needed when you mint another worker
                   cert by re-running this script. Don't ship to either
                   server.

EOF
for cn in "${WORKERS[@]}"; do
    cat <<EOF
  ${cn}.crt / ${cn}.key
                 → copy both to that worker's box. Pass to the library via
                   ServerOptions.TLSCert (or --rhttp-cert / --rhttp-key
                   when using the slides binary). chmod 600 ${cn}.key.

                   Reference from your HAProxy frontend with an ACL such as
                     acl is_worker ssl_c_s_dn(CN) -m str ${cn}
                     tcp-request session attach-srv <backend>/<srv> if is_worker

EOF
done

cat <<'EOF'
To verify mTLS works against your HAProxy after deploying:

  openssl s_client -connect <proxy>:1025 \
      -cert <worker>.crt -key <worker>.key \
      -CAfile <proxy-server-ca>.pem \
      -servername <proxy-host> -alpn h2 </dev/null 2>&1 | head -20

A clean "Verify return code: 0 (ok)" plus "ALPN protocol: h2" means the
handshake works end-to-end.
EOF
