#!/usr/bin/env bash
# A throwaway TLS Redis for RedisLiveTest's TLS half (libs/client-attestation): what build.yml's java job starts
# before the reactor build, so a checkout gets the same server.
#
#   tools/ci/start-tls-redis.sh DIR [PORT] [NAME]
#
# openssl makes a CA and a certificate for localhost in DIR, valid for a day. The CA's key is deleted once the
# certificate is signed, so nothing else can be issued under it; nothing here is tracked or reused. The
# certificate names DNS:localhost and no address, because one of the tests connects to 127.0.0.1 instead and
# expects the handshake to fail before AUTH. redis:7-alpine then serves TLS only (--port 0) on 127.0.0.1:PORT
# with a password, as the user running this script so it can read the key, and the script waits until it
# answers PING over TLS. It prints the two variables the test reads as KEY=value lines on stdout, and nothing
# else: build.yml appends them to $GITHUB_ENV, and locally
#   export $(tools/ci/start-tls-redis.sh /tmp/redis-tls 56374 redis-tls)
# sets them for a `mvn verify` in the same shell. Stop the server with `docker rm -f NAME`.
set -euo pipefail
dir="${1:?usage: start-tls-redis.sh DIR [PORT] [NAME]}"
port="${2:-6380}"
name="${3:-oidf-test-redis-tls}"
# Throwaway, like the Postgres service's credentials in build.yml: the server listens on 127.0.0.1 for one job.
password=redis-live-test

mkdir -p "$dir"
dir="$(cd "$dir" && pwd)"

# Both requests read this file rather than the system's openssl.cnf, so OpenSSL 3 on the runner and on a Mac
# make the same certificates.
cat > "$dir/req.cnf" <<'CNF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = RedisLiveTest throwaway CA
[ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[server]
subjectAltName = DNS:localhost
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
CNF
openssl req -x509 -new -config "$dir/req.cnf" -extensions ca -newkey rsa:2048 -nodes -days 1 \
  -keyout "$dir/ca.key" -out "$dir/ca.pem" 2>/dev/null
openssl req -new -config "$dir/req.cnf" -newkey rsa:2048 -nodes -subj /CN=localhost \
  -keyout "$dir/server.key" -out "$dir/server.csr" 2>/dev/null
openssl x509 -req -in "$dir/server.csr" -CA "$dir/ca.pem" -CAkey "$dir/ca.key" -set_serial "0x$(openssl rand -hex 8)" \
  -days 1 -extfile "$dir/req.cnf" -extensions server -out "$dir/server.pem" 2>/dev/null
rm -f "$dir/ca.key" "$dir/server.csr"
openssl verify -CAfile "$dir/ca.pem" "$dir/server.pem" >&2

docker run -d --rm --name "$name" --user "$(id -u):$(id -g)" -p "127.0.0.1:$port:6379" -v "$dir:/tls:ro" \
  redis:7-alpine redis-server --port 0 --tls-port 6379 \
  --tls-cert-file /tls/server.pem --tls-key-file /tls/server.key --tls-ca-cert-file /tls/ca.pem \
  --tls-auth-clients no --requirepass "$password" --save '' --appendonly no >/dev/null

for _ in $(seq 1 30); do
  if docker exec "$name" redis-cli --tls --cacert /tls/ca.pem -h localhost -a "$password" --no-auth-warning ping \
       2>/dev/null | grep -qx PONG; then
    echo "TLS Redis $name answers on 127.0.0.1:$port with a certificate for localhost" >&2
    echo "OIDF_TEST_REDIS_TLS_URL=rediss://:$password@localhost:$port"
    echo "OIDF_TEST_REDIS_CA_FILE=$dir/ca.pem"
    exit 0
  fi
  sleep 1
done
echo "TLS Redis $name did not answer PING over TLS within 30 seconds; its log:" >&2
docker logs "$name" >&2 || true
exit 1
