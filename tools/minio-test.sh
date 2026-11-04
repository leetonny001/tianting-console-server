#!/usr/bin/env bash
# 启动开启 Object Lock 的 MinIO，建只写和只读两份凭证，跑 TestRealMinIOWORM。CI 里运行。
# MinIO 不再发布公开的镜像和二进制：从固定版本的源码构建，需要 go 和 git。MINIO_BIN_DIR 可以复用构建结果。
set -euo pipefail
WORK="$(mktemp -d)"
BIN="${MINIO_BIN_DIR:-$WORK/bin}"
mkdir -p "$BIN"
build_from_source() { # name repo tag
  [ -x "$BIN/$1" ] && return 0
  git clone -q --depth 1 --branch "$3" "$2" "$WORK/src-$1"
  (cd "$WORK/src-$1" && CGO_ENABLED=0 go build -o "$BIN/$1" .)
}
build_from_source minio https://github.com/minio/minio RELEASE.2025-04-22T22-12-26Z
build_from_source mc https://github.com/minio/mc RELEASE.2025-04-16T18-13-26Z
root_pw=$(openssl rand -hex 16)
writer_pw=$(openssl rand -hex 16)
reader_pw=$(openssl rand -hex 16)
MINIO_ROOT_USER=root MINIO_ROOT_PASSWORD="$root_pw" "$BIN/minio" server --quiet --address 127.0.0.1:19000 "$WORK/data" >/dev/null 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true' EXIT
for _ in $(seq 1 60); do curl -fs http://127.0.0.1:19000/minio/health/live >/dev/null && break; sleep 1; done
export MC_CONFIG_DIR="$WORK/mc"
mc() { "$BIN/mc" "$@"; }
mc alias set --quiet t http://127.0.0.1:19000 root "$root_pw" >/dev/null
mc mb --quiet --with-lock t/anchor >/dev/null
cat >"$WORK/w.json" <<'P'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject","s3:PutObjectRetention"],"Resource":["arn:aws:s3:::anchor/*"]}]}
P
cat >"$WORK/r.json" <<'P'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::anchor","arn:aws:s3:::anchor/*"]}]}
P
mc admin policy create t anchorw "$WORK/w.json" >/dev/null
mc admin policy create t anchorr "$WORK/r.json" >/dev/null
mc admin user add t writer "$writer_pw" >/dev/null
mc admin user add t reader "$reader_pw" >/dev/null
mc admin policy attach t anchorw --user writer >/dev/null
mc admin policy attach t anchorr --user reader >/dev/null
CON_TEST_S3_ENDPOINT=http://127.0.0.1:19000 CON_TEST_S3_BUCKET=anchor \
CON_TEST_S3_WRITER_ACCESS=writer CON_TEST_S3_WRITER_SECRET="$writer_pw" \
CON_TEST_S3_READER_ACCESS=reader CON_TEST_S3_READER_SECRET="$reader_pw" \
go test -count=1 -v -run TestRealMinIOWORM ./e2e/
