#!/usr/bin/env bash
# 启动开启 Object Lock 的 MinIO，建只写和只读两份凭证，跑 TestRealMinIOWORM。需要 docker，CI 里运行。
set -euo pipefail
name=console-minio-test
root_pw=$(openssl rand -hex 16)
writer_pw=$(openssl rand -hex 16)
reader_pw=$(openssl rand -hex 16)
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker run -d --name "$name" -p 19000:9000 -e MINIO_ROOT_USER=root -e MINIO_ROOT_PASSWORD="$root_pw" minio/minio:RELEASE.2025-04-22T22-12-26Z server /data >/dev/null
for _ in $(seq 1 60); do curl -fs http://127.0.0.1:19000/minio/health/live >/dev/null && break; sleep 1; done
mc() { docker run --rm --network "container:$name" --entrypoint sh minio/mc:RELEASE.2025-04-16T18-13-26Z -c "mc alias set t http://127.0.0.1:9000 root $root_pw >/dev/null && $1"; }
mc "mc mb --with-lock t/anchor"
mc "cat > /tmp/w.json <<'P'
{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:PutObject\",\"s3:PutObjectRetention\"],\"Resource\":[\"arn:aws:s3:::anchor/*\"]}]}
P
cat > /tmp/r.json <<'P'
{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\",\"s3:ListBucket\"],\"Resource\":[\"arn:aws:s3:::anchor\",\"arn:aws:s3:::anchor/*\"]}]}
P
mc admin policy create t anchorw /tmp/w.json && mc admin policy create t anchorr /tmp/r.json &&
mc admin user add t writer $writer_pw && mc admin user add t reader $reader_pw &&
mc admin policy attach t anchorw --user writer && mc admin policy attach t anchorr --user reader"
CON_TEST_S3_ENDPOINT=http://127.0.0.1:19000 CON_TEST_S3_BUCKET=anchor \
CON_TEST_S3_WRITER_ACCESS=writer CON_TEST_S3_WRITER_SECRET="$writer_pw" \
CON_TEST_S3_READER_ACCESS=reader CON_TEST_S3_READER_SECRET="$reader_pw" \
go test -count=1 -v -run TestRealMinIOWORM ./e2e/
