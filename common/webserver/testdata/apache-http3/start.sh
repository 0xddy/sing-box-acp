#!/bin/sh
set -eu
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout /tmp/reference.key -out /tmp/reference.crt -days 2 \
  -subj /CN=example.com -addext subjectAltName=DNS:example.com >/dev/null 2>&1
exec /opt/httpd/bin/httpd -DFOREGROUND
