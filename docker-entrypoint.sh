#!/bin/bash
# Runs on every container start (not just the first) - each step here must be idempotent.
set -e

cd "$(dirname "$0")"

# 1. TLS cert - flask_files/flask.crt/.key are gitignored (see Phase 0's README note) and
# aren't baked into the image, so generate a self-signed pair if missing. Regenerates on
# every container *recreation* (this directory isn't a mounted volume) but not on a plain
# restart of an existing container.
if [ ! -f flask_files/flask.crt ] || [ ! -f flask_files/flask.key ]; then
    echo "Generating self-signed TLS cert for the Flask app..."
    openssl req -x509 -newkey rsa:4096 -nodes \
        -out flask_files/flask.crt -keyout flask_files/flask.key \
        -days 365 -subj "/CN=localhost"
fi

# 2. Make sure the client-data volume mount point exists. OUTPUT_PATH itself is not
# env-var-driven in enterprise_user_conf.py (it's an in-container path, not a secret) - this
# must match that file's OUTPUT_PATH literal and the docker-compose.yml volume mount below.
mkdir -p /usr/local/clients/

# 3. Idempotent DB/admin-user bootstrap (install.py was reworked in this phase to be safe
# to run on every start - see the Phase 5 plan doc).
python3 install.py

# 4. Hand off to the actual container command (Flask app by default, see Dockerfile CMD).
exec "$@"
