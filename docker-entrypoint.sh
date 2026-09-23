#!/bin/bash
# Runs on every container start (not just the first) - each step here must be idempotent.
set -e

cd "$(dirname "$0")"

# 0. Make the container's LINUX_GROUP (enterprise_user_conf.py, 'staff' by default) resolve to
# a GID the host user is actually a member of, via TE_LINUX_GID. common/common.py's
# assign_permissions() already chmod 774s + chgrp's every engagement folder/file this app
# creates to that group name - the app was already designed for shared group access, it just
# needed the group's GID to line up with something outside the container. The whole app runs
# as root (unchanged - many of the bundled tools assume raw sockets/privileged ports that
# aren't worth re-auditing one by one for non-root compatibility), so this is what makes files
# under the bind-mounted /usr/local/clients readable/writable by the host user without sudo.
# Not fatal if it fails (e.g. the GID collides with an existing group) - permissions just won't
# line up as nicely, which beats refusing to start.
TE_LINUX_GID="${TE_LINUX_GID:-1000}"
if getent group staff >/dev/null 2>&1; then
    groupmod -g "$TE_LINUX_GID" staff || echo "Warning: could not set the 'staff' group's GID to $TE_LINUX_GID (already in use by another group?) - engagement files may not be host-group-readable."
else
    groupadd -g "$TE_LINUX_GID" staff || echo "Warning: could not create the 'staff' group with GID $TE_LINUX_GID - engagement files may not be host-group-readable."
fi

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
chgrp staff /usr/local/clients/ 2>/dev/null || true
chmod 775 /usr/local/clients/ 2>/dev/null || true

# 3. Idempotent DB/admin-user bootstrap (install.py was reworked in this phase to be safe
# to run on every start - see the Phase 5 plan doc).
python3 install.py

# 4. Hand off to the actual container command (Flask app by default, see Dockerfile CMD).
exec "$@"
