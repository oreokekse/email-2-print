#!/bin/sh
set -e

CUPS_ADMIN_USER="${CUPS_ADMIN_USER:-admin}"
CUPS_ADMIN_PASSWORD="${CUPS_ADMIN_PASSWORD}"

if [ -z "${CUPS_ADMIN_PASSWORD}" ]; then
    echo "CUPS_ADMIN_PASSWORD must not be empty." >&2
    exit 1
fi

echo "Configuring CUPS admin user..."

# Create admin user if missing
if ! id "${CUPS_ADMIN_USER}" >/dev/null 2>&1; then
    echo "Creating CUPS admin user '${CUPS_ADMIN_USER}'..."
    useradd -m "${CUPS_ADMIN_USER}"
else
    echo "CUPS admin user already exists."
fi

# Always (re)set the admin password to the provided value
echo "${CUPS_ADMIN_USER}:${CUPS_ADMIN_PASSWORD}" | chpasswd

# Ensure correct group memberships
# lpadmin → CUPS administrators
# lp → printing permissions
usermod -aG lpadmin "${CUPS_ADMIN_USER}"
usermod -aG lp "${CUPS_ADMIN_USER}"

echo "Admin user configured."

echo "Starting CUPS..."
/usr/sbin/cupsd

sleep 2

echo "Starting email print bot..."
exec python3 /app/app.py
