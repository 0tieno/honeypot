#!/usr/bin/env bash
# Cloud Bait VM provisioning. Run as root on the honeypot VM (Ubuntu 24.04).
# Expects cloudbait_web.py, cowrie.cfg and nginx-cloudbait.conf in the same directory.
set -euo pipefail

ADMIN_PORT="${ADMIN_PORT:-22022}"
HERE="$(cd "$(dirname "$0")" && pwd)"
export DEBIAN_FRONTEND=noninteractive

echo "=== 1. Packages ==="
apt-get update -q
apt-get -y -q -o Dpkg::Options::=--force-confold upgrade
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
apt-get install -y -q git python3-venv python3-dev libssl-dev libffi-dev build-essential \
    authbind nginx iptables-persistent

echo "=== 2. Move real sshd to port ${ADMIN_PORT} ==="
# Ubuntu 24.04 uses socket activation: the listening port lives in ssh.socket, not sshd_config.
mkdir -p /etc/systemd/system/ssh.socket.d
cat > /etc/systemd/system/ssh.socket.d/override.conf <<EOF
[Socket]
ListenStream=
ListenStream=0.0.0.0:${ADMIN_PORT}
ListenStream=[::]:${ADMIN_PORT}
EOF
cat > /etc/ssh/sshd_config.d/10-cloudbait.conf <<EOF
Port ${ADMIN_PORT}
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
EOF
systemctl daemon-reload
systemctl restart ssh.socket
systemctl restart ssh.service || true

echo "=== 3. Cowrie ==="
id cowrie >/dev/null 2>&1 || adduser --disabled-password --gecos "" cowrie
if [ ! -d /home/cowrie/cowrie ]; then
    sudo -u cowrie git clone -q https://github.com/cowrie/cowrie /home/cowrie/cowrie
fi
sudo -u cowrie bash -c '
  cd /home/cowrie/cowrie
  python3 -m venv cowrie-env
  . cowrie-env/bin/activate
  pip install -q --upgrade pip
  if [ -f requirements.txt ]; then pip install -q -r requirements.txt; fi
  pip install -q -e .
'
install -o cowrie -g cowrie -m 0644 "$HERE/cowrie.cfg" /home/cowrie/cowrie/etc/cowrie.cfg
mkdir -p /home/cowrie/cowrie/var/log/cowrie /home/cowrie/cowrie/var/lib/cowrie/downloads /home/cowrie/cowrie/var/lib/cowrie/tty
chown -R cowrie:cowrie /home/cowrie/cowrie/var
# Azure Monitor Agent tails cowrie.json as the "syslog" user; /home/cowrie is 0750.
usermod -aG cowrie syslog

cat > /etc/systemd/system/cowrie.service <<'EOF'
[Unit]
Description=Cowrie SSH/Telnet honeypot
After=network.target

[Service]
Type=simple
User=cowrie
Group=cowrie
WorkingDirectory=/home/cowrie/cowrie
Environment=PYTHONPATH=/home/cowrie/cowrie/src
ExecStart=/home/cowrie/cowrie/cowrie-env/bin/twistd --umask=0022 --nodaemon --pidfile= -l - cowrie
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/home/cowrie/cowrie/var
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now cowrie

echo "=== 4. Redirect 22->2222 and 23->2223 into Cowrie ==="
iptables -t nat -C PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222 2>/dev/null || \
    iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
iptables -t nat -C PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2223 2>/dev/null || \
    iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2223
netfilter-persistent save

echo "=== 5. Fake web app ==="
id cloudbait >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin cloudbait
install -d -o root -g root -m 0755 /opt/cloudbait
install -o root -g root -m 0755 "$HERE/cloudbait_web.py" /opt/cloudbait/cloudbait_web.py
install -d -o cloudbait -g cloudbait -m 0755 /var/log/cloudbait
cat > /etc/systemd/system/cloudbait-web.service <<'EOF'
[Unit]
Description=Cloud Bait fake web application
After=network.target

[Service]
Type=simple
User=cloudbait
Group=cloudbait
Environment=CLOUDBAIT_LOG=/var/log/cloudbait/web.json
ExecStart=/usr/bin/python3 /opt/cloudbait/cloudbait_web.py
Restart=always
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/cloudbait
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now cloudbait-web

echo "=== 6. nginx + self-signed TLS ==="
if [ ! -f /etc/ssl/private/cloudbait.key ]; then
    openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
        -keyout /etc/ssl/private/cloudbait.key -out /etc/ssl/certs/cloudbait.crt \
        -subj "/C=KE/O=Kipeo Digital Services/CN=portal.kipeo.example" 2>/dev/null
fi
install -m 0644 "$HERE/nginx-cloudbait.conf" /etc/nginx/sites-available/cloudbait
ln -sf /etc/nginx/sites-available/cloudbait /etc/nginx/sites-enabled/cloudbait
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable nginx
systemctl reload nginx || systemctl restart nginx

echo "=== 7. Log rotation ==="
cat > /etc/logrotate.d/cloudbait <<'EOF'
/var/log/cloudbait/*.json {
    daily
    rotate 14
    missingok
    notifempty
    copytruncate
    compress
    delaycompress
}
EOF

echo "=== Done ==="
systemctl --no-pager --lines=0 status cowrie cloudbait-web nginx ssh.socket | grep -E '●|Active:'
ss -tlnp | grep -E ':(22022|2222|2223|80|443|8080) '
