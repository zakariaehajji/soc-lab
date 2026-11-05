# UNLOCK for Cursor automation — paste in IDS root terminal
# 1) If you are inside a cat/EOF heredoc, press Ctrl+C first
# 2) Paste everything below:

systemctl enable --now ssh
mkdir -p /root/.ssh && chmod 700 /root/.ssh
grep -qxF 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDSqUeZbiz9ZVh4J4iRkf7bZw+zsNxA7xkprFlhx2QPR pc-lab-admin' /root/.ssh/authorized_keys 2>/dev/null || echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDSqUeZbiz9ZVh4J4iRkf7bZw+zsNxA7xkprFlhx2QPR pc-lab-admin' >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
# Ensure full config is restored (not the incomplete minimal heredoc)
if [ -f /root/ossec.conf.before-minimal-test ]; then
  cp -a /root/ossec.conf.before-minimal-test /var/ossec/etc/ossec.conf
  chown root:wazuh /var/ossec/etc/ossec.conf
  chmod 640 /var/ossec/etc/ossec.conf
fi
ss -lntp | grep -E ':22\s' || true
ip -4 -o addr show | awk '{print $2,$4}'
echo UNLOCK_OK