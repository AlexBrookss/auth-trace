#!/usr/bin/env bash
# uninstall.sh — 卸载 auth-trace 服务（保留历史日志/证据）
set -u
[ "$(id -u)" = "0" ] || { echo "需要 root: sudo $0"; exit 1; }

echo "==> 停止并移除系统服务"
systemctl disable --now auth-trace-system.service 2>/dev/null || true
rm -f /etc/systemd/system/auth-trace-system.service
systemctl daemon-reload 2>/dev/null || true

U="${SUDO_USER:-}"
if [ -z "$U" ]; then
  U="$(loginctl list-users --no-legend 2>/dev/null | awk '{print $2}' | head -n1)"
fi
if [ -n "$U" ] && id "$U" >/dev/null 2>&1; then
  home="$(getent passwd "$U" | cut -d: -f6)"
  uid="$(id -u "$U")"
  echo "==> 停止并移除用户服务 ($U)"
  if [ -d "/run/user/$uid" ] && command -v runuser >/dev/null 2>&1; then
    runuser -u "$U" -- env XDG_RUNTIME_DIR="/run/user/$uid" systemctl --user disable --now auth-trace-session.service 2>/dev/null || true
  fi
  rm -f "$home/.config/systemd/user/auth-trace-session.service" \
        "$home/.config/systemd/user/default.target.wants/auth-trace-session.service"
fi

rm -f /usr/local/bin/auth-trace-report
rm -rf /opt/auth-trace

echo "已卸载。"
echo "证据日志予以保留: /var/log/auth-trace/  和  ~/.local/state/auth-trace/"
