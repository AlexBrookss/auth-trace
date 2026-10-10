#!/usr/bin/env bash
# install.sh — 安装 auth-trace 持久化监听服务（开机/登录自启）
#
#   sudo ./install.sh           完整安装: 系统总线服务 + 用户会话服务 + 取证命令
#   ./install.sh --user-only    仅安装当前用户的会话监听服务（无需 root，
#                               适合先体验；完整功能请用 sudo 运行）
set -u
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE="full"
if [ "${1:-}" = "--user-only" ]; then MODE="user-only"; fi

write_user_unit() {
  # $1=用户名 $2=auth_monitor.py 路径 $3=日志目录
  local user="$1" pyexec="$2" logdir="$3"
  local home uid unitdir
  home="$(getent passwd "$user" | cut -d: -f6)"
  uid="$(id -u "$user")"
  unitdir="$home/.config/systemd/user"
  mkdir -p "$unitdir/default.target.wants" "$logdir"
  cat > "$unitdir/auth-trace-session.service" <<EOF
[Unit]
Description=auth-trace: 会话总线鉴权事件持久化监听
After=dbus.socket

[Service]
Type=simple
Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=%t/bus
ExecStart=/usr/bin/python3 $pyexec --service-session --dir $logdir --windows
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
EOF
  ln -sf ../auth-trace-session.service "$unitdir/default.target.wants/auth-trace-session.service"
  if [ "$(id -u)" = "0" ]; then
    chown -R "$user":"$user" "$unitdir" "$logdir"
    if [ -d "/run/user/$uid" ]; then
      runuser -u "$user" -- env XDG_RUNTIME_DIR="/run/user/$uid" systemctl --user daemon-reload 2>/dev/null || true
      runuser -u "$user" -- env XDG_RUNTIME_DIR="/run/user/$uid" systemctl --user restart auth-trace-session.service 2>/dev/null || true
    fi
  else
    systemctl --user daemon-reload 2>/dev/null || true
    systemctl --user restart auth-trace-session.service 2>/dev/null || true
  fi
}

if [ "$MODE" = "user-only" ]; then
  write_user_unit "$(id -un)" "$DIR/auth_monitor.py" "$HOME/.local/state/auth-trace"
  echo "已安装并启动用户会话监听服务: auth-trace-session.service"
  echo "日志目录: $HOME/.local/state/auth-trace"
  echo "查看状态: systemctl --user status auth-trace-session.service"
  exit 0
fi

[ "$(id -u)" = "0" ] || { echo "完整安装需要 root: sudo $0"; exit 1; }

echo "==> 安装文件到 /opt/auth-trace"
mkdir -p /opt/auth-trace /var/log/auth-trace/reports
install -m 644 "$DIR/auth_monitor.py" /opt/auth-trace/auth_monitor.py
install -m 644 "$DIR/auth-trace-report.py" /opt/auth-trace/auth-trace-report.py
[ -f "$DIR/README.md" ] && install -m 644 "$DIR/README.md" /opt/auth-trace/README.md

echo "==> 安装取证命令 /usr/local/bin/auth-trace-report"
cat > /usr/local/bin/auth-trace-report <<'EOF'
#!/usr/bin/env bash
exec /usr/bin/python3 /opt/auth-trace/auth-trace-report.py "$@"
EOF
chmod 755 /usr/local/bin/auth-trace-report

echo "==> 安装系统总线服务 auth-trace-system.service"
cat > /etc/systemd/system/auth-trace-system.service <<'EOF'
[Unit]
Description=auth-trace: 系统总线鉴权事件持久化监听 (polkit/deepin-authenticate 等)
After=dbus.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/auth-trace/auth_monitor.py --system --dir /var/log/auth-trace
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now auth-trace-system.service

U="${SUDO_USER:-}"
if [ -z "$U" ]; then
  U="$(loginctl list-users --no-legend 2>/dev/null | awk '{print $2}' | head -n1)"
fi
if [ -n "$U" ] && id "$U" >/dev/null 2>&1; then
  echo "==> 安装用户会话服务 (用户: $U)"
  write_user_unit "$U" "/opt/auth-trace/auth_monitor.py" \
    "$(getent passwd "$U" | cut -d: -f6)/.local/state/auth-trace"
else
  echo "!! 未识别当前桌面用户，请以该用户重新执行: $0 --user-only"
fi

if [ ! -d /var/log/journal ]; then
  echo "==> 开启 journald 持久化存储"
  mkdir -p /var/log/journal
  systemd-tmpfiles --create --prefix /var/log/journal 2>/dev/null || true
  systemctl restart systemd-journald 2>/dev/null || true
fi

echo
echo "==> 服务状态"
systemctl is-active auth-trace-system.service 2>/dev/null || true
systemctl show auth-trace-system.service -p ActiveState -p SubState -p MainPID --no-pager 2>/dev/null || true
echo
echo "完成。"
echo "  实时查看捕获: tail -f /var/log/auth-trace/events.log"
echo "  会话总线日志: tail -f ~/.local/state/auth-trace/events.log"
echo "  候选动作示意: 把 15:20 换成复现时间"
echo "      sudo auth-trace-report \"15:20\""
