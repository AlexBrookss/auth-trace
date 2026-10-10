#!/usr/bin/env bash
# catch-auth.sh — 桌面“鉴权弹窗”调用方捕捉工具（UOS/DDE）
# 用法见 ./catch-auth.sh help
set -u
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIDFILE="$DIR/monitor.pid"
WINPIDFILE="$DIR/windows.pid"

usage() {
  cat <<'EOF'
用法: ./catch-auth.sh <命令>

  start      启动监听(后台运行; 系统总线部分需要输入一次 sudo 密码)
  stop       停止监听
  status     查看运行状态与最近事件
  show [N]   查看最近 N 条捕获事件(默认 40)
  raw [N]    查看最近 N 条原始 D-Bus 报文(默认 120)
  follow     实时跟踪捕获事件(Ctrl+C 退出)
  selftest   自检: 发一条无害的 polkit 查询，验证系统总线监听链路
  help       显示本帮助
EOF
}

running() { [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; }

case "${1:-help}" in
  start)
    if running; then
      echo "已在运行 (PID $(cat "$PIDFILE"))。查看: $0 show"
      exit 0
    fi
    touch "$DIR/events.log" "$DIR/raw.log"
    if ! sudo -n true 2>/dev/null; then
      echo ">>> 监听系统总线(polkit / deepin-authenticate 等)需要 sudo 权限。"
      echo ">>> 如提示密码，请输入当前用户密码（仅用于启动监听，之后不再需要）:"
      if ! sudo -v; then
        echo ">>> 警告: 未获得 sudo，将只监听会话总线(udcp auth-dialog、权限管理等)。"
      fi
    fi
    nohup python3 "$DIR/auth_monitor.py" >>"$DIR/monitor.out" 2>&1 &
    echo $! > "$PIDFILE"
    sleep 1
    if ! running; then
      echo "启动失败，请查看 $DIR/monitor.out" >&2
      exit 1
    fi
    echo "已启动 (PID $(cat "$PIDFILE"))"
    if command -v xdotool >/dev/null 2>&1; then
      nohup bash "$DIR/catch-windows.sh" >>"$DIR/monitor.out" 2>&1 &
      echo $! > "$WINPIDFILE"
    fi
    echo "事件日志: $DIR/events.log"
    echo "复现鉴权窗后执行: $0 show"
    ;;
  stop)
    if running; then kill "$(cat "$PIDFILE")" 2>/dev/null; fi
    [ -f "$WINPIDFILE" ] && kill "$(cat "$WINPIDFILE")" 2>/dev/null
    sleep 0.5
    pkill -f "auth_monitor\.py --system" 2>/dev/null || true
    sudo pkill -f "auth_monitor\.py --system" 2>/dev/null || true
    sudo pkill -f "dbus-monitor --system .*org.freedesktop.PolicyKit1" 2>/dev/null || true
    pkill -f "dbus-monitor --session .*org.freedesktop.PolicyKit1.AuthenticationAgent" 2>/dev/null || true
    pkill -f "catch-windows.sh" 2>/dev/null || true
    rm -f "$PIDFILE" "$WINPIDFILE"
    echo "已停止"
    ;;
  status)
    if running; then
      echo "运行中 (PID $(cat "$PIDFILE"))"
      pgrep -af "dbus-monitor --(system|session)" 2>/dev/null || true
      echo "--- 最近事件 ---"
      tail -n 5 "$DIR/events.log" 2>/dev/null || true
    else
      echo "未运行"
    fi
    ;;
  show) tail -n "${2:-40}" "$DIR/events.log" 2>/dev/null ;;
  raw) tail -n "${2:-120}" "$DIR/raw.log" 2>/dev/null ;;
  follow) tail -f "$DIR/events.log" ;;
  selftest)
    n0=0
    n1=0
    if [ -f "$DIR/events.log" ]; then n0=$(grep -c 'member=EnumerateActions' "$DIR/events.log" 2>/dev/null) || true; fi
    case "${n0:-}" in ''|*[!0-9]*) n0=0 ;; esac
    pkaction --verbose >/dev/null 2>&1 || true
    sleep 1.5
    if [ -f "$DIR/events.log" ]; then n1=$(grep -c 'member=EnumerateActions' "$DIR/events.log" 2>/dev/null) || true; fi
    case "${n1:-}" in ''|*[!0-9]*) n1=0 ;; esac
    if [ "$n1" -gt "$n0" ]; then
      echo "自检通过: 系统总线监听链路工作正常。"
    else
      echo "未捕获到自检请求: 可能监听未启动，或没有 sudo 权限(系统总线监听不可用)。"
      echo "会话总线部分不依赖 sudo，仍可能有效。"
    fi
    ;;
  help|*)
    usage
    ;;
esac
