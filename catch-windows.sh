#!/usr/bin/env bash
# catch-windows.sh — 记录新出现的窗口(标题/PID/类名)，用于与 events.log 对照。
# 由 catch-auth.sh start 自动启动；也可单独运行。需要 xdotool。
set -u
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="$DIR/windows.log"
LIST="$DIR/.window-ids"
touch "$LIST"
if ! command -v xdotool >/dev/null 2>&1; then
  echo "catch-windows: 需要 xdotool，已跳过"
  exit 1
fi
while :; do
  cur=""
  for wid in $(xdotool search --onlyvisible --name '.*' 2>/dev/null); do
    cur="$cur $wid"
    if ! grep -qw -- "$wid" "$LIST" 2>/dev/null; then
      name=$(xdotool getwindowname "$wid" 2>/dev/null || true)
      pid=$(xdotool getwindowpid "$wid" 2>/dev/null || true)
      class=$(xprop -id "$wid" WM_CLASS 2>/dev/null | sed 's/^[^=]*= *//')
      mark=""
      case "$name" in
        *认证*|*授权*|*鉴权*|*密码*|*验证*|*身份*) mark=" <== 疑似鉴权窗口" ;;
      esac
      printf '[%s] wid=%s pid=%s name=%s class=%s%s\n' \
        "$(date '+%Y-%m-%d %H:%M:%S')" "$wid" "$pid" "$name" "$class" "$mark" >> "$LOG"
    fi
  done
  printf '%s\n' $cur > "$LIST"
  sleep 1
done
