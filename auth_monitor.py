#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""auth_monitor.py — “鉴权弹窗”调用方蹲点监听器（UOS/DDE）

用途
====
桌面偶尔弹出鉴权/认证窗口，但不知道是哪个程序、调用了什么接口时，
把本监听器挂在后台。弹窗出现后，events.log 中会记录：

  - 调用方进程: pid / uid / exe / cmdline / systemd unit(cgroup)
  - D-Bus 调用: 目标服务、接口、方法、polkit action id
  - 完整原始报文: raw.log

覆盖的典型“弹窗”来源（UOS 20）:
  - polkit:            org.freedesktop.PolicyKit1  (agent: dde-polkit-agent)
  - deepin 认证框架:   com.deepin.daemon.Authenticate (deepin-authenticate)
  - dde PAM 授权:      com.deepin.daemon.Authority (dde-authority)
  - UDCP/安全管控:     com.deepin.udcp.* (auth-dialog 等)
  - 权限管理:          org.deepin.PermissionManager*

系统总线（polkit 等）需要 root —— 主进程会通过 sudo 自动拉起系统总线子进程；
会话总线不需要 root。

持久化用法（开机自启，推荐）: 由 install.sh 安装 systemd 服务
  - 系统总线: root 服务 auth-trace-system.service  → /var/log/auth-trace/
  - 会话总线: 用户服务 auth-trace-session.service → ~/.local/state/auth-trace/
事后按复现时间取证: sudo auth-trace-report "15:20"

手动临时用法: ./catch-auth.sh start / show / follow / stop / selftest
直接运行方式:
  python3 auth_monitor.py                       # 手动: 会话总线 + 拉起系统总线监听
  sudo python3 auth_monitor.py --system         # 系统总线子进程
  python3 auth_monitor.py --service-session --dir DIR --windows   # 用户服务模式
"""
import datetime
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time


# ---------------------------------------------------------------------------
# 参数与配置
# ---------------------------------------------------------------------------

def parse_args(argv):
    cfg = {'system': False, 'service_session': False, 'windows': False,
           'dir': None, 'test': False}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == '--system':
            cfg['system'] = True
        elif a == '--service-session':
            cfg['service_session'] = True
        elif a == '--windows':
            cfg['windows'] = True
        elif a == '--test':
            cfg['test'] = True
        elif a == '--dir' and i + 1 < len(argv):
            cfg['dir'] = argv[i + 1]
            i += 1
        i += 1
    return cfg


CFG = parse_args(sys.argv[1:])
BASE = (CFG['dir'] or os.environ.get('AUTH_TRACE_DIR')
        or os.path.dirname(os.path.abspath(__file__)))
EVENTS = os.path.join(BASE, 'events.log')
RAW = os.path.join(BASE, 'raw.log')
TEST = CFG['test'] or os.environ.get('AUTH_TRACE_TEST') == '1'
NO_SYSTEM = os.environ.get('AUTH_TRACE_NO_SYSTEM') == '1'
WINDOWS = CFG['windows']
MAX_LOG_BYTES = 20 * 1024 * 1024

# 关注的服务名 / 接口关键字（大小写不敏感）
KEY_RE = re.compile(r'(?i)(auth|policykit|polkit|permission|udcp|authority|passwd|defender|security)')
# 明确排除的无关噪音
EXCLUDE_RE = re.compile(r'(impl\.portal\.PermissionStore|^org\.freedesktop\.DBus$)')
# 方法名关键字（兜底：服务名没覆盖到但方法很可疑时也记录）
HIT_MEMBER_RE = re.compile(r'(?i)(authoriz|authenticat|checkauth|password|passwd|verify|grant|preauth)')

HEADER_RE = re.compile(r'^(method call|signal|method return|error)\s+time=([0-9.]+)\s+(.*)$')
DOTTED_RE = re.compile(r'string "([A-Za-z][A-Za-z0-9_]*\.[A-Za-z0-9_.\-]+)"')

SYS_SERVICE_DIRS = ['/usr/share/dbus-1/system-services', '/etc/dbus-1/system-services']
SES_SERVICE_DIRS = ['/usr/share/dbus-1/services', '/etc/dbus-1/services',
                    os.path.expanduser('~/.local/share/dbus-1/services')]

CHILDREN = []  # [(Popen, kind)] kind: '--session' / '--system' / 'system-child'


# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------

def ts():
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]


def ensure_dir():
    try:
        os.makedirs(BASE, exist_ok=True)
    except OSError:
        pass
    for p in (EVENTS, RAW):
        try:
            with open(p, 'a'):
                pass
        except OSError:
            pass


def _append(path, text):
    """追加写文件；超过上限时轮转为 .1（保留一代，防止无限增长）。"""
    try:
        if os.path.exists(path) and os.path.getsize(path) > MAX_LOG_BYTES:
            try:
                os.remove(path + '.1')
            except OSError:
                pass
            try:
                os.rename(path, path + '.1')
            except OSError:
                pass
        with open(path, 'a', encoding='utf-8', errors='replace') as f:
            f.write(text)
    except OSError:
        pass


def note(text):
    """只打印到 stdout（systemd 服务下进 journal），不写事件日志。"""
    print('[%s] %s' % (ts(), text), flush=True)


def emit(text):
    """事件日志 + 控制台（控制台输出便于排错）。"""
    line = '[%s] %s' % (ts(), text)
    _append(EVENTS, line + '\n')
    print(line, flush=True)


def append_raw(text):
    _append(RAW, text + '\n')


def flat(text):
    return re.sub(r'\s+', ' ', text).strip()


def rx(pattern, text, group=1):
    m = re.search(pattern, text)
    return m.group(group) if m else ''


def bus_call(bus, *args):
    """bus 为 '--system' / '--session'（内部映射为 busctl 的 --user）"""
    if bus == '--session':
        bus = '--user'
    cmd = ['busctl', bus] + list(args)
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           timeout=5, text=True)
        return r.stdout.strip()
    except Exception:
        return ''


def resolve_pid(bus, name):
    if not name:
        return ''
    out = bus_call(bus, 'call', 'org.freedesktop.DBus', '/org/freedesktop/DBus',
                   'org.freedesktop.DBus', 'GetConnectionUnixProcessID', 's', name)
    return rx(r'\bu\s+(\d+)\b', out)


def resolve_user(bus, name):
    if not name:
        return ''
    out = bus_call(bus, 'call', 'org.freedesktop.DBus', '/org/freedesktop/DBus',
                   'org.freedesktop.DBus', 'GetConnectionUnixUser', 's', name)
    return rx(r'\bu\s+(\d+)\b', out)


def unit_from_cgroup(cg):
    if not cg:
        return ''
    hits = re.findall(r'([A-Za-z0-9_@.:\-]+\.(?:service|scope|slice))', cg)
    return hits[-1] if hits else ''


def proc_info(pid):
    res = {'exe': '', 'cmd': '', 'unit': ''}
    if not pid:
        return res
    try:
        data = open('/proc/%s/cmdline' % pid, 'rb').read().decode('utf-8', 'replace')
        res['cmd'] = data.replace('\0', ' ').strip()
    except Exception:
        pass
    try:
        res['exe'] = os.readlink('/proc/%s/exe' % pid)
    except Exception:
        pass
    try:
        lines = open('/proc/%s/cgroup' % pid).read().splitlines()
        best = max(lines, key=len) if lines else ''
        res['unit'] = unit_from_cgroup(best)
    except Exception:
        pass
    return res


# ---------------------------------------------------------------------------
# 服务名发现
# ---------------------------------------------------------------------------

def discover_names(bus):
    names = set()
    out = bus_call(bus, 'list', '--no-legend', '--no-pager')
    for ln in out.splitlines():
        parts = ln.split()
        if parts and KEY_RE.search(parts[0]) and not EXCLUDE_RE.search(parts[0]):
            names.add(parts[0])
    return names


def service_file_names(dirs):
    names = set()
    for d in dirs:
        try:
            files = os.listdir(d)
        except OSError:
            continue
        for fn in files:
            if not fn.endswith('.service'):
                continue
            try:
                txt = open(os.path.join(d, fn), encoding='utf-8', errors='replace').read()
            except OSError:
                continue
            m = re.search(r'^Name=(\S+)', txt, re.M)
            if m and KEY_RE.search(m.group(1)) and not EXCLUDE_RE.search(m.group(1)):
                names.add(m.group(1))
    return names


# ---------------------------------------------------------------------------
# dbus-monitor 报文解析
# ---------------------------------------------------------------------------

def stream_blocks(stream):
    """把 dbus-monitor 的流式输出切成一条条消息块。"""
    cur = None
    for raw in stream:
        line = raw.rstrip('\n')
        m = HEADER_RE.match(line)
        if m:
            if cur is not None:
                yield cur
            cur = {'kind': m.group(1), 'time': float(m.group(2)),
                   'header': line, 'body': []}
        elif cur is not None:
            if line and line[0] in ' \t':
                cur['body'].append(line)
            elif line == '':
                continue
            else:
                yield cur
                cur = None
    if cur is not None:
        yield cur


def hfield(header, field):
    return rx(r'(?:^|\s)' + field + r'=([^\s;]+)', header)


def analyze(blk):
    h = blk['header']
    info = {
        'kind': 'CALL',
        'iface': hfield(h, 'interface'),
        'member': hfield(h, 'member'),
        'sender': hfield(h, 'sender'),
        'dest': hfield(h, 'destination'),
        'action': '',
        'pid': '',
        'uid': '',
    }
    body = flat('\n'.join(blk['body']))
    if info['iface'] == 'org.freedesktop.PolicyKit1.Authority' and info['member'].startswith('Check'):
        info['kind'] = 'POLKIT-CHECK'
        info['pid'] = rx(r'string "pid" variant (?:\w+ )?(\d+)', body)
        info['uid'] = rx(r'string "uid" variant (?:\w+ )?(\d+)', body)
        info['action'] = first_action(body)
    elif info['member'] == 'BeginAuthentication':
        info['kind'] = 'POLKIT-DIALOG'
        info['action'] = first_action(body)
    return info


def first_action(flat_body):
    m = DOTTED_RE.search(flat_body)
    return m.group(1) if m else ''


# ---------------------------------------------------------------------------
# 事件处理
# ---------------------------------------------------------------------------

def handle_block(blk, bus):
    if blk['kind'] != 'method call':
        return
    inf = analyze(blk)
    interesting = (
        inf['iface'].startswith('org.freedesktop.PolicyKit1')
        or KEY_RE.search(inf['dest'])
        or KEY_RE.search(inf['iface'])
        or HIT_MEMBER_RE.search(inf['member'])
    )
    if TEST and inf['dest'] == 'org.freedesktop.DBus' and inf['member'] == 'NameHasOwner':
        interesting = True
    if not interesting:
        return

    pid = inf['pid']
    uid = inf['uid']
    if not pid and inf['sender']:
        pid = resolve_pid(bus, inf['sender'])
    if not uid and pid:
        uid = resolve_user(bus, pid)
    pinfo = proc_info(pid)

    parts = ['[%s]' % ts(), inf['kind'], 'bus=%s' % ('SYS' if bus == '--system' else 'SES')]
    if inf['action']:
        parts.append('action=%s' % inf['action'])
    parts.append('member=%s' % inf['member'])
    parts.append('sender=%s' % inf['sender'])
    if inf['dest']:
        parts.append('dest=%s' % inf['dest'])
    if pid:
        parts.append('pid=%s' % pid)
    if uid:
        parts.append('uid=%s' % uid)
    if pinfo['exe']:
        parts.append('exe=%s' % pinfo['exe'])
    if pinfo['cmd']:
        parts.append('cmd="%s"' % pinfo['cmd'].replace('"', "'")[:400])
    if pinfo['unit']:
        parts.append('unit=%s' % pinfo['unit'])
    line = ' '.join(parts)
    _append(EVENTS, line + '\n')
    print(line, flush=True)

    rawtext = blk['header'] + ('\n' + '\n'.join(blk['body']) if blk['body'] else '')
    append_raw('===== %s =====\n%s' % (line, rawtext))


# ---------------------------------------------------------------------------
# 监听循环与进程管理
# ---------------------------------------------------------------------------

STDBUF = shutil.which('stdbuf')


def monitor_loop(bus, rules):
    # 注意: dbus-monitor 输出到管道时是全缓冲的，必须用 stdbuf 改成行缓冲，
    # 否则事件会卡在缓冲区里，直到进程退出才可见。
    cmd = (([STDBUF, '-oL', '-eL'] if STDBUF else []) + ['dbus-monitor', bus] + rules)
    errname = 'system-monitor.err' if bus == '--system' else 'session-monitor.err'
    try:
        errf = open(os.path.join(BASE, errname), 'ab', buffering=0)
    except OSError:
        errf = subprocess.DEVNULL
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=errf,
                         text=True, bufsize=1, errors='replace')
    CHILDREN.append((p, bus))
    emit('[monitor] %s 总线监听已启动 pid=%d rules=%d' % (bus, p.pid, len(rules)))
    rc = 0
    try:
        for blk in stream_blocks(p.stdout):
            try:
                handle_block(blk, bus)
            except Exception as e:
                emit('[monitor] 解析异常: %r' % (e,))
    finally:
        rc = p.wait()
    emit('[monitor] %s 总线监听退出 rc=%s' % (bus, rc))
    return rc


def run_monitor_with_retry(bus, rules):
    while True:
        rc = monitor_loop(bus, rules)
        note('[monitor] %s 监听退出 rc=%s，5 秒后重试' % (bus, rc))
        time.sleep(5)


def window_watcher():
    """轮询新出现的窗口（标题/PID/类名），写入 windows.log。"""
    seen = set()
    primed = False
    warned = False
    env = os.environ.copy()
    if not env.get('DISPLAY'):
        env['DISPLAY'] = ':0'
    while True:
        try:
            r = subprocess.run(['xdotool', 'search', '--onlyvisible', '--name', '.*'],
                               capture_output=True, text=True, timeout=15, env=env)
            if r.returncode not in (0, 1):
                raise RuntimeError((r.stderr or '').strip()[:200] or ('rc=%s' % r.returncode))
            cur = set(r.stdout.split())
            if not primed:
                seen = cur
                primed = True
                note('[monitor] 窗口监听基线完成(已有窗口 %d 个)' % len(cur))
            else:
                for wid in sorted(cur - seen):
                    name = subprocess.run(['xdotool', 'getwindowname', wid],
                                          capture_output=True, text=True, timeout=5,
                                          env=env).stdout.strip()
                    pid = subprocess.run(['xdotool', 'getwindowpid', wid],
                                         capture_output=True, text=True, timeout=5,
                                         env=env).stdout.strip()
                    if not name and not pid:
                        continue
                    cls = subprocess.run(['xprop', '-id', wid, 'WM_CLASS'],
                                         capture_output=True, text=True, timeout=5,
                                         env=env).stdout.strip()
                    if 'not found' in cls:
                        cls = ''
                    mark = ' <== 疑似鉴权窗口' if re.search('认证|授权|鉴权|密码|验证|身份', name) else ''
                    _append(os.path.join(BASE, 'windows.log'),
                            '[%s] wid=%s pid=%s name=%s class=%s%s\n'
                            % (ts(), wid, pid, name, cls, mark))
                seen = cur
            if warned:
                note('[monitor] 窗口监听已恢复')
                warned = False
        except Exception as e:
            if not warned:
                note('[monitor] 窗口监听未就绪(稍后重试): %r' % (e,))
                warned = True
        time.sleep(1)


def maybe_start_windows():
    if not WINDOWS:
        return
    if not shutil.which('xdotool'):
        note('[monitor] 未找到 xdotool，跳过窗口监听')
        return
    threading.Thread(target=window_watcher, name='window-watcher', daemon=True).start()
    note('[monitor] 窗口监听已启动')


def system_supervisor():
    fails = 0
    while True:
        cmd = ['sudo', '-n', sys.executable, os.path.abspath(__file__), '--system', '--dir', BASE]
        if TEST:
            cmd.append('--test')
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            emit('[monitor] 无法启动系统总线监听: %r' % (e,))
            time.sleep(60)
            continue
        CHILDREN.append((p, 'system-child'))
        rc = p.wait()
        try:
            CHILDREN.remove((p, 'system-child'))
        except ValueError:
            pass
        if rc == 0:
            emit('[monitor] 系统总线监听子进程正常退出，不再重启')
            return
        fails += 1
        if fails <= 2 or fails % 10 == 0:
            emit('[monitor] 系统总线子进程退出 rc=%s（第 %d 次）。'
                 '若因 sudo 未授权，请重新执行 sudo -v 或重启本工具；60 秒后重试。' % (rc, fails))
        time.sleep(60)


def shutdown(signum, frame):
    for p, kind in list(CHILDREN):
        try:
            if kind == 'system-child':
                subprocess.run(['sudo', '-n', 'kill', str(p.pid)], timeout=5,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                p.terminate()
        except Exception:
            pass
    time.sleep(0.15)
    os._exit(0)


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def run_system_side():
    names = discover_names('--system') | service_file_names(SYS_SERVICE_DIRS)
    names = {n for n in names if not EXCLUDE_RE.search(n)}
    rules = ["type='method_call',interface='org.freedesktop.PolicyKit1.Authority'",
             "type='method_call',interface='org.freedesktop.PolicyKit1.AuthenticationAgent'"]
    rules += ["type='method_call',destination='%s'" % n for n in sorted(names)]
    if TEST:
        rules.append("type='method_call',destination='org.freedesktop.DBus'")
    emit('[monitor] 系统总线覆盖服务(%d): %s' % (len(names), ', '.join(sorted(names))))
    run_monitor_with_retry('--system', rules)


def run_main_side():
    ensure_dir()
    emit('')
    emit('[monitor] ===== auth-trace 启动 =====')
    emit('[monitor] 提示: 弹窗出现后看 events.log 最新几行；'
         'POLKIT-DIALOG=polkit弹窗触发, POLKIT-CHECK=鉴权请求, CALL=其他鉴权服务调用')

    sess_names = discover_names('--user') | service_file_names(SES_SERVICE_DIRS)
    sess_names = {n for n in sess_names if not EXCLUDE_RE.search(n)}
    sess_rules = ["type='method_call',interface='org.freedesktop.PolicyKit1.AuthenticationAgent'"]
    sess_rules += ["type='method_call',destination='%s'" % n for n in sorted(sess_names)]
    if TEST:
        sess_rules.append("type='method_call',destination='org.freedesktop.DBus'")
    emit('[monitor] 会话总线覆盖服务(%d): %s' % (len(sess_names), ', '.join(sorted(sess_names))))

    if NO_SYSTEM:
        emit('[monitor] 按要求跳过系统总线监听 (AUTH_TRACE_NO_SYSTEM=1)')
    else:
        threading.Thread(target=system_supervisor, name='sys-supervisor', daemon=True).start()

    maybe_start_windows()
    run_monitor_with_retry('--session', sess_rules)


def run_service_session():
    """systemd 用户服务模式: 会话总线 + 窗口监听（不拉系统总线子进程）。"""
    ensure_dir()
    emit('[monitor] ===== auth-trace 服务(会话总线)启动 =====')
    sess_names = discover_names('--user') | service_file_names(SES_SERVICE_DIRS)
    sess_names = {n for n in sess_names if not EXCLUDE_RE.search(n)}
    sess_rules = ["type='method_call',interface='org.freedesktop.PolicyKit1.AuthenticationAgent'"]
    sess_rules += ["type='method_call',destination='%s'" % n for n in sorted(sess_names)]
    if TEST:
        sess_rules.append("type='method_call',destination='org.freedesktop.DBus'")
    emit('[monitor] 会话总线覆盖服务(%d): %s' % (len(sess_names), ', '.join(sorted(sess_names))))
    maybe_start_windows()
    run_monitor_with_retry('--session', sess_rules)


def main():
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    if CFG['service_session']:
        run_service_session()
    elif CFG['system']:
        run_system_side()
    else:
        run_main_side()


if __name__ == '__main__':
    main()
