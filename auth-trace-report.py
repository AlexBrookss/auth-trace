#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""auth-trace-report.py — 按“复现时间”生成鉴权问题证据包

用法:
    sudo auth-trace-report "15:20"
    sudo auth-trace-report "2026-10-10 15:20:30" -w 5

证据来源:
    - auth-trace 服务捕获的 D-Bus 鉴权事件（系统总线 + 会话总线）与窗口记录
    - journald 中与鉴权相关的日志行
    - 事件涉及进程(pid)的 journal 上下文
    - 对应时段的原始 D-Bus 报文（仅写入报告文件）

输出:
    - 控制台: 证据摘要与判读提示
    - 报告文件: /var/log/auth-trace/reports/auth-trace-report-*.txt（root 运行时）
                否则输出到当前目录
"""
import argparse
import datetime
import glob
import os
import re
import subprocess
import sys

TS_RE = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})')
PID_RE = re.compile(r'\bpid=(\d+)\b')
JOURNAL_KEY_RE = re.compile(
    r'(?i)(polkit|dde-polkit|authent|authority|udcp|auth-dialog|permission|passwd|sudo|pam_|认证|鉴权|授权)')
SYS_DIR = '/var/log/auth-trace'


def parse_time(s):
    s = s.strip()
    now = datetime.datetime.now()
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M'):
        try:
            return datetime.datetime.strptime(s, fmt)
        except ValueError:
            pass
    for fmt in ('%H:%M:%S', '%H:%M'):
        try:
            t = datetime.datetime.strptime(s, fmt)
            return now.replace(hour=t.hour, minute=t.minute, second=t.second, microsecond=0)
        except ValueError:
            pass
    raise SystemExit('无法解析时间 %r；支持: "15:20" / "15:20:30" / "2026-10-10 15:20[:30]"' % s)


def collect_lines(path, since_s, until_s, limit=3000):
    out = []
    try:
        with open(path, 'r', errors='replace') as f:
            for line in f:
                m = TS_RE.search(line[:60])
                if m and since_s <= m.group(1) <= until_s:
                    out.append(line.rstrip())
                    if len(out) >= limit:
                        break
    except OSError:
        pass
    return out


def collect_raw(path, since_s, until_s, limit=200):
    blocks = []
    cur = None
    try:
        with open(path, 'r', errors='replace') as f:
            for line in f:
                if line.startswith('====='):
                    if cur is not None:
                        blocks.append(cur)
                    m = TS_RE.search(line[:80])
                    cur = {'ts': m.group(1) if m else '', 'lines': [line.rstrip()]}
                elif cur is not None and len(cur['lines']) < 300:
                    cur['lines'].append(line.rstrip())
        if cur is not None:
            blocks.append(cur)
    except OSError:
        pass
    return [b for b in blocks if b['ts'] and since_s <= b['ts'] <= until_s][:limit]


def user_log_dirs():
    dirs = []
    cands = glob.glob('/home/*/.local/state/auth-trace')
    home = os.environ.get('HOME', '')
    if home:
        cands.append(os.path.join(home, '.local/state/auth-trace'))
    for d in cands:
        if os.path.isdir(d) and d not in dirs:
            dirs.append(d)
    return dirs


def run_journal(since_s, until_s):
    try:
        r = subprocess.run(['journalctl', '--since', since_s, '--until', until_s,
                            '-o', 'short-iso-precise', '--no-pager'],
                           capture_output=True, text=True, timeout=180)
    except Exception as e:
        return [], '调用 journalctl 失败: %r' % (e,)
    if r.returncode != 0:
        return [], (r.stderr or 'journalctl 退出码 %s' % r.returncode).strip()
    return r.stdout.splitlines(), ''


def last_ts(path):
    try:
        with open(path, 'rb') as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 4096))
            data = f.read().decode('utf-8', 'replace')
        hits = TS_RE.findall(data)
        return hits[-1] if hits else '?'
    except OSError:
        return '?'


def main():
    ap = argparse.ArgumentParser(description='按复现时间生成 auth-trace 鉴权问题证据包')
    ap.add_argument('time', nargs='+', help='复现时间, 如 "15:20" 或 "2026-10-10 15:20:30"')
    ap.add_argument('-w', '--window', type=float, default=3.0, help='前后分钟数(默认 3)')
    args = ap.parse_args()

    t = parse_time(' '.join(args.time))
    since = t - datetime.timedelta(minutes=args.window)
    until = t + datetime.timedelta(minutes=args.window)
    since_s = since.strftime('%Y-%m-%d %H:%M:%S')
    until_s = until.strftime('%Y-%m-%d %H:%M:%S')

    out = []

    def w(s=''):
        out.append(s)

    w('=' * 76)
    w('auth-trace 鉴权问题证据包')
    w('复现时间: %s  (± %s 分钟)' % (t.strftime('%Y-%m-%d %H:%M:%S'), args.window))
    w('时间范围: %s ~ %s' % (since_s, until_s))
    w('生成时间: %s   生成者: uid=%s' % (datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), os.geteuid()))
    w('=' * 76)

    # [0] 日志文件状态（判断服务是否在跑）
    w('')
    w('[0] 日志文件状态')
    sys_log = os.path.join(SYS_DIR, 'events.log')
    w('  系统总线: %s  (最后事件: %s)' % (sys_log if os.path.exists(sys_log) else '不存在',
                                        last_ts(sys_log) if os.path.exists(sys_log) else '-'))
    for d in user_log_dirs():
        p = os.path.join(d, 'events.log')
        w('  会话总线: %s  (最后事件: %s)' % (p, last_ts(p) if os.path.exists(p) else '-'))

    # [1] 捕获事件
    events = []
    for ln in collect_lines(sys_log, since_s, until_s):
        events.append(('SYS', ln))
    for d in user_log_dirs():
        for ln in collect_lines(os.path.join(d, 'events.log'), since_s, until_s):
            events.append(('SES', ln))
    w('')
    w('[1] 捕获到的鉴权相关 D-Bus 事件: %d 条' % len(events))
    for src, ln in events[:400]:
        w('  (%s) %s' % (src, ln))
    w('')
    w('    >> 判读提示')
    joined = '\n'.join(ln for _s, ln in events if '[monitor]' not in ln)
    if 'POLKIT-DIALOG' in joined:
        w('    - [命中] polkit 触发了弹窗(POLKIT-DIALOG): action= 为申请动作, pid/exe/cmd 为调用方')
    elif 'POLKIT-CHECK' in joined:
        w('    - [命中] 存在 polkit 鉴权请求(POLKIT-CHECK): action= 为申请动作, pid/exe/cmd 为调用方')
    if 'udcp.Authoriztion' in joined:
        w('    - [命中] 存在 UDCP(auth-dialog/IAM) 调用: 安全管控类弹窗')
    if 'daemon.Authenticate' in joined:
        w('    - [命中] 存在 Deepin 认证框架(com.deepin.daemon.Authenticate)调用')
    if 'daemon.Authority' in joined:
        w('    - [命中] 存在 DDE PAM 授权(com.deepin.daemon.Authority)调用')
    if not events:
        w('    - 未捕获到事件。可能: 服务未运行 / 时间段不对 / 该弹窗不经 D-Bus(如终端 sudo 的 PAM 提示)')

    # [2] 窗口记录
    wins = []
    for d in user_log_dirs():
        wins += collect_lines(os.path.join(d, 'windows.log'), since_s, until_s)
    w('')
    w('[2] 窗口记录: %d 条' % len(wins))
    for ln in wins[:200]:
        w('  ' + ln)

    # [3] journal 相关日志
    journal_lines, jerr = run_journal(since_s, until_s)
    jhits = [ln for ln in journal_lines if JOURNAL_KEY_RE.search(ln)]
    w('')
    w('[3] journald 相关日志: %d 条 (窗口内共 %d 行)' % (len(jhits), len(journal_lines)))
    if jerr:
        w('  !! journal 读取受限: %s  (建议用 sudo 运行本命令)' % jerr)
    for ln in jhits[:300]:
        w('  ' + ln)

    # [4] 事件进程的 journal 上下文
    pids = set()
    for _s, ln in events:
        pids.update(PID_RE.findall(ln))
    pid_ctx = []
    if pids:
        pat = re.compile(r'\[(?:%s)\]' % '|'.join(sorted(pids)))
        for ln in journal_lines:
            if pat.search(ln) and ln not in jhits:
                pid_ctx.append(ln)
    w('')
    w('[4] 相关进程(pid=%s)的 journal 上下文: %d 条' % (','.join(sorted(pids)) or '-', len(pid_ctx)))
    for ln in pid_ctx[:200]:
        w('  ' + ln)

    # [5] 原始报文（仅写入报告文件）
    raw_blocks = []
    paths = [os.path.join(SYS_DIR, 'raw.log')] + [os.path.join(d, 'raw.log') for d in user_log_dirs()]
    for path in paths:
        raw_blocks += collect_raw(path, since_s, until_s)

    text = '\n'.join(out)
    file_text = [text, '', '[5] 原始 D-Bus 报文: %d 块' % len(raw_blocks)]
    for b in raw_blocks[:100]:
        file_text.extend(b['lines'])
        file_text.append('')

    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    if os.geteuid() == 0:
        outdir = os.path.join(SYS_DIR, 'reports')
    else:
        outdir = os.getcwd()
    outpath = None
    try:
        os.makedirs(outdir, exist_ok=True)
        outpath = os.path.join(outdir, 'auth-trace-report-%s.txt' % stamp)
        with open(outpath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(file_text) + '\n')
    except OSError as e:
        print('警告: 报告文件写入失败: %r' % (e,), file=sys.stderr)

    print(text)
    if outpath:
        print()
        print('完整报告(含原始报文): %s' % outpath)


if __name__ == '__main__':
    main()
