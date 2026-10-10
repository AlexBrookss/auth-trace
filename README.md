# auth-trace

捕捉桌面“鉴权弹窗”背后调用方的取证工具（UOS / Deepin / DDE，其他 D-Bus 桌面同样适用）。

桌面偶尔弹出鉴权/认证窗口，却无法知道是**哪个程序**、通过**哪个接口**发起的请求。
`auth-trace` 在 D-Bus 系统总线和会话总线上做被动监听（纯只读，不会触发任何鉴权），
把调用方（pid / 可执行文件 / 命令行 / systemd unit）与调用内容（目标服务、接口、
方法、polkit action）持久化到硬盘。复现问题后**只需要提供复现时间**，即可生成证据包：
捕获到的 D-Bus 事件 + 窗口记录 + journald 日志 + 原始报文。

上游仓库：`git@github.com:AlexBrookss/auth-trace.git`

## 工作原理

```
 应用A ── CheckAuthorization ──▶ polkitd ──▶ dde-polkit-agent ──▶ 鉴权窗
 应用B ── PreAuthenticate ────▶ deepin-authenticate ──────────▶ 鉴权窗
 应用C ── Authorize ──────────▶ udcp auth-dialog (IAM) ───────▶ 鉴权窗
                                    
        ▲ 鉴权窗本身不带调用者信息，只能在总线上蹲点
┌───────┴──────────────────────────────────────────────────────────┐
│  auth-trace 常驻服务 (systemd, 开机/登录自启)                       │
│   ├─ auth-trace-system.service   (root)  系统总线 → /var/log/auth-trace/
│   └─ auth-trace-session.service  (用户)  会话总线 + 窗口记录
│                                            → ~/.local/state/auth-trace/
└───────────────────────────────────────────────────────────────────┘
```

覆盖的常见弹窗来源：

| 来源 | D-Bus 服务 | 弹窗程序 |
| --- | --- | --- |
| polkit 认证弹窗 | `org.freedesktop.PolicyKit1`（系统总线） | `dde-polkit-agent` |
| Deepin 认证框架 | `com.deepin.daemon.Authenticate`（系统总线） | `deepin-authentication` |
| DDE PAM 授权 | `com.deepin.daemon.Authority`（系统总线） | `dde-authority` |
| UDCP 安全管控 IAM | `com.deepin.udcp.Authoriztion`（会话总线） | `auth-dialog` |
| 权限管理 | `org.deepin.PermissionManager*`（系统/会话总线） | `permission_manager` |

## 功能特性

- 系统总线（root）+ 会话总线（用户）双监听，覆盖 polkit / deepin / udcp / 权限管理
- 记录调用方 pid、可执行文件、命令行、systemd unit
- 窗口标题记录（新窗口 + “疑似鉴权窗口”标记），用于和 D-Bus 事件时间对照
- 开机/登录自启；日志落盘并自动轮转（20MB/代，保留一代）
- `auth-trace-report "复现时间"` 一键生成证据包
- 纯监听、零侵入，不触发任何鉴权行为

---

## 安装

### 方式一：deb 包（推荐）

```bash
# 1. 构建（在仓库根目录）
sudo apt install debhelper dpkg-dev fakeroot     # 按需安装构建依赖
dpkg-buildpackage -us -uc -b

# 2. 安装
sudo apt install ../auth-trace_*.deb

# 3. 为当前用户启用会话总线监听（登录自启）
systemctl --user enable --now auth-trace-session.service
```

安装后：

| 组件 | 说明 |
| --- | --- |
| `auth-trace-system.service`（系统） | 包管理器自动启用并开机自启，监听系统总线 |
| `auth-trace-session.service`（用户级） | 按需为各用户启用，监听会话总线 + 窗口记录 |
| 命令 `auth-trace-report` | 按复现时间生成证据包 |
| 日志 | `/var/log/auth-trace/`、`~/.local/state/auth-trace/` |

### 方式二：源码脚本安装（不经过包管理）

```bash
cd auth-trace
sudo ./install.sh            # 完整安装（部署到 /opt，含系统 + 用户服务）
./install.sh --user-only     # 只装当前用户的会话监听（无需 root）
sudo ./uninstall.sh          # 卸载（保留历史证据日志）
```

> 注意：两种方式二选一。若之前用 `install.sh` 装过，请先卸载再加入 deb 方案，
> 避免新旧两套服务同时监听。

---

## 使用：复现后取证

```bash
sudo auth-trace-report "15:20"                       # 今天 15:20，前后 ±3 分钟
sudo auth-trace-report "2026-10-10 15:20:30" -w 5    # 指定日期时间，±5 分钟
```

输出证据包（控制台摘要 + `/var/log/auth-trace/reports/*.txt` 完整报告）：

| 章节 | 内容 |
| --- | --- |
| [0] | 服务/日志状态（最后一条事件时间，判断监听是否在跑） |
| [1] | 捕获到的 D-Bus 鉴权事件（调用方 pid / exe / cmd / polkit action） |
| [2] | 窗口记录（含“疑似鉴权窗口”标注） |
| [3] | journald 相关日志（polkit/认证/管控等关键词过滤） |
| [4] | 事件涉及进程的 journal 上下文 |
| [5] | 原始 D-Bus 报文（完整报告文件中） |

实时查看：

```bash
tail -f /var/log/auth-trace/events.log            # 系统总线
tail -f ~/.local/state/auth-trace/events.log      # 会话总线
```

### 手动临时抓取（不依赖服务）

```bash
cd auth-trace
./catch-auth.sh start      # 启动（需要输入一次 sudo 密码）
./catch-auth.sh show       # 查看最近捕获的事件
./catch-auth.sh follow     # 实时跟踪
./catch-auth.sh raw 200    # 查看原始 D-Bus 报文
./catch-auth.sh selftest   # 自检监听链路
./catch-auth.sh stop       # 停止
```

## 事件判读

事件行示例：

```
[2026-10-10 15:20:31.123] POLKIT-CHECK bus=SYS action=org.freedesktop.policykit.exec member=CheckAuthorization sender=:1.234 dest=org.freedesktop.PolicyKit1 pid=12345 uid=1000 exe=/usr/bin/xxx cmd="/usr/bin/xxx --flag" unit=app-xxx@autostart.service
```

- `POLKIT-CHECK` — 某程序向 polkit 发起鉴权检查，`action=` 就是它申请的权限
- `POLKIT-DIALOG` — polkit 已通知 agent 弹窗（基本等同“窗口出现了”）
- `CALL` — 其他鉴权服务调用（关键看 `dest=`）

弹窗出现的时刻，看时间戳附近最新的几行：

- 有 `POLKIT-CHECK` / `POLKIT-DIALOG` → polkit 弹窗，`pid/exe/cmd` 是调用方
- `dest=com.deepin.udcp.Authoriztion` → UDCP（安全管控/IAM）弹的
- `dest=com.deepin.daemon.Authenticate` → Deepin 认证框架弹的
- `dest=com.deepin.daemon.Authority` → dde PAM 授权弹的

`windows.log` 中标注“疑似鉴权窗口”的记录的 `pid` 是**弹窗程序**，
`events.log` 里的 `pid` 才是**发起调用的应用**。

## 目录结构

| 路径 | 作用 |
| --- | --- |
| `auth_monitor.py` | 监听器本体（手动模式 / `--system` / `--service-session`） |
| `auth-trace-report.py` | 证据包生成器（安装为 `auth-trace-report`） |
| `systemd/*.service` | 系统级 / 用户级 systemd unit |
| `debian/` | Debian 打包目录 |
| `install.sh` / `uninstall.sh` | 源码脚本安装 / 卸载 |
| `catch-auth.sh` / `catch-windows.sh` | 手动临时抓取工具 |

## 构建 deb / 发布新版本

```bash
# 更新版本号（二选一）
dch -i                              # 需要 devscripts
vim debian/changelog                # 或手工编辑

# 构建（产物在上层目录）
dpkg-buildpackage -us -uc -b
ls ../auth-trace_*_all.deb
```

打包要点：

- 纯脚本项目，`debian/rules` 仅调用 `dh`；打包兼容 `debhelper >= 12`
- `debian/install` 负责文件落位；`dh_installsystemd{,user}` 自动为
  `usr/lib/systemd/{system,user}` 下的 unit 生成启用脚本
- 系统服务安装后自动 enable + start；用户级服务需要各用户自行
  `systemctl --user enable --now auth-trace-session.service`

## 卸载

```bash
sudo apt remove auth-trace            # deb 安装的
sudo ./uninstall.sh                   # 脚本安装的
```

两种方式都会保留历史证据日志（`/var/log/auth-trace/`、`~/.local/state/auth-trace/`）。

## 备选：打开 polkitd 调试日志

```bash
sudo systemctl edit polkit.service
# 在编辑器中输入（原 ExecStart 带 --no-debug，这里覆盖为不带）：
[Service]
ExecStart=
ExecStart=/usr/lib/policykit-1/polkitd
sudo systemctl restart polkit.service
sudo journalctl -f -u polkit.service
```

恢复：`sudo systemctl revert polkit.service`。deepin-authenticate 的日志：
`sudo journalctl -u deepin-authenticate -f`

## License

Apache-2.0（见 [LICENSE](LICENSE)）
