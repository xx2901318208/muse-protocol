"""多账号批量调度（开源版，语义对齐本地实现）。

调度规则：
- worker 独占一条 sticky 代理行（claim/release），不抢他人的行；池耗尽才共享并打日志。
- max_per_ip 按"验证成功数"计：达到上限释放当前行并换行（原行本轮避开）。
- pre-send 阶段（initialized/bootstrap/restart，OTP 未发出）的传输失败：释放当前行、
  内存标记 pool_bad、同邮箱换代理重试 <=3 次，不消耗新邮箱；仍失败则标记 tried。
- 业务拒绝 / pending / 已发 OTP 后的失败：整批停止——不换行、不重试、不补号。
- region_waitlist：账号已注册但地区受限——记录 registered_waitlist（账号保留）并停止。
- 预算 = 领取的不同邮箱数，失败不补号。

邮箱来源两种（二选一，见 init）：
  1. otp_file 清单：每行 email----otp源URL，OTP 从该 URL 轮询；
  2. temp_mail 自动生成：config 里 temp_mail=true 时，init(count) 直接
     从 generator.email 生成 count 个新邮箱，每个邮箱的 OTP 从它自己
     的收件箱轮询，不再需要 otp_file。

每账号结果写入 output_dir/<email>.json（简化字段）。frl_access_token 与
hatch_sess 仅在内存中使用，不落盘。仅供个人学习与研究使用。
"""

import concurrent.futures as cf
import json
import os
import random
import threading
from datetime import datetime, timezone

from . import caa as _caa
from . import otp as _otp
from . import temp_mail as _temp_mail
from .client import MuseClient, MuseError, random_dob
import contextlib

PRE_SEND_STAGES = frozenset({"initialized", "bootstrap", "restart"})
AUTH_STAGES = PRE_SEND_STAGES | {"send_otp", "wait_otp", "confirm_otp", "completion"}

TRANSPORT_MARKERS = (
    "curl: (35)", "curl: (28)", "curl: (7)", "curl: (56)", "curl: (52)",
    "timed out", "connectionerror", "connection reset", "connection refused",
)

# 常用日本姓名池（姓 / 名），register_completion 语义：first_name=名、last_name=姓
SURNAMES = ["佐藤", "鈴木", "高橋", "田中", "伊藤", "渡辺", "山本", "中村", "小林", "加藤",
            "吉田", "山田", "佐々木", "山口", "松本", "井上", "木村", "林", "斎藤", "清水",
            "山崎", "森", "池田", "橋本", "阿部", "石川", "前田", "藤田", "小川", "岡田",
            "後藤", "長谷川", "石井", "村上", "近藤", "坂本", "遠藤", "青木", "藤井", "西村"]
GIVEN_NAMES = ["ヨウ", "タクミ", "ユウキ", "ハルト", "ソウタ", "リク", "カイト", "ミナト", "ハル", "アオイ",
               "ヒナタ", "ツバサ", "レン", "コウ", "シュン", "ナオキ", "ケイタ", "ダイキ", "リョウ", "ユウト",
               "サクラ", "ユイ", "メイ", "アカリ", "ヒカリ", "ノゾミ", "ミサキ", "カナ", "リナ", "ユナ",
               "ソラ", "カイ", "トワ", "イツキ", "アサヒ", "マコト", "タケル", "ジン", "カズマ", "ユウマ"]


def _lines(path):
    try:
        with open(path, encoding="utf-8") as stream:
            return [line.strip() for line in stream if line.strip()]
    except OSError:
        return []


def mkproxy(line):
    """host:port:user:pass → http://user:pass@host:port；host:port → http://host:port。

    也接受已是完整 URL 的行（http://user:pass@host:port）。
    之前用 line.split(":") 且要求正好 4 段：密码里带冒号会被截断成
    ValueError，IPv6 地址更是直接解析错。这里按“最多切 3 次”处理，
    密码保留剩余全部内容，并对 user/password 做 URL 编码。
    """
    from urllib.parse import quote, urlsplit

    raw = (line or "").strip()
    if raw.startswith(("http://", "https://")):
        return raw
    parts = raw.split(":", 3)
    if len(parts) == 4:
        host, port, user, password = parts
        return f"http://{quote(user, safe='')}:{quote(password, safe='')}@{host}:{port}"
    if len(parts) == 2:
        host, port = parts
        # [::1]:port 这种 IPv6 行 split(":") 会碎掉，走 urlsplit 兜底
        if raw.startswith("["):
            hostport = urlsplit("//" + raw)
            if hostport.hostname and hostport.port:
                return f"http://{raw}"
        return f"http://{host}:{port}"
    if raw.startswith("["):
        hostport = urlsplit("//" + raw)
        if hostport.hostname and hostport.port:
            return f"http://{raw}"
    raise ValueError("proxy_line_format")


def proxy_endpoint(line):
    """仅取 host:port，用于日志（不打印凭据）。"""
    from urllib.parse import urlsplit

    raw = (line or "").strip()
    if raw.startswith(("http://", "https://")):
        parsed = urlsplit(raw)
        return parsed.hostname + (f":{parsed.port}" if parsed.port else "")
    if raw.startswith("["):
        parsed = urlsplit("//" + raw)
        if parsed.hostname:
            return parsed.hostname + (f":{parsed.port}" if parsed.port else "")
    parts = raw.split(":", 3)
    return f"{parts[0]}:{parts[1]}" if len(parts) >= 2 else None


def _classify_error(exc):
    """传输层失败归 transport_error；其余归 failed。不做任何 IP 封禁推断。"""
    if isinstance(exc, (TimeoutError, ConnectionError)):
        return "transport_error"
    text = str(exc).lower()
    if any(marker in text for marker in TRANSPORT_MARKERS):
        return "transport_error"
    return "failed"


def utc_stamp():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


class BatchRunner:
    """多账号批量调度器。一个账号 = 一个新 MuseClient 实例 + 一条当前 sticky 代理行。"""

    def __init__(self, config, *, client_factory=None, otp_waiter=None, ip_resolver=None):
        self.cfg = config
        self.workers = int(config.get("workers", 5) or 5)
        self.max_per_ip = int(config.get("max_per_ip", 6) or 6)
        self.lang = config.get("lang", "ja")
        self.fp = config.get("impersonate", "chrome142")
        self.otp_file = config.get("otp_file")
        self.proxy_file = config.get("proxy_file")
        self.codes_file = config.get("codes_file")
        self.output_dir = config.get("output_dir", "output")
        self.tried_file = config.get("tried_file")
        self.send_caa = bool(config.get("send_caa", False))
        self.resolve_ip = bool(config.get("resolve_ip", True))
        # 临时邮箱：temp_mail=true 时不用 otp_file，init 直接生成新邮箱
        self.temp_mail = bool(config.get("temp_mail", False))
        self.temp_mail_timeout = int(config.get("temp_mail_timeout", 120) or 120)
        self.temp_mail_max_switches = int(config.get("temp_mail_max_switches", 2) or 0)
        self.temp_mail_domains = config.get("temp_mail_domains") or None
        self._temp_seen = {}  # email -> 生成时收件箱已有的码快照（去重用）
        self.email_generator = None  # 注入点（离线测试用）：() -> (email, seen_before)
        # 注入点（离线测试用）：客户端工厂 / OTP 轮询 / 出口 IP 解析
        self.client_factory = client_factory or self._default_client_factory
        self.otp_waiter = otp_waiter or self._default_otp_waiter
        self.ip_resolver = ip_resolver or self._default_ip_resolver
        self.ROWS, self.QUEUE, self.PX, self.CODES = {}, [], [], []
        self._lk = threading.Lock()
        self._codes_lk = threading.Lock()
        self._storage_lk = threading.Lock()
        self._stop = threading.Event()
        self._stop_reason = None
        self._proxy_claims, self._pool_bad, self._ipcache, self._tried = set(), set(), {}, set()
        self._qi = [0]
        self._stats = {key: 0 for key in ("started", "ok", "pending", "server_rejected",
                                          "transport_error", "failed", "ip_switches")}

    # ---------- 默认依赖 ----------

    def _default_client_factory(self, proxy_url):
        return MuseClient(proxy=proxy_url, impersonate=self.fp, lang=self.lang)

    def _default_otp_waiter(self, email, url, after):
        # generator: 开头的行是临时邮箱：OTP 从它自己的收件箱轮询，
        # 不走 otp_file 的 JSON 源；其余行保持原有 _otp.wait_otp 行为。
        if isinstance(url, str) and url.startswith("generator:"):
            waiter = _temp_mail.make_otp_waiter(
                email, impersonate=self.fp, timeout=self.temp_mail_timeout,
                seen_before=self._temp_seen.get(email, ()))
            return waiter(email, url, after)
        return _otp.wait_otp(url, after)

    @staticmethod
    def _default_ip_resolver(proxy_url):
        from curl_cffi import requests as cr
        r = cr.get("https://api.ipify.org", impersonate="chrome142",
                   proxies={"http": proxy_url, "https": proxy_url}, timeout=12)
        ip = r.text.strip()
        return ip if ip.count(".") == 3 else None

    # ---------- 池加载（预算 = count 个不同邮箱） ----------

    def _generate_temp_rows(self, count):
        """生成 count 个临时邮箱：{email: "generator:<email>"}。

        每个邮箱生成后立刻快照一次收件箱（正常应为空），快照里的码
        在后续 wait_otp 里会被排除，避免把生成前就有的旧码当本次 OTP。
        生成失败（域名拿不到等）直接抛 TempMailError，init 不补号、
        不 fallback 到 otp_file——两种来源混用只会让排错更难。
        """
        rows, seen = {}, {}
        for _ in range(count):
            if self.email_generator is not None:
                email, snapshot = self.email_generator()
            else:
                email, mail = _temp_mail.generate_email(
                    domains=self.temp_mail_domains, impersonate=self.fp)
                try:
                    snapshot = tuple(mail.fetch_codes())
                except Exception:
                    snapshot = ()
                finally:
                    mail.close()
            rows[email] = f"generator:{email}"
            seen[email] = tuple(snapshot or ())
        return rows, seen

    def init(self, count=30):
        """加载邮箱/代理/验证码池。失败不补号；已在 tried_file 的邮箱跳过。"""
        count = int(count)
        if count < 1:
            raise ValueError("count_must_be_positive")
        if self.temp_mail:
            rows, seen = self._generate_temp_rows(count)
            self._temp_seen = seen
        else:
            rows = {}
            for line in _lines(self.otp_file or ""):
                if "----" not in line:
                    continue
                email, url = line.split("----", 1)
                email = email.strip()
                if not email or any(ch in email for ch in "/\\:\x00"):
                    continue  # 非法记录名，直接跳过
                rows[email] = url.strip()
        tried = (set(_lines(self.tried_file))
                 if self.tried_file and os.path.exists(self.tried_file) else set())
        proxies = _lines(self.proxy_file or "")
        if not proxies:
            raise ValueError("proxy_pool_empty")
        with self._lk:
            self.ROWS = rows
            self.QUEUE = [email for email in rows if email not in tried][:count]
            self.PX = proxies
            self.CODES = _lines(self.codes_file) if self.codes_file else []
            self._tried = set(tried)
            self._proxy_claims.clear()
            self._pool_bad.clear()
            self._ipcache.clear()
            self._qi[0] = 0
            for key in self._stats:
                self._stats[key] = 0
            self._stop.clear()
            self._stop_reason = None
        os.makedirs(self.output_dir, exist_ok=True)
        return len(self.QUEUE)

    # ---------- 批次状态 ----------

    def next_job(self):
        with self._lk:
            if self._stop.is_set() or self._qi[0] >= len(self.QUEUE):
                return None
            email = self.QUEUE[self._qi[0]]
            self._qi[0] += 1
            self._stats["started"] += 1
            return email

    def request_stop(self, reason):
        with self._lk:
            if not self._stop.is_set():
                self._stop_reason = reason
            self._stop.set()

    def summary(self):
        with self._lk:
            return {**self._stats,
                    "queued": len(self.QUEUE),
                    "remaining": len(self.QUEUE) - self._stats["started"],
                    "stopped": self._stop.is_set(),
                    "stop_reason": self._stop_reason}

    # ---------- 代理调度（worker 独占 sticky） ----------

    def _resolve_ip(self, line):
        """resolve_ip=false → (None, True)：出口 IP 未知但行仍可用。"""
        if not self.resolve_ip:
            return None, True
        with self._lk:
            if line in self._ipcache:
                cached = self._ipcache[line]
                return cached, cached is not None
        try:
            ip = self.ip_resolver(mkproxy(line))
            if ip is not None and not (isinstance(ip, str) and ip.count(".") == 3):
                ip = None
        except Exception:
            ip = None
        with self._lk:
            self._ipcache[line] = ip
        return ip, ip is not None

    def _pick_proxy(self, *, current=None, avoid=None):
        """worker 独占 sticky 选择：已占用的行不交给其他 worker。

        池耗尽或全部校验失败时：先复用自己的当前行，再找未占用行，
        最后才共享（打日志）。avoid 排除刚换掉的行（达 max_per_ip 后）。
        """
        # 之前是 400 次 random.choice 碰运气：池子一大、坏行一多就白转很多圈，
        # 还可能 400 次都撞上已占用行。改成洗牌后顺序遍历，每行最多校验一次。
        candidates = list(self.PX)
        random.shuffle(candidates)
        for line in candidates:
            if line in self._pool_bad or line == avoid:
                continue
            if line != current:
                with self._lk:
                    if line in self._proxy_claims:
                        continue
            ip, ok = self._resolve_ip(line)
            if not ok:
                with self._lk:
                    self._pool_bad.add(line)
                continue
            with self._lk:
                self._proxy_claims.add(line)
            return line, ip
        if current is not None and current not in self._pool_bad:
            with self._lk:
                self._proxy_claims.add(current)
            return current, self._ipcache.get(current)
        for _ in range(len(self.PX)):
            with self._lk:
                free = [item for item in self.PX
                        if item not in self._pool_bad and item not in self._proxy_claims
                        and item != avoid]
                if not free:
                    break
                line = random.choice(free)
                self._proxy_claims.add(line)
            ip, ok = self._resolve_ip(line)
            if ok:
                return line, ip
            with self._lk:
                self._proxy_claims.discard(line)
        if current is not None:
            with self._lk:
                self._proxy_claims.add(current)
            return current, self._ipcache.get(current)
        with self._lk:
            shared = list(self._proxy_claims) or list(self.PX)
        line = random.choice(shared)
        print(f"[i] proxy pool exhausted; sharing {proxy_endpoint(line)}", flush=True)
        with self._lk:
            self._proxy_claims.add(line)
        return line, self._ipcache.get(line)

    def _release(self, line):
        """释放本 worker 的 sticky 占用；不动 pool_bad。"""
        if not line:
            return
        with self._lk:
            self._proxy_claims.discard(line)

    # ---------- 记录（简化字段，不含 token/cookie） ----------

    def _save_record(self, rec):
        path = os.path.join(self.output_dir, rec["email"] + ".json")
        with self._storage_lk:
            previous = {}
            try:
                with open(path, encoding="utf-8") as stream:
                    previous = json.load(stream)
            except (OSError, ValueError):
                previous = {}
            merged = {**previous, **rec}
            for key in ("registered", "own_code"):
                if previous.get(key) and not rec.get(key):
                    merged[key] = previous[key]
            if previous.get("status") == "redeemed":
                merged["status"] = "redeemed"
            merged["updated_at"] = utc_stamp()
            with open(path, "w", encoding="utf-8") as stream:
                json.dump(merged, stream, ensure_ascii=False, indent=2)

    def _stamp_tried(self, email):
        with self._storage_lk:
            self._tried.add(email)
            if self.tried_file:
                with open(self.tried_file, "a", encoding="utf-8") as stream:
                    stream.write(email + "\n")

    def _take_code(self):
        with self._codes_lk:
            if self.CODES:
                return self.CODES.pop(0)
        return None

    def _finish(self, email, rec, outcome, reason, stage, *, status=None):
        """统一收口：落盘 → 决定是否整批停止。返回 (outcome, detail)。"""
        rec.update(stage=stage, last_error=reason)
        if status is None:
            if rec.get("registered") and outcome == "ok":
                status = "redeemed"
            elif rec.get("registered"):
                status = "registered_pending_redemption"
            else:
                status = outcome
        rec["status"] = status
        self._save_record(rec)
        stop = (outcome in ("server_rejected", "pending", "failed")
                or (outcome == "transport_error" and stage not in PRE_SEND_STAGES))
        if stop:
            self.request_stop("authentication_paused" if stage in AUTH_STAGES
                              else "workflow_paused")
        return outcome, {"stage": stage, "status": status, "email": rec.get("email"),
                         "registered": bool(rec.get("registered")), "reason": reason}

    # ---------- 单账号全链（顺序对齐本地实现） ----------

    def register_one(self, email, proxy_line):
        """open→restart→send_otp→wait_otp→confirm→completion→activate_session
        （onboarding 门）→accept_tos→wake→sharing→invite→redeem→own_code。

        返回 (outcome, detail)；outcome: ok|server_rejected|pending|transport_error|failed
        """
        rec = {"email": email, "status": "pending", "stage": "initialized",
               "registered": False, "own_code": None, "own_code_status": None,
               "reveal_status": "not_attempted", "is_revealed": None,
               "ip": self._ipcache.get(proxy_line), "last_error": None}
        stage = "initialized"
        client = None
        try:
            if not self.ROWS.get(email):
                return self._finish(email, rec, "failed", "otp_source_missing", stage)
            client = self.client_factory(mkproxy(proxy_line))
            caa = _caa.Caa(client.fp, client.lang) if self.send_caa else None
            if caa is not None and hasattr(client, "waterfall_id"):
                # 漏斗 id 全程同一个：client 的 X-Hatch-Waterfall-Id 与
                # caa 事件的 waterfall_id 对齐，否则服务端看到两条断裂的漏斗。
                client.waterfall_id = caa.wid
            # 拿验证码阶段（可切换邮箱重试）：临时邮箱等不到码时，换一个
            # 新邮箱、从 bootstrap 重新走一遍；手动邮箱 / otp_file 模式
            # 没有“换邮箱”这一说，只试一次。temp_mail_max_switches 默认 2。
            is_temp = (self.temp_mail
                       and isinstance(self.ROWS.get(email), str)
                       and self.ROWS.get(email).startswith("generator:"))
            max_switches = self.temp_mail_max_switches if is_temp else 0
            otp_code = None
            for attempt in range(max_switches + 1):
                stage = "bootstrap"
                client.open_home()
                if caa:
                    caa.page_shown(client.s)
                    caa.focus(client.s)
                    caa.continue_clicked(client.s)
                stage = "restart"
                client.restart()
                if caa:
                    caa.registration_start(client.s)
                stage = "send_otp"
                client.send_otp(email)
                sent_at = utc_stamp()
                if caa:
                    caa.otp_typed(client.s)
                stage = "wait_otp"
                otp_code = self.otp_waiter(email, self.ROWS.get(email), sent_at)
                if otp_code:
                    break
                if attempt >= max_switches:
                    return self._finish(email, rec, "pending", "otp_wait_timeout", stage)
                # 切换：旧邮箱丢弃（临时邮箱一次性的），换新邮箱重走全程。
                # 新邮箱记进 ROWS / _temp_seen，记录文件最终按新邮箱落盘。
                old_email = email
                if self.email_generator is not None:
                    email, snapshot = self.email_generator()
                else:
                    email, mail = _temp_mail.generate_email(
                        domains=self.temp_mail_domains, impersonate=self.fp)
                    try:
                        snapshot = tuple(mail.fetch_codes())
                    except Exception:
                        snapshot = ()
                    finally:
                        mail.close()
                self.ROWS[email] = f"generator:{email}"
                self._temp_seen[email] = tuple(snapshot or ())
                rec["email"] = email
                print(f"  [i] {old_email} 没收到码，已切换到新邮箱 {email}",
                      flush=True)
            if caa:
                caa.otp_success(client.s)
                caa.birthday_start(client.s)
            stage = "confirm_otp"
            client.confirm_otp(otp_code)
            stage = "completion"
            data = client.register_completion(random_dob(),
                                              random.choice(GIVEN_NAMES),
                                              random.choice(SURNAMES))
            auth = data.get("auth_meta_session") or {}
            token, uid = auth.get("frl_access_token"), auth.get("frl_account_id")
            if not token:
                return self._finish(email, rec, "pending", "completion_result_unknown", stage)
            rec["registered"] = True  # token 仅内存使用，不落盘
            if caa:
                caa.create_success(client.s, uid)
                caa.login_success(client.s, uid)
            stage = "session_bootstrap"
            onboarding = client.activate_session(token)
            stage = "accept_tos"
            client.accept_tos(onboarding)
            stage = "wake"
            if client.wake_vm() is None:
                return self._finish(email, rec, "pending", "vm_unresolved", stage)
            stage = "sharing"
            client.stateful_sharing()
            stage = "invite"
            if not client.is_live():
                return self._finish(email, rec, "pending", "invite_result_unverified", stage)
            code = self._take_code()
            if not code:
                return self._finish(email, rec, "pending", "redemption_code_unavailable", stage)
            stage = "redeem"
            ok, reason = client.redeem(code)
            if not ok:
                return self._finish(email, rec, "server_rejected",
                                    f"redemption_unverified:{reason}", stage)
            stage = "own_code"
            own = client.scratch_code()
            if own:
                rec["own_code"] = own
                rec["own_code_status"] = "available"
                return self._finish(email, rec, "ok", "redemption_verified", stage)
            rec["own_code_status"] = "pending"
            return self._finish(email, rec, "ok", "own_code_pending", stage)
        except MuseError as exc:
            text = str(exc)
            if "region_waitlist" in text:
                return self._finish(email, rec, "pending", "region_waitlist", stage,
                                    status="registered_waitlist")
            if text.startswith(("restart ", "send-otp ", "confirm-otp ",
                                "register-completion ", "accept-tos ")):
                return self._finish(email, rec, "server_rejected", text, stage)
            return self._finish(email, rec, "pending", text, stage)
        except Exception as exc:
            return self._finish(email, rec, _classify_error(exc), type(exc).__name__, stage)
        finally:
            if client is not None:
                with contextlib.suppress(Exception):
                    client.close()

    # ---------- worker ----------

    def _worker(self, wid):
        proxy_line, avoid = None, None
        uses, retries = 0, 0
        email = None
        while True:
            if email is None:
                email = self.next_job()
                if email is None:
                    self._release(proxy_line)
                    return
                retries = 0
            if proxy_line is None:
                proxy_line, _ = self._pick_proxy(current=None, avoid=avoid)
                avoid = None
            outcome, detail = self.register_one(email, proxy_line)
            # 临时邮箱切换过的话，detail 里的 email 才是最终成功的那个，
            # 后续 tried 标记 / 传输重试都按最终邮箱走，别再记旧邮箱。
            email = detail.get("email") or email
            message = json.dumps(detail, ensure_ascii=False, sort_keys=True)
            print(f"  [W{wid}] {outcome} {message}", flush=True)
            with self._lk:
                self._stats[outcome if outcome in self._stats else "failed"] += 1
            if outcome == "ok":
                self._stamp_tried(email)
                uses += 1  # max_per_ip 只按验证成功数计
                email, retries = None, 0
                if uses >= self.max_per_ip and not self._stop.is_set():
                    self._release(proxy_line)
                    with self._lk:
                        self._stats["ip_switches"] += 1
                    avoid = proxy_line  # 换行时避开刚用满的那条
                    proxy_line, uses = None, 0
            elif (outcome == "transport_error" and retries < 3
                    and detail.get("stage") in PRE_SEND_STAGES):
                # pre-send 传输失败、零副作用：释放当前代理，同邮箱换代理重试，
                # 不消耗新邮箱；pool_bad 仅内存标记，不写任何黑名单文件。
                retries += 1
                self._release(proxy_line)
                with self._lk:
                    self._pool_bad.add(proxy_line)
                proxy_line = None
                with self._lk:
                    self._stats["ip_switches"] += 1
                print(f"  [W{wid}] proxy_retry#{retries} {email}", flush=True)
            else:
                # 业务拒绝 / pending / 已发 OTP 后的失败：不换行、不重试、不补号；
                # 整批停止由 register_one 的 _finish 里 request_stop 生效。
                self._stamp_tried(email)
                email, retries = None, 0
            if self._stop.is_set():
                self._release(proxy_line)
                return

    def run(self):
        workers = max(1, self.workers)
        with cf.ThreadPoolExecutor(max_workers=workers) as executor:
            list(executor.map(self._worker, range(workers)))
