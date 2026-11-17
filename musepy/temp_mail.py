"""generator.email 临时邮箱：生成新邮箱 + 从收件箱读验证码。

接口（按 generator.email 站内行为与公开实现整理，见 README）：
  - 域名发现：GET https://generator.email/search.php?key=<2 字符>
    按旧版公开实现应返回 JSON 域名数组；但 2026-11-17 实测：
    同一浏览器会话里直接打开它也返回 403 Forbidden（nginx），
    无 JSON。拿不到时用 FALLBACK_DOMAINS（当天页面下拉框里看到的
    域名）兜底，或用配置 temp_mail_domains 指定。
  - 收件箱：GET https://generator.email/inbox1/，按旧版公开实现靠
    Cookie 认邮箱：embx = ["<完整邮箱>"]，surl = "<域名>/<local>"，
    返回 HTML 收件箱列表（非 JSON）。但 2026-11-17 实测：页面是
    渲染式会话标识（/inbox1/、/inbox2/ 按标签分，/{email} 会重定向
    到 /inboxN/），浏览器视图里看不到 embx/surl 这两个 Cookie，
    也看不到加载消息的 XHR/JSON 端点——所以这套 Cookie 机制在
    当前 live 站点上是**未证实的**，只能按旧实现先写着，收不到码
    时请回退到 otp_file 手动邮箱模式，别反复重试。

注意：
  - 这是公开的临时邮箱服务，收件箱谁拿到地址谁就能读，不要用它
    收任何敏感邮件；只适合收一次性验证码。
  - 验证码提取不依赖具体表格结构：把 inbox HTML 去标签转纯文本，
    再找 6 位数字；新邮箱在 send 前应为空，send 后出现的第一个
    新码就是本次 OTP，同一轮出现多个不同码视为歧义、返回 None。
  - search.php 对纯文本抓取会 403，必须用 curl_cffi 的浏览器
    impersonation（chrome142）去请求，和 muse 客户端同一套。
"""

import html as _html
import json
import random
import re
import secrets
import string
import time
from urllib.parse import quote

from curl_cffi import requests as cr
import contextlib

BASE = "https://generator.email"
SEARCH_URL = BASE + "/search.php"
INBOX_URL = BASE + "/inbox1/"

# 兜底域名：2026-11-17 在 generator.email 页面域名下拉框里实际看到的
# 一批域名。search.php 当天对裸请求返回 403（见下文），拿不到域名池
# 时就用这批；域名池是站点动态变的，失效了请用 temp_mail_domains
# 在配置里传新域名，或直接在网站下拉框里抄一批换掉这里。
FALLBACK_DOMAINS = [
    "redproxies.com", "au-1.top", "dyclsr.com", "qwertyhandsome.com",
    "990907.xyz", "fastnodo.com", "kysngd.com", "mentongwang.com",
    "fazendabrasil1.com", "chatgptku.com", "song88.net", "nupak.com",
    "huhu8686.com", "kakao-mail.com", "eva.vopzi236.com",
]

_CODE_RE = re.compile(r"(?<!\d)([0-9]{6})(?!\d)")
_TAG_RE = re.compile(r"<[^>]+>")


class TempMailError(RuntimeError):
    """临时邮箱服务的预期失败（域名取不到 / 收件箱打不开 / 读码超时等）"""


def _random_key():
    consonants = "bcdfghjklmnpqrstvwxz"
    vowels = "aeiou"
    return random.choice(consonants) + random.choice(vowels)


def _random_local(length=11):
    alphabet = string.ascii_lowercase + string.digits
    local = "".join(secrets.choice(alphabet) for _ in range(length))
    if local[0].isdigit():
        local = secrets.choice(string.ascii_lowercase) + local[1:]
    return local


def html_to_text(html_text):
    """inbox HTML → 纯文本：去标签、解实体、多余空白压成一个空格。"""
    if not isinstance(html_text, str):
        return ""
    text = _TAG_RE.sub(" ", html_text)
    text = _html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def extract_codes(text):
    """按出现顺序返回纯文本里的全部 6 位验证码（去重，保序）。"""
    seen = []
    for code in _CODE_RE.findall(text or ""):
        if code not in seen:
            seen.append(code)
    return seen


def select_new_code(text, seen_before):
    """send 之后出现、且之前没见过的码；多个不同新码 → 歧义，返回 None。

    text: 本轮 inbox 纯文本；seen_before: send 前已有的码集合。
    新邮箱 send 前收件箱应为空，正常情况这里只会冒出一个新码。
    """
    fresh = [c for c in extract_codes(text) if c not in set(seen_before or ())]
    if len(fresh) == 1:
        return fresh[0]
    return None


def parse_inbox(html_text):
    """解析 inbox HTML，返回 {messages, codes}。

    不硬编码表格结构：先转纯文本提所有 6 位码；再按行切出含
    Meta / Muse / log in / code 字样的行作候选摘要，便于日志排查。
    messages 每项只有 text 摘要，没有发件人/时间的结构化字段——
    站点返回的就是 HTML 列表，强行解析表格只会更脆。
    """
    text = html_to_text(html_text)
    codes = extract_codes(text)
    messages = []
    for chunk in text.split("  "):
        low = chunk.lower()
        if any(k in low for k in ("meta", "muse", "log in", "login code", "use code")):
            snippet = chunk.strip()
            if snippet and snippet not in messages:
                messages.append(snippet)
    return {"messages": messages, "codes": codes, "text": text}


class GeneratorMail:
    """一个临时邮箱 = 一个 curl_cffi Session + embx/surl Cookie。"""

    def __init__(self, email, proxy=None, impersonate="chrome142", timeout=30,
                 session_factory=None):
        if not isinstance(email, str) or "@" not in email:
            raise TempMailError("temp_mail_email_invalid")
        self.email = email.strip()
        self.local, self.domain = self.email.rsplit("@", 1)
        self.proxy = proxy
        self.impersonate = impersonate
        self.timeout = timeout
        self._session_factory = session_factory
        if session_factory is not None:
            self.s = session_factory()
        else:
            self.s = cr.Session(
                impersonate=impersonate,
                proxies={"http": proxy, "https": proxy} if proxy else None,
                timeout=timeout,
            )
        self._set_cookies()

    def _set_cookies(self):
        # Cookie 认邮箱：embx 是 JSON 数组，surl 是 domain/local
        self.s.cookies.set("embx", json.dumps([self.email]), domain="generator.email")
        self.s.cookies.set("surl", f"{self.domain}/{self.local}", domain="generator.email")

    def close(self):
        with contextlib.suppress(Exception):
            self.s.close()

    # ---------- 刷新 / 切换 ----------

    def refresh(self):
        """刷新一次收件箱：重新 GET inbox1，返回 parse_inbox 的结果。

        就是网站上那个“刷新”按钮做的事——重新拉一遍 HTML 再解析，
        不换邮箱、不清 Cookie。wait_otp 内部每轮就是调它（经 fetch_codes）。
        """
        return parse_inbox(self.fetch_inbox_html())

    def refresh_codes(self):
        """刷新一次收件箱，只返回当前全部 6 位码。"""
        return self.fetch_codes()

    def switch_to_new_email(self, domains=None, domain_fetcher=None):
        """切换到一个全新的临时邮箱，返回新邮箱地址。

        旧邮箱直接丢弃（临时邮箱本来就是一次性的，不保留、不迁移邮件）。
        切换后本对象就代表新邮箱：email/local/domain 和 embx/surl
        Cookie 都已更新，旧 Session 已关闭；调用方只需用新 email
        重新走 restart → send_otp → wait_otp。
        生成失败（域名拿不到）抛 TempMailError，旧邮箱保持不变——
        先生成成功才切换，不会把还能用的旧邮箱弄丢。
        """
        new_email, new_mail = generate_email(
            domains=domains, proxy=self.proxy, impersonate=self.impersonate,
            timeout=self.timeout, session_factory=self._session_factory,
            domain_fetcher=domain_fetcher)
        old_session = self.s
        self.email = new_mail.email
        self.local, self.domain = new_mail.local, new_mail.domain
        self.s = new_mail.s
        with contextlib.suppress(Exception):
            old_session.close()
        return self.email

    def switch_to_email(self, email):
        """切换到指定的已存在邮箱地址（比如用户在网站上手动改的那个）。"""
        if not isinstance(email, str) or "@" not in email:
            raise TempMailError("temp_mail_email_invalid")
        self.email = email.strip()
        self.local, self.domain = self.email.rsplit("@", 1)
        self._set_cookies()
        return self.email

    def fetch_inbox_html(self):
        """取 inbox1 HTML；非 200 时试直达 URL，仍失败则抛错。"""
        headers = {"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                   "accept-language": "en-US,en;q=0.9",
                   "referer": BASE + "/"}
        r = self.s.get(INBOX_URL, headers=headers, timeout=self.timeout)
        if r.status_code == 200 and r.text:
            return r.text
        # 兜底：同后端 /<完整邮箱> 直达收件箱
        r2 = self.s.get(f"{BASE}/{quote(self.email)}", headers=headers, timeout=self.timeout)
        if r2.status_code == 200 and r2.text:
            return r2.text
        raise TempMailError(f"temp_mail_inbox_http_{r.status_code}")

    def fetch_codes(self):
        return extract_codes(html_to_text(self.fetch_inbox_html()))

    def wait_otp(self, seen_before=(), *, timeout=120, poll_interval=3):
        """轮询收件箱直到出现 send 之后的新 6 位码，超时返回 None。

        seen_before：send_otp 前收件箱已有的码（新邮箱一般为空集）。
        网络异常向上抛（调用方按 transport_error 处理）；歧义（同轮
        多个不同新码）不猜，直接返回 None，让调用方走 otp 超时分支。
        """
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            codes = self.fetch_codes()
            fresh = [c for c in codes if c not in set(seen_before or ())]
            if len(fresh) == 1:
                return fresh[0]
            if len(fresh) > 1:
                return None
            time.sleep(poll_interval)
        return None


def fetch_domains(proxy=None, impersonate="chrome142", timeout=15, session_factory=None):
    """GET search.php?key=<随机 2 字符>，返回 ASCII 域名列表；失败返回 []。"""
    if session_factory is not None:
        session = session_factory()
    else:
        session = cr.Session(
            impersonate=impersonate,
            proxies={"http": proxy, "https": proxy} if proxy else None,
            timeout=timeout,
        )
    try:
        r = session.get(f"{SEARCH_URL}?key={_random_key()}",
                        headers={"accept": "application/json, */*",
                                 "referer": BASE + "/"},
                        timeout=timeout)
        if r.status_code != 200:
            return []
        try:
            data = json.loads(r.text)
        except (TypeError, ValueError):
            return []
        if not isinstance(data, list):
            return []
        domains = []
        for item in data:
            if isinstance(item, str):
                item = item.strip().lower()
                if item and all(ord(ch) < 128 for ch in item) and "." in item:
                    domains.append(item)
        return domains
    except Exception:
        return []
    finally:
        with contextlib.suppress(Exception):
            session.close()


def generate_email(domains=None, proxy=None, impersonate="chrome142", timeout=15,
                   session_factory=None, domain_fetcher=None):
    """生成一个新临时邮箱并返回 (email, GeneratorMail)。

    domains 为空时先调 search.php 拿域名；拿不到（403/空列表）就抛
    TempMailError，不猜域名、不硬编码域名——域名池是站点动态变的。
    """
    fetcher = domain_fetcher or (lambda: fetch_domains(
        proxy=proxy, impersonate=impersonate, timeout=timeout,
        session_factory=session_factory))
    pool = list(domains or fetcher() or [])
    if not pool:
        # search.php 拿不到域名（实测 403）时用当天页面下拉框里看到的
        # 兜底域名；连兜底都没有才报错。注意：域名对不代表收件箱一定
        # 能收到——live 站是会话标识邮箱，见模块 docstring。
        pool = list(FALLBACK_DOMAINS)
    if not pool:
        raise TempMailError("temp_mail_no_domains")
    domain = random.choice(pool)
    email = f"{_random_local()}@{domain}"
    mail = GeneratorMail(email, proxy=proxy, impersonate=impersonate,
                         timeout=timeout, session_factory=session_factory)
    return email, mail


def make_otp_waiter(email, proxy=None, impersonate="chrome142", timeout=120,
                    poll_interval=3, session_factory=None, seen_before=()):
    """给 BatchRunner 用的 otp_waiter(email, otp_source_url, after)。

    otp_source_url 在这里不使用（为兼容 runner 的签名保留参数）；
    每次调用新建一个 GeneratorMail 会话轮询该邮箱，读到码即关闭。
    seen_before 是生成邮箱时 / send 前收件箱已有的码快照，用它去重，
    而不是 after 时间戳——generator.email 的 inbox HTML 不带可靠的
    每封邮件时间戳，时间戳去重在这里不可靠。
    """
    seen = tuple(seen_before or ())

    def waiter(_email, _url, _after):
        mail = GeneratorMail(email, proxy=proxy, impersonate=impersonate,
                             timeout=timeout, session_factory=session_factory)
        try:
            return mail.wait_otp(seen, timeout=timeout, poll_interval=poll_interval)
        finally:
            mail.close()

    return waiter
