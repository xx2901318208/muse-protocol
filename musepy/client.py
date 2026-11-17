"""
muse.ai 注册与邀请码兑换协议客户端（纯 HTTP，无浏览器）

仅供协议研究与个人学习使用。使用前请自行确认目标站点的服务条款。
"""

import json
import random
import re
import time
import uuid
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit

from curl_cffi import requests as cr
import contextlib

BASE = "https://muse.ai"

# 会话引导端点：register-completion 拿到 frl_access_token 后必须先走这里，
# 否则后续所有 hatch 接口一律 403（本地运行时实测确认）。
BOOTSTRAP_URL = "https://auth.meta.com/hatch/session/bootstrap/"
TRUSTED_HOSTS = frozenset({"auth.meta.com", "auth.muse.ai", "muse.ai"})

# onboarding 页面提交的 TOS 版本号，仅作 confirm-otp 未返回 tos.content_version
# 时的兜底；正常情况下应使用 confirm_otp 动态返回的服务端版本。
TOS_VERSION = "ntm_create_account:default_v1_meta_account_v3+docs_v2"

HEADERS_JSON = {
    "accept": "*/*",
    "content-type": "application/json",
    "origin": BASE,
    "referer": BASE + "/",
    "sec-fetch-site": "same-origin",
    "sec-fetch-mode": "cors",
    "sec-fetch-dest": "empty",
}
HEADERS_GET = {
    "accept": "*/*",
    "referer": BASE + "/",
    "sec-fetch-site": "same-origin",
    "sec-fetch-mode": "cors",
    "sec-fetch-dest": "empty",
}
HEADERS_HTML = {
    # 完整浏览器文档 accept 串（抓包比对得出；截短版会在引导链上露馅）
    "accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
               "image/avif,image/webp,image/apng,*/*;q=0.8,"
               "application/signed-exchange;v=b3;q=0.7"),
    "sec-fetch-site": "same-origin",
    "sec-fetch-mode": "navigate",
    "sec-fetch-dest": "document",
}

# 抓包时服务端返回的披露正文参考。accept-tos 的正文已改为使用 activate_session()
# 解析出的服务端动态 disclosure_text / disclosure_version，此常量仅作对照文档保留。
DISCLOSURE_TEXT_JA = (
    "次に進むことで、Muse利用規約およびMetaのAI利用規約に同意するものとします。"
    "これには利用者の権利と責任に関する重要な情報が含まれています。"
    "プライバシーに関するMuseのアプローチについて詳しくはMuseプライバシーポリシーをご覧ください。"
)


class MuseError(RuntimeError):
    """协议流程中的可预期失败"""


class MuseClient:
    """一个账号 = 一个 Session（一个出口 IP）"""

    def __init__(self, proxy=None, impersonate="chrome142", lang="ja", timeout=30):
        self.fp = impersonate
        self.lang = lang
        self.proxy = proxy
        self.timeout = timeout
        self.s = cr.Session(impersonate=impersonate,
                            proxies={"http": proxy, "https": proxy} if proxy else None,
                            timeout=timeout)
        self.csrf = None
        self.account_id = None
        self.tos_content_version = None   # confirm-otp 动态返回的服务端 TOS 版本
        self.onboarding = None            # activate_session 解析出的披露结果
        # waterfall_id 同一账号全程固定（caa 漏斗要求同一 id 贯穿全程）：
        # 之前 _auth_headers() 每次调用都生成新 uuid，服务端看到的是断裂的漏斗。
        self.waterfall_id = _uuid()

    # ---------- 基础设施 ----------

    def _h(self, base, extra=None):
        h = dict(base)
        h["accept-language"] = self.lang
        if extra:
            h.update(extra)
        return h

    def _json(self, resp):
        try:
            return resp.json() or {}
        except (ValueError, TypeError, AttributeError):
            return {}

    def close(self):
        with contextlib.suppress(Exception):
            self.s.close()

    # ---------- 注册流程 ----------

    def open_home(self):
        return self.s.get(BASE + "/", impersonate=self.fp,
                          headers=self._h(HEADERS_HTML))

    def restart(self, resume=False):
        """开启注册流程，返回 csrf_token"""
        r = self.s.post(BASE + "/api/auth/native/restart", impersonate=self.fp,
                        headers=self._h(HEADERS_JSON), data=json.dumps({"resume": resume}))
        if r.status_code != 201:
            raise MuseError(f"restart {r.status_code}: {r.text[:120]}")
        self.csrf = self._json(r).get("csrf_token")
        if not self.csrf:
            raise MuseError("restart 未返回 csrf_token")
        return self.csrf

    def _auth_headers(self):
        h = self._h(HEADERS_JSON)
        if self.csrf:
            h["X-Hatch-CSRF-Token"] = self.csrf
            h["X-Hatch-Waterfall-Id"] = self.waterfall_id
            h["X-Hatch-Caa-Reg-Entry-Point"] = "login_home"
        return h

    def send_otp(self, email):
        r = self.s.post(BASE + "/api/auth/native/send-otp", impersonate=self.fp,
                        headers=self._auth_headers(), data=json.dumps({"contact_point": email}))
        if r.status_code not in (200, 201):
            raise MuseError(f"send-otp {r.status_code}: {r.text[:120]}")
        return self._json(r)

    def confirm_otp(self, code):
        """关键：supports_muse_link_transparency 必须为 true"""
        r = self.s.post(BASE + "/api/auth/native/confirm-otp", impersonate=self.fp,
                        headers=self._auth_headers(),
                        data=json.dumps({"otp_code": code,
                                         "remember_device": True,
                                         "supports_muse_link_transparency": True}))
        if r.status_code != 200:
            raise MuseError(f"confirm-otp {r.status_code}: {r.text[:120]}")
        data = self._json(r)
        tos = data.get("tos")
        if (isinstance(tos, dict) and isinstance(tos.get("content_version"), str)
                and tos["content_version"].strip()):
            # register-completion 必须用服务端动态返回的版本，不再用硬编码常量
            self.tos_content_version = tos["content_version"]
        return data

    def register_completion(self, date_of_birth, first_name, last_name, remember_device=True):
        """
        完成注册。注意字段语义：
          first_name = 名（given name）
          last_name  = 姓（family name）
        生日早于约 18 年前会被服务端拒绝（403）。
        """
        body = {
            "date_of_birth": date_of_birth,
            "first_name": first_name,
            "last_name": last_name,
            "tos_content_version": self.tos_content_version or TOS_VERSION,
            "remember_device": remember_device,
        }
        r = self.s.post(BASE + "/api/auth/native/register-completion", impersonate=self.fp,
                        headers=self._auth_headers(), data=json.dumps(body))
        if r.status_code != 200:
            raise MuseError(f"register-completion {r.status_code}: {r.text[:120]}")
        data = self._json(r)
        self.account_id = (data.get("auth_meta_session") or {}).get("frl_account_id")
        return data

    def session_cookie(self, name="hatch_sess"):
        for c in self.s.cookies.jar:
            if c.name == name:
                return c.value
        return None

    # ---------- 激活 ----------

    def _trusted_location(self, location, base_url):
        """校验并解析 3xx 的 Location（相对路径按当前 URL 解析）。

        只接受 https + 受信域（auth.meta.com / auth.muse.ai / muse.ai），
        拒绝 userinfo、非 443 端口与含反斜杠/空白的目标。
        """
        if (not isinstance(location, str) or not location
                or "\\" in location or any(ch.isspace() for ch in location)):
            raise MuseError("activate_session 重定向 Location 非法")
        parts = urlsplit(urljoin(base_url, location))
        if (parts.scheme != "https" or parts.hostname not in TRUSTED_HOSTS
                or parts.username is not None or parts.password is not None
                or parts.port not in (None, 443)):
            raise MuseError("activate_session 重定向目标不受信任")
        return urlunsplit(("https", parts.hostname, parts.path or "/", parts.query, ""))

    def activate_session(self, frl_access_token):
        """会话引导（register-completion 之后、accept-tos 之前必须调用）。

        POST https://auth.meta.com/hatch/session/bootstrap/，form 表单只带
        frl_access_token，allow_redirects=False 手动跟随 301/302/303 下一跳，
        最终应落到 muse.ai 200 HTML 文档。从文档中解析动态披露与状态门：
          - resolvedDestination=="waitlist" 或 isGeoGated=True
                → MuseError("region_waitlist")（账号已注册但地区受限，未证明已加入名单）
          - 披露文本/版本冲突或缺失 → MuseError("disclosure_context_unresolved")
          - 仅支持 disclosureVersion=="HATCH_ROW_v0"，未知版本不猜参数
        成功返回 dict（含 disclosure_text / disclosure_version / source_url），
        直接传给 accept_tos()。
        """
        if not isinstance(frl_access_token, str) or not frl_access_token.strip():
            raise MuseError("activate_session 缺少 frl_access_token")
        url, method, hops = BOOTSTRAP_URL, "POST", 0
        while True:
            headers = self._h(HEADERS_HTML)
            if method == "POST":
                headers.update({
                    "content-type": "application/x-www-form-urlencoded",
                    "origin": BASE,
                    "referer": BASE + "/",
                    "sec-fetch-dest": "document",
                    "sec-fetch-mode": "navigate",
                    "sec-fetch-site": "cross-site",
                    "upgrade-insecure-requests": "1",
                    "cache-control": "max-age=0",
                    "priority": "u=0, i",
                })
                r = self.s.post(url, impersonate=self.fp, headers=headers,
                                data=urlencode({"frl_access_token": frl_access_token}),
                                allow_redirects=False)
            else:
                r = self.s.get(url, impersonate=self.fp, headers=headers,
                               allow_redirects=False)
            if r.status_code in (301, 302, 303):
                hops += 1
                if hops > 6:
                    raise MuseError("activate_session 重定向次数过多")
                url, method = self._trusted_location(r.headers.get("location"), url), "GET"
                continue
            break
        if r.status_code != 200:
            raise MuseError(f"activate_session 引导失败 {r.status_code}: {r.text[:120]}")
        final = urlsplit(url)
        if final.hostname != "muse.ai":
            raise MuseError(f"activate_session 最终落在非 muse.ai 域（{final.hostname}）")
        onboarding = parse_onboarding(r.text)
        if onboarding["state"] == "waitlist":
            raise MuseError("region_waitlist")
        if onboarding["state"] != "disclosure":
            raise MuseError(f"disclosure_context_unresolved ({onboarding.get('reason')})")
        onboarding["source_url"] = urlunsplit(("https", final.hostname, final.path or "/", "", ""))
        self.onboarding = onboarding
        return onboarding

    def accept_tos(self, onboarding=None):
        """必须调用，否则后续 hatch 接口一律 403。单次调用即可，不重试。

        onboarding 必须是 activate_session() 返回的解析结果：正文取服务端
        动态返回的 disclosure_text / disclosure_version（不再用硬编码常量），
        Referer 用实际披露页 URL。
        """
        text = (onboarding or {}).get("disclosure_text")
        version = (onboarding or {}).get("disclosure_version")
        if not text or not version:
            raise MuseError("accept_tos 缺少动态披露结果，请先调用 activate_session()")
        body = {
            "saw_meta_ai_tos": False,
            "client_request_timestamp": str(int(time.time())),
            "entry_point": "web_onboarding_flow",
            "nux_type": "ROW",
            "disclosure_version": version,
            "disclosure_text": text,
        }
        headers = self._h(HEADERS_JSON)
        referer = (onboarding or {}).get("source_url")
        if referer:
            headers["referer"] = referer
        r = self.s.post(BASE + "/api/hatch/accept-tos", impersonate=self.fp,
                        headers=headers, data=json.dumps(body))
        if r.status_code == 403:
            raise MuseError(f"accept-tos 403: {r.text[:200]}")
        if r.status_code != 200:
            raise MuseError(f"accept-tos {r.status_code}: {r.text[:200]}")
        return r

    def invite(self):
        return self.s.get(BASE + "/api/hatch/invite", impersonate=self.fp,
                          headers=self._h(HEADERS_GET))

    def is_live(self):
        """invite 200 = 有效账号；401/403 = 无 hatch 权限"""
        try:
            return self.invite().status_code == 200
        except Exception:
            return False

    def wake_vm(self):
        """必须调用，否则兑换会返回误导性的 invalid。

        首连 wake_trigger 用 "mount"，body 带 open_id（新 uuid）与 away_ms=0；
        wake 前先 GET /?aymh_complete=1 从文档里解析 vmId（保留原有逻辑）。
        """
        r = self.s.get(BASE + "/?aymh_complete=1", impersonate=self.fp,
                       headers=self._h(HEADERS_HTML))
        m = re.search(r'vmId[\\"]*:[\\"]*([0-9a-fA-F-]{36})', r.text)
        if not m:
            return None
        vm_id = m.group(1)
        r = self.s.post(BASE + "/api/hatch/vm/wake", impersonate=self.fp,
                    headers=self._h(HEADERS_JSON),
                    data=json.dumps({"vm_id": vm_id,
                                     "retry_count": 0,
                                     "connect_attempt_id": _uuid(),
                                     "wake_trigger": "mount",
                                     "open_id": _uuid(),
                                     "away_ms": 0}))
        # 之前这里不看 wake 的返回就直接当成功：wake 失败时兑换会误报 invalid，
        # 调用方却以为 vm 已唤醒。非 200 一律当未唤醒，让 runner 走 vm_unresolved。
        if r.status_code != 200:
            return None
        return vm_id

    def stateful_sharing(self):
        r = self.s.post(BASE + "/api/hatch/stateful-sharing", impersonate=self.fp,
                        headers=self._h(HEADERS_JSON), data="")
        if r.status_code != 200:
            raise MuseError(f"stateful-sharing {r.status_code}: {r.text[:120]}")
        return r

    # ---------- 兑换 ----------

    def redeem(self, code):
        """
        兑换邀请码。返回 (ok, reason)。
          reason: redeemed | already_redeemed | used_up | invalid
        """
        r = self.s.post(BASE + "/api/hatch/invite-code/redeem", impersonate=self.fp,
                        headers=self._h(HEADERS_JSON),
                        data=json.dumps({"code": code, "supportsRedemptionStatus": True}))
        # 之前用 '"success":true' 子串匹配正文：带空格的 {"success": true}、
        # 嵌套字段里出现 success=true 都会误判/漏判。按 JSON 字段判定。
        data = self._json(r)
        if r.status_code == 200 and data.get("success") is True:
            return True, "redeemed"
        reason = data.get("reason") or data.get("redemptionStatus")
        if r.status_code == 200 and reason == "redeemed":
            return True, "redeemed"
        return False, reason or f"http-{r.status_code}"

    def scratch_code(self):
        """兑换成功后取回本账号已分配的邀请码。

        注意：POST /api/hatch/invite 只返回（自己的）邀请码本身，
        并不等于把页面上已刮开的码再"刮开/揭示"（reveal）一次。
        """
        r = self.s.post(BASE + "/api/hatch/invite", impersonate=self.fp,
                        headers=self._h(HEADERS_JSON), data="")
        if r.status_code != 200:
            return None
        return self._json(r).get("code")


def _uuid():
    return str(uuid.uuid4())


def _flight_chunks(text):
    """抽取 self.__next_f.push 序列化的字符串数据（纯文本解析，不执行任何脚本）。"""
    chunks = []
    if not isinstance(text, str):
        return chunks
    for script in re.findall(r"<script\b[^>]*>(.*?)</script\s*>", text, re.IGNORECASE | re.DOTALL):
        match = re.fullmatch(r"\s*self\.__next_f\.push\((.*)\)\s*;?\s*", script, re.DOTALL)
        if not match:
            continue
        try:
            value = json.loads(match.group(1))
        except (ValueError, TypeError):
            continue
        if (isinstance(value, list) and len(value) == 2 and value[0] == 1
                and isinstance(value[1], str)):
            chunks.append(value[1])
    return chunks


def parse_onboarding(html):
    """解析 muse.ai 引导文档里的 Next Flight 数据（离线纯函数，不发请求）。

    返回 dict：state = disclosure | waitlist | unresolved。
      - resolvedDestination=="waitlist" 或 isGeoGated is True → state="waitlist"
      - 披露文本/版本冲突或缺失 → state="unresolved"（不猜测参数）
      - 仅支持 disclosureVersion=="HATCH_ROW_v0"，未知版本同样 unresolved
    status 字段（isGeoGated / hasHatchAccess / waitlistStatus）原样透传。
    """
    states, disclosures = [], []
    objects = []

    def collect(value):
        # 迭代收集，不用递归：服务端返回的嵌套 JSON 很深时递归会触发
        # RecursionError；栈式遍历对任意深度都安全。
        stack = [value]
        while stack:
            item = stack.pop()
            if isinstance(item, dict):
                objects.append(item)
                stack.extend(item.values())
            elif isinstance(item, list):
                stack.extend(item)

    for row in "".join(_flight_chunks(html)).splitlines():
        row_id, separator, data = row.partition(":")
        if not separator or not re.fullmatch(r"[0-9a-f]+", row_id):
            continue
        try:
            collect(json.loads(data))
        except (ValueError, TypeError):
            continue  # 模块/文本导入等非 JSON 数据行
    for obj in objects:
        if "resolvedDestination" in obj and isinstance(obj.get("status"), dict):
            status = obj["status"]
            states.append({
                "resolved_destination": obj.get("resolvedDestination"),
                "is_geo_gated": status.get("isGeoGated"),
                "has_hatch_access": status.get("hasHatchAccess"),
                "waitlist_status": status.get("waitlistStatus"),
            })
        if "disclosureText" in obj or "disclosureVersion" in obj:
            disclosures.append((obj.get("disclosureText"), obj.get("disclosureVersion")))
    if states:
        if len({json.dumps(s, sort_keys=True) for s in states}) > 1:
            return {"state": "unresolved", "reason": "onboarding_state_conflict"}
        if (states[0]["resolved_destination"] == "waitlist"
                or states[0]["is_geo_gated"] is True):
            return {"state": "waitlist", "reason": "onboarding_waitlist", **states[0]}
    texts = list(dict.fromkeys(t for t, _ in disclosures
                               if isinstance(t, str) and t.strip()))
    versions = list(dict.fromkeys(v for _, v in disclosures
                                  if isinstance(v, str) and v.strip()))
    if len(texts) != 1 or len(versions) != 1:
        return {"state": "unresolved", "reason": "disclosure_context_unresolved"}
    if versions[0] != "HATCH_ROW_v0":
        return {"state": "unresolved", "reason": "disclosure_version_unsupported",
                "disclosure_version": versions[0]}
    out = {"state": "disclosure", "reason": "disclosure_context_observed",
           "disclosure_text": texts[0], "disclosure_version": versions[0]}
    if states:
        out.update(states[0])
    return out


def random_dob(min_year=1970, max_year=1999):
    return (f"{random.randint(min_year, max_year)}-"
            f"{random.randint(1, 12):02d}-"
            f"{random.randint(1, 28):02d}")
