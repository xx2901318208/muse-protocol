"""回归测试：本次改进修掉的 bug（离线，mock 网络）。

运行：python -m pytest test_fixes.py -q
覆盖：waterfall_id 全程固定 / redeem 按 JSON 判定而非子串 /
wake 非 200 返回 None / mkproxy 密码含冒号 / OTP 源 500 后继续轮询。
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from musepy.client import MuseClient
from musepy.otp import wait_otp
from musepy.runner import BatchRunner, mkproxy, proxy_endpoint
from musepy.temp_mail import (
    GeneratorMail,
    extract_codes,
    html_to_text,
    parse_inbox,
    select_new_code,
)


class FakeResponse:
    def __init__(self, status_code=200, text="", payload=None):
        self.status_code = status_code
        self.text = text
        self._payload = payload

    def json(self):
        if self._payload is not None:
            return self._payload
        return json.loads(self.text)


class FakeSession:
    """按 URL 分流的假会话：get/post 返回预设响应。"""

    def __init__(self, get_map=None, post_map=None):
        self.get_map = get_map or {}
        self.post_map = post_map or {}

    def _match(self, mapping, url):
        for key, resp in mapping.items():
            if key in url:
                return resp
        return FakeResponse(404, "")

    def get(self, url, **kwargs):
        return self._match(self.get_map, url)

    def post(self, url, **kwargs):
        return self._match(self.post_map, url)

    def close(self):
        pass


def test_waterfall_id_stable():
    c = MuseClient()
    c.csrf = "csrf-test"
    try:
        h1 = c._auth_headers()
        h2 = c._auth_headers()
        assert h1["X-Hatch-Waterfall-Id"] == h2["X-Hatch-Waterfall-Id"]
        assert h1["X-Hatch-Waterfall-Id"] == c.waterfall_id
    finally:
        c.close()


def test_redeem_json_with_spaces():
    c = MuseClient()
    # 带空格的 {"success": true}：旧的子串 '"success":true' 匹配不到，会误判失败
    c.s = FakeSession(post_map={
        "invite-code/redeem": FakeResponse(200, '{"success": true}',
                                           {"success": True}),
    })
    ok, reason = c.redeem("CODE-1")
    assert (ok, reason) == (True, "redeemed")
    c.s = FakeSession(post_map={
        "invite-code/redeem": FakeResponse(200, '{"success": false, "reason": "used_up"}',
                                           {"success": False, "reason": "used_up"}),
    })
    assert c.redeem("CODE-1") == (False, "used_up")


def test_wake_vm_failure_returns_none():
    c = MuseClient()
    html = '<html>vmId: "123e4567-e89b-12d3-a456-426614174000"</html>'
    c.s = FakeSession(
        get_map={"aymh_complete": FakeResponse(200, html)},
        post_map={"vm/wake": FakeResponse(500, "error")},
    )
    assert c.wake_vm() is None


def test_mkproxy_password_with_colon():
    url = mkproxy("10.0.0.1:8080:user:p:a:b")
    assert url == "http://user:p%3Aa%3Ab@10.0.0.1:8080", url
    assert mkproxy("10.0.0.1:8080") == "http://10.0.0.1:8080"
    assert mkproxy("http://u:p@10.0.0.1:8080") == "http://u:p@10.0.0.1:8080"
    # 日志用的 endpoint 绝不能带凭据
    assert proxy_endpoint("10.0.0.1:8080:user:secret") == "10.0.0.1:8080"


def test_wait_otp_retries_after_500():
    after = "2026-01-01T00:00:00Z"
    responses = [
        FakeResponse(500, "boom"),
        FakeResponse(200, json.dumps([{"otp": "123456",
                                       "time": "2026-01-01T00:00:30+00:00"}])),
    ]

    class Session:
        def __init__(self):
            self.i = 0

        def get(self, url, timeout=None, headers=None):
            item = responses[min(self.i, len(responses) - 1)]
            self.i += 1
            return item

        def close(self):
            pass

    otp = wait_otp("https://otp.example/1", after, timeout=5, poll_interval=0,
                   session_factory=Session)
    assert otp == "123456"


# ---------- generator.email 临时邮箱 ----------

def test_temp_mail_extract_codes():
    html = ("<html><body><table><tr><td>Meta</td><td>Use code 375900 to log in</td>"
            "<td>Hi Christopher, Login code 375900</td></tr>"
            "<tr><td>Meta</td><td>Did you just add an email address?</td></tr>"
            "</table></body></html>")
    assert html_to_text(html).count("375900") == 2
    assert extract_codes(html_to_text(html)) == ["375900"]
    parsed = parse_inbox(html)
    assert parsed["codes"] == ["375900"]
    # send 前已有 111111，send 后只认新码；同轮两个新码视为歧义
    assert select_new_code("code 111111 and 222222", {"111111"}) == "222222"
    assert select_new_code("code 222222 and 333333", {"111111"}) is None
    assert select_new_code("code 111111", {"111111"}) is None


def test_temp_mail_wait_otp_with_fake_session():
    inbox_html = [
        "<html><body>No messages yet</body></html>",
        "<html><body>Meta Use code 654321 to log in</body></html>",
    ]

    class Session:
        def __init__(self):
            self.i = 0
            self.cookies = self

        def set(self, *args, **kwargs):
            pass

        def get(self, url, **kwargs):
            item = inbox_html[min(self.i, len(inbox_html) - 1)]
            self.i += 1
            return FakeResponse(200, item)

        def close(self):
            pass

    mail = GeneratorMail("abc123@example.test", session_factory=Session)
    assert mail.wait_otp((), timeout=5, poll_interval=0) == "654321"


def test_temp_mail_generate_uses_fallback_domains():
    from musepy.temp_mail import FALLBACK_DOMAINS, generate_email

    class Session:
        def __init__(self):
            self.cookies = self

        def set(self, *args, **kwargs):
            pass

        def get(self, url, **kwargs):
            return FakeResponse(200, "<html></html>")

        def close(self):
            pass

    # search.php 拿不到域名（返回空）时用兜底域名，不直接报错
    email, mail = generate_email(session_factory=Session,
                                 domain_fetcher=lambda: [])
    assert email.split("@")[1] in FALLBACK_DOMAINS
    mail.close()


def test_temp_mail_refresh_and_switch():
    html = "<html><body>Meta Use code 654321 to log in</body></html>"

    class Session:
        def __init__(self):
            self.cookies = self

        def set(self, *args, **kwargs):
            pass

        def get(self, url, **kwargs):
            return FakeResponse(200, html)

        def close(self):
            pass

    mail = GeneratorMail("abc123@example.test", session_factory=Session)
    assert mail.refresh()["codes"] == ["654321"]
    assert mail.refresh_codes() == ["654321"]
    old = mail.email
    new = mail.switch_to_new_email(domain_fetcher=lambda: ["example.test"])
    assert new != old and new.endswith("@example.test") and mail.email == new
    assert mail.switch_to_email("manual@example.test") == "manual@example.test"


def test_runner_temp_mail_switch_on_otp_timeout():
    import tempfile

    from test_runner_smoke import FakeClient

    with tempfile.TemporaryDirectory() as d:
        proxy_file = os.path.join(d, "proxy.txt")
        with open(proxy_file, "w", encoding="utf-8") as f:
            f.write("10.0.0.1:8000:u:p\n")
        codes_file = os.path.join(d, "codes.txt")
        with open(codes_file, "w", encoding="utf-8") as f:
            f.write("C1\n")
        cfg = {"proxy_file": proxy_file, "codes_file": codes_file,
               "output_dir": os.path.join(d, "out"),
               "tried_file": os.path.join(d, "tried.txt"),
               "workers": 1, "max_per_ip": 6, "resolve_ip": False,
               "send_caa": False, "temp_mail": True,
               "temp_mail_max_switches": 1}
        generated = iter([("tmp1@example.test", ()), ("tmp2@example.test", ())])
        calls = []

        def waiter(email, url, after):
            calls.append(email)
            return None if len(calls) == 1 else "123456"

        runner = BatchRunner(cfg, client_factory=lambda proxy_url: FakeClient(),
                             otp_waiter=waiter)
        runner.email_generator = lambda: next(generated)
        assert runner.init(1) == 1
        runner.run()
        s = runner.summary()
        assert s["ok"] == 1, s
        assert calls == ["tmp1@example.test", "tmp2@example.test"], calls
        # 记录按最终邮箱落盘，旧邮箱没有记录文件
        assert os.path.exists(os.path.join(d, "out", "tmp2@example.test.json"))
        assert not os.path.exists(os.path.join(d, "out", "tmp1@example.test.json"))


def test_runner_temp_mail_mode_uses_generated_emails():
    import tempfile

    from test_runner_smoke import FakeClient

    with tempfile.TemporaryDirectory() as d:
        proxy_file = os.path.join(d, "proxy.txt")
        with open(proxy_file, "w", encoding="utf-8") as f:
            f.write("10.0.0.1:8000:u:p\n")
        cfg = {"proxy_file": proxy_file,
               "output_dir": os.path.join(d, "out"),
               "tried_file": os.path.join(d, "tried.txt"),
               "workers": 1, "max_per_ip": 6, "resolve_ip": False,
               "send_caa": False, "temp_mail": True}
        generated = iter([("tmp1@example.test", ()), ("tmp2@example.test", ())])
        runner = BatchRunner(
            cfg, client_factory=lambda proxy_url: FakeClient(),
            otp_waiter=lambda email, url, after: "123456")
        runner.email_generator = lambda: next(generated)
        assert runner.init(2) == 2
        assert runner.QUEUE == ["tmp1@example.test", "tmp2@example.test"]
        assert runner.ROWS["tmp1@example.test"] == "generator:tmp1@example.test"
