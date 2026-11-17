"""离线冒烟：musepy.runner 批量调度语义（mock 网络，不联网）。

覆盖：select_otp 幂等 / wait_otp 轮询 / claim 独占 / sticky 复用与
max_per_ip 换行 / pre-send 重试上限与 tried 标记 / 业务拒绝停批不换行 /
region_waitlist 停止且账号保留 / 预算不超领 / 记录字段无 token/cookie。
运行：python test_runner_smoke.py
"""

import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from musepy.client import MuseError
from musepy.otp import select_otp, wait_otp
from musepy.runner import BatchRunner, mkproxy


# ---------- 假客户端 / 假会话 ----------

class FakeClient:
    """MuseClient 形状的假实现；fail_stage 在指定阶段抛传输异常。"""

    fp = "chrome142"
    lang = "ja"
    s = None

    def __init__(self, fail_stage=None, redeem_ok=True, waitlist=False,
                 live=True, own_code="OWN-CODE"):
        self.fail_stage = fail_stage
        self.redeem_ok = redeem_ok
        self.waitlist = waitlist
        self.live = live
        self.own_code_value = own_code
        self.proxy_url = None
        self.calls = []

    def _fail(self, stage):
        self.calls.append(stage)
        if self.fail_stage == stage:
            raise ConnectionError("connection reset by peer")

    def open_home(self):
        self._fail("bootstrap")

    def restart(self):
        self._fail("restart")

    def send_otp(self, email):
        self._fail("send_otp")

    def confirm_otp(self, code):
        self._fail("confirm_otp")
        return {"registration_state": "completion_required",
                "tos": {"content_version": "v_test"}}

    def register_completion(self, dob, first, last):
        self._fail("completion")
        return {"auth_meta_session": {"frl_access_token": "tok-secret",
                                      "frl_account_id": "uid-1"}}

    def activate_session(self, token):
        self.calls.append("session_bootstrap")
        if self.waitlist:
            raise MuseError("region_waitlist")
        return {"state": "disclosure", "disclosure_text": "T",
                "disclosure_version": "HATCH_ROW_v0",
                "resolved_destination": "main_app"}

    def accept_tos(self, onboarding):
        self._fail("accept_tos")

    def is_live(self):
        return self.live

    def wake_vm(self):
        self._fail("wake")
        return "vm-id-1"

    def stateful_sharing(self):
        self.calls.append("sharing")

    def redeem(self, code):
        return (True, "redeemed") if self.redeem_ok else (False, "invalid")

    def scratch_code(self):
        return self.own_code_value

    def close(self):
        pass


class FakeResponse:
    def __init__(self, status_code, text):
        self.status_code, self.text = status_code, text


class FakeOtpSession:
    def __init__(self, responses):
        self.responses, self.i = responses, 0

    def get(self, url, timeout=None, headers=None):
        item = self.responses[min(self.i, len(self.responses) - 1)]
        self.i += 1
        return item

    def close(self):
        pass


# ---------- 测试脚手架 ----------

def make_runner(tmp, email_lines, proxy_lines, count, maker, *, codes=None, **overrides):
    otp_file = os.path.join(tmp, "otp.txt")
    with open(otp_file, "w", encoding="utf-8") as f:
        f.write("\n".join(email_lines) + "\n")
    proxy_file = os.path.join(tmp, "proxy.txt")
    with open(proxy_file, "w", encoding="utf-8") as f:
        f.write("\n".join(proxy_lines) + "\n")
    cfg = {"otp_file": otp_file, "proxy_file": proxy_file,
           "output_dir": os.path.join(tmp, "out"),
           "tried_file": os.path.join(tmp, "tried.txt"),
           "workers": 1, "max_per_ip": 6, "resolve_ip": False,
           "send_caa": False, "lang": "ja", "impersonate": "chrome142"}
    if codes is not None:
        codes_file = os.path.join(tmp, "codes.txt")
        with open(codes_file, "w", encoding="utf-8") as f:
            f.write("\n".join(codes) + "\n")
        cfg["codes_file"] = codes_file
    cfg.update(overrides)
    clients = []

    def factory(proxy_url):
        client = maker()
        client.proxy_url = proxy_url
        clients.append(client)
        return client

    runner = BatchRunner(cfg, client_factory=factory,
                         otp_waiter=lambda email, url, after: "123456")
    runner.init(count)
    return runner, clients


def record_path(tmp, email):
    return os.path.join(tmp, "out", email + ".json")


def load_record(tmp, email):
    with open(record_path(tmp, email), encoding="utf-8") as f:
        return json.load(f)


def tried_lines(tmp):
    path = os.path.join(tmp, "tried.txt")
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


EMAILS = [f"e{i}@x.test----https://otp.example/{i}" for i in range(3)]
PROXIES = ["10.0.0.1:8000:u:p", "10.0.0.2:8001:u:p", "10.0.0.3:8002:u:p"]


# ---------- 用例 ----------

def test_select_otp_idempotent():
    before = "2026-01-01T00:00:00+00:00"
    after = "2026-01-01T00:01:00+00:00"
    records = [{"otp": "111111", "time": before},   # 早于 send 开始 → 排除
               {"otp": "222222", "time": after},
               {"otp": "333333", "time": after}]    # 最新一秒两个码 → 歧义
    assert select_otp(records, after) is None
    assert select_otp(records[:1], after) is None
    ok = [{"otp": "111111", "time": before},
          {"otp": "444444", "time": "2026-01-01T00:02:00+00:00"}]
    assert select_otp(ok, after) == "444444"
    # 幂等：把边界推到该码之后，同一份记录不再返回旧码
    assert select_otp(ok, "2026-01-01T00:02:00+00:00") is None


def test_wait_otp_poll():
    after = "2026-01-01T00:00:00Z"
    responses = [
        FakeResponse(200, json.dumps([{"otp": "000000",
                                       "time": "2025-12-31T23:59:00+00:00"}])),
        FakeResponse(200, json.dumps([{"otp": "123456",
                                       "time": "2026-01-01T00:00:30+00:00"}])),
    ]
    otp = wait_otp("https://otp.example/1", after, timeout=5, poll_interval=0,
                   session_factory=lambda: FakeOtpSession(responses))
    assert otp == "123456"
    none = wait_otp("https://otp.example/1", after, timeout=0.01, poll_interval=0,
                    session_factory=lambda: FakeOtpSession([
                        FakeResponse(200, json.dumps([]))]))
    assert none is None


def test_claim_exclusive():
    with tempfile.TemporaryDirectory() as d:
        runner, _ = make_runner(d, EMAILS[:1], PROXIES[:2], 1, FakeClient)
        runner._proxy_claims.add(PROXIES[0])          # 其他 worker 已占用
        line, _ = runner._pick_proxy()
        assert line == PROXIES[1], line               # 不抢他人的行
        runner._proxy_claims.add(PROXIES[1])
        line, _ = runner._pick_proxy()                # 池耗尽 → 共享 + 日志
        assert line in PROXIES, line
        line, _ = runner._pick_proxy(current=PROXIES[0])
        assert line == PROXIES[0], line               # sticky：复用自己的行


def test_sticky_reuse_and_switch():
    with tempfile.TemporaryDirectory() as d:
        runner, clients = make_runner(d, EMAILS, PROXIES[:2], 3, FakeClient,
                                      codes=["C1", "C2", "C3"], max_per_ip=2)
        runner.run()
        s = runner.summary()
        assert s["ok"] == 3 and s["ip_switches"] == 1, s
        urls = [c.proxy_url for c in clients]
        assert urls[0] == urls[1]                     # 同一条 sticky 代理复用多个账号
        other = [mkproxy(p) for p in PROXIES[:2] if mkproxy(p) != urls[0]][0]
        assert urls[2] == other                       # 达 max_per_ip 后换到另一条


def test_presend_retry_cap():
    with tempfile.TemporaryDirectory() as d:
        runner, clients = make_runner(d, EMAILS, PROXIES, 2,
                                      lambda: FakeClient(fail_stage="bootstrap"))
        runner.run()
        s = runner.summary()
        assert s["started"] == 2 and s["ok"] == 0, s
        assert s["transport_error"] == 8, s           # 每邮箱 1+3 次尝试都计入 stats
        assert s["ip_switches"] == 6, s               # 每邮箱 3 次换代理重试
        assert s["remaining"] == 0 and s["stopped"] is False, s
        assert len(clients) == 8, len(clients)        # 每邮箱 1 + 3 次换代理重试
        tried = tried_lines(d)
        assert "e0@x.test" in tried and "e1@x.test" in tried
        assert "e2@x.test" not in tried               # 第三个邮箱未被消耗


def test_business_reject_stops():
    with tempfile.TemporaryDirectory() as d:
        runner, clients = make_runner(d, EMAILS, PROXIES[:2], 2,
                                      lambda: FakeClient(redeem_ok=False),
                                      codes=["C1", "C2"])
        runner.run()
        s = runner.summary()
        assert s["started"] == 1 and s["server_rejected"] == 1, s
        assert s["stopped"] is True and s["stop_reason"] == "workflow_paused", s
        assert s["ip_switches"] == 0, s               # 业务拒绝不换行
        assert len({c.proxy_url for c in clients}) == 1
        rec = load_record(d, "e0@x.test")
        # 已注册但兑换未成功：status 口径与本地一致（outcome 仍计入 server_rejected）
        assert rec["status"] == "registered_pending_redemption", rec
        assert rec["registered"] is True and rec["stage"] == "redeem", rec
        assert rec["last_error"].startswith("redemption_unverified"), rec


def test_region_waitlist():
    with tempfile.TemporaryDirectory() as d:
        runner, _ = make_runner(d, EMAILS, PROXIES[:2], 2,
                                lambda: FakeClient(waitlist=True),
                                codes=["C1", "C2"])
        runner.run()
        s = runner.summary()
        assert s["started"] == 1 and s["stopped"] is True, s
        rec = load_record(d, "e0@x.test")
        assert rec["status"] == "registered_waitlist", rec   # 账号保留
        assert rec["registered"] is True and rec["stage"] == "session_bootstrap", rec
        assert rec["last_error"] == "region_waitlist", rec


def test_budget_no_replenish():
    with tempfile.TemporaryDirectory() as d:
        runner, _ = make_runner(d, EMAILS, PROXIES[:1], 1, FakeClient, codes=["C1"])
        assert runner.summary()["queued"] == 1
        runner.run()
        s = runner.summary()
        assert s["started"] == 1 and s["ok"] == 1 and s["remaining"] == 0, s
        tried = tried_lines(d)
        assert "e0@x.test" in tried and "e1@x.test" not in tried and "e2@x.test" not in tried
        assert not os.path.exists(record_path(d, "e1@x.test"))
        assert not os.path.exists(record_path(d, "e2@x.test"))


def test_record_fields_no_secrets():
    with tempfile.TemporaryDirectory() as d:
        runner, _ = make_runner(d, EMAILS[:1], PROXIES[:1], 1, FakeClient, codes=["C1"])
        runner.run()
        rec = load_record(d, "e0@x.test")
        for key in ("email", "status", "stage", "registered", "own_code",
                    "own_code_status", "reveal_status", "is_revealed", "ip", "last_error"):
            assert key in rec, key
        assert rec["status"] == "redeemed" and rec["own_code"] == "OWN-CODE", rec
        assert rec["own_code_status"] == "available", rec
        assert rec["reveal_status"] == "not_attempted" and rec["is_revealed"] is None, rec
        with open(record_path(d, "e0@x.test"), encoding="utf-8") as f:
            text = f.read()
        assert "frl_access_token" not in text and "hatch_sess" not in text
        assert "tok-secret" not in text


def main():
    tests = [("select_otp_idempotent", test_select_otp_idempotent),
             ("wait_otp_poll", test_wait_otp_poll),
             ("claim_exclusive", test_claim_exclusive),
             ("sticky_reuse_and_switch", test_sticky_reuse_and_switch),
             ("presend_retry_cap", test_presend_retry_cap),
             ("business_reject_stops", test_business_reject_stops),
             ("region_waitlist", test_region_waitlist),
             ("budget_no_replenish", test_budget_no_replenish),
             ("record_fields_no_secrets", test_record_fields_no_secrets)]
    for name, fn in tests:
        fn()
        print(f"[PASS] {name}")
    print(f"冒烟通过 {len(tests)}/{len(tests)}")


if __name__ == "__main__":
    main()
