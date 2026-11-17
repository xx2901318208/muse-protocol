"""离线冒烟：musepy.client.parse_onboarding 纯函数（不联网、不执行页面脚本）。

运行：python test_onboarding_smoke.py
用例：正常披露 / waitlist / 披露冲突，外加一条非 push 脚本混入的干扰项。
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from musepy.client import parse_onboarding


def _html(*push_chunks):
    """合成一个带 self.__next_f.push 的 muse.ai 风格文档。"""
    scripts = []
    for chunk in push_chunks:
        scripts.append(
            "<script>self.__next_f.push(%s);</script>" % json.dumps([1, chunk])
        )
    noise = "<script>function notAFlightRecord(){return 0;}</script>"
    return "<html><body>" + noise + "".join(scripts) + "</body></html>"


def _row(row_id, payload):
    # 真实 Flight chunk 以换行结尾，这里保持一致
    return row_id + ":" + json.dumps(payload) + "\n"


def test_normal():
    status = {"result": "success", "resolvedDestination": "main_app",
              "status": {"isGeoGated": False, "hasHatchAccess": True, "waitlistStatus": None}}
    disclosure = {"disclosureText": "次に進むことで同意します。", "disclosureVersion": "HATCH_ROW_v0"}
    doc = _html(_row("1a2b", status), _row("3c4d", disclosure))
    out = parse_onboarding(doc)
    assert out["state"] == "disclosure", out
    assert out["disclosure_text"] == disclosure["disclosureText"], out
    assert out["disclosure_version"] == "HATCH_ROW_v0", out
    assert out["resolved_destination"] == "main_app", out
    assert out["is_geo_gated"] is False and out["has_hatch_access"] is True, out


def test_waitlist():
    status = {"result": "success", "resolvedDestination": "waitlist",
              "status": {"isGeoGated": False, "hasHatchAccess": False, "waitlistStatus": "pending"}}
    doc = _html(_row("a1b2", status),
                _row("c3d4", {"disclosureText": "任意正文", "disclosureVersion": "HATCH_ROW_v0"}))
    out = parse_onboarding(doc)
    assert out["state"] == "waitlist", out
    assert out["resolved_destination"] == "waitlist", out
    assert out["waitlist_status"] == "pending", out


def test_geo_gated():
    status = {"result": "success", "resolvedDestination": "main_app",
              "status": {"isGeoGated": True, "hasHatchAccess": False, "waitlistStatus": None}}
    doc = _html(_row("aa11", status),
                _row("bb22", {"disclosureText": "任意正文", "disclosureVersion": "HATCH_ROW_v0"}))
    out = parse_onboarding(doc)
    assert out["state"] == "waitlist", out
    assert out["is_geo_gated"] is True, out


def test_conflict():
    doc = _html(
        _row("1a2b", {"disclosureText": "版本A的正文", "disclosureVersion": "HATCH_ROW_v0"}),
        _row("3c4d", {"disclosureText": "版本B的正文", "disclosureVersion": "HATCH_ROW_v0"}),
    )
    out = parse_onboarding(doc)
    assert out["state"] == "unresolved", out


def test_missing():
    doc = _html(_row("1a2b", {"unrelated": True}))
    out = parse_onboarding(doc)
    assert out["state"] == "unresolved", out


def test_unknown_version():
    doc = _html(_row("1a2b", {"disclosureText": "正文", "disclosureVersion": "HATCH_UNKNOWN_v9"}))
    out = parse_onboarding(doc)
    assert out["state"] == "unresolved", out
    assert out["reason"] == "disclosure_version_unsupported", out


def main():
    tests = [("normal_disclosure", test_normal), ("waitlist", test_waitlist),
             ("geo_gated", test_geo_gated), ("disclosure_conflict", test_conflict),
             ("disclosure_missing", test_missing), ("unknown_version", test_unknown_version)]
    for name, fn in tests:
        fn()
        print(f"[PASS] {name}")
    print(f"冒烟通过 {len(tests)}/{len(tests)}")


if __name__ == "__main__":
    main()
