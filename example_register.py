"""完整注册 + 兑换流程示例。运行前请填写 config.json（见 config.example.json）。"""

import json
import os
import re
import sys
import time
import uuid

# 之前是 dirname(dirname(__file__))：从仓库外其他目录运行时会把仓库
# 的父目录加进 sys.path，musepy 反而找不到了。example 就在仓库根目录，
# 正确的就是它自己的目录（和 example_batch.py 一致）。
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from musepy import caa, falco
from musepy.client import MuseClient, MuseError, random_dob
from musepy.temp_mail import TempMailError, generate_email


def load_config(path="config.json"):
    if not os.path.exists(path):
        raise SystemExit(f"缺少配置文件 {path}，请从 config.example.json 复制并填写")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def read_otp_code(path):
    """从文件读单个 6 位验证码；文件不存在 / 内容不是 6 位数字时返回 None。

    注意：这里的 otp_file 是“只含一个验证码”的文件，别和批量模式的
    otp_file（email----otp源URL 清单）搞混。之前是
    `otp_file and open(...).read() or input(...)`：文件句柄不关、
    空文件会静默 fallback 到 input、非 6 位内容也会直接拿去 confirm。
    """
    if not path or not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        code = f.read().strip()
    return code if re.fullmatch(r"[0-9]{6}", code) else None


def main():
    cfg = load_config()

    email = cfg.get("email") or ""
    proxy = cfg.get("proxy") or None
    invite_code = cfg.get("invite_code") or ""
    otp_file = cfg.get("otp_file")  # 可选：从文件读取当前验证码
    temp_mail_timeout = int(cfg.get("temp_mail_timeout", 120) or 120)

    # ---- 临时邮箱（可选）：temp_mail=true 或 email 为空时自动生成 ----
    # 生成后立刻快照收件箱（正常为空），send 之后只认快照外的新码。
    mail = None
    seen_before = ()
    if cfg.get("temp_mail") or not email:
        try:
            email, mail = generate_email(
                domains=cfg.get("temp_mail_domains"),
                proxy=proxy,
                impersonate=cfg.get("impersonate", "chrome142"),
            )
        except TempMailError as exc:
            raise SystemExit(f"临时邮箱生成失败: {exc}（请检查网络/代理，或改填 email 走手动邮箱）")
        try:
            seen_before = tuple(mail.fetch_codes())
        except TempMailError:
            seen_before = ()
        print(f"[0] 临时邮箱已生成  {email}")

    c = MuseClient(proxy=proxy, impersonate=cfg.get("impersonate", "chrome142"),
                   lang=cfg.get("lang", "ja"))

    print(f"[1] 打开首页  {email}")
    c.open_home()

    # ---- 可选的漏斗埋点 ----
    # waterfall_id 与 client 共用同一个，否则服务端看到两条断裂的漏斗。
    funnel = caa.Caa(c.fp, c.lang, waterfall_id=c.waterfall_id)

    # 拿验证码阶段（可切换邮箱重试）：临时邮箱等不到码时，换一个新邮箱、
    # 从 restart 重新走一遍；手动邮箱没有“换邮箱”这一说，只试一次。
    # temp_mail_max_switches 默认 2，即最多 1 个初始邮箱 + 2 次切换。
    max_switches = int(cfg.get("temp_mail_max_switches", 2) or 0) if mail is not None else 0
    code = None
    for attempt in range(max_switches + 1):
        print(f"[2] 重启注册流程  {email}")
        c.restart()
        if cfg.get("send_caa", True):
            funnel.page_shown(c.s)
            time.sleep(2)
            funnel.focus(c.s)
            time.sleep(0.5)
            funnel.continue_clicked(c.s)
            funnel.registration_start(c.s)

        print("[3] 发送验证码")
        c.send_otp(email)

        # 验证码来源优先级：临时邮箱收件箱 > otp_file 文件 > 手动输入
        if mail is not None:
            print(f"[3.1] 等临时邮箱收件（最长 {temp_mail_timeout} 秒，"
                  f"第 {attempt + 1}/{max_switches + 1} 个邮箱）…")
            code = mail.wait_otp(seen_before, timeout=temp_mail_timeout)
            if code is not None:
                break
            if attempt >= max_switches:
                raise SystemExit(
                    f"临时邮箱里没等到新验证码，已换 {max_switches} 次仍超时，"
                    "请检查出口节点/域名是否被拦后重试")
            # 切换：旧邮箱丢弃，换新邮箱重新 restart → send → 等码
            old_email = email
            try:
                email = mail.switch_to_new_email(domains=cfg.get("temp_mail_domains"))
            except TempMailError as exc:
                raise SystemExit(f"切换新邮箱失败: {exc}（旧邮箱 {old_email} 已无法继续）")
            try:
                seen_before = tuple(mail.refresh_codes())
            except TempMailError:
                seen_before = ()
            print(f"[3.2] 旧邮箱 {old_email} 没收到码，已切换到新邮箱  {email}")
            continue
        code = read_otp_code(otp_file)
        if code is None:
            if otp_file:
                print(f"提示：{otp_file} 里没有有效的 6 位验证码，改由手动输入")
            code = input("输入收到的 6 位验证码: ").strip()
        break
    if not code or not re.fullmatch(r"[0-9]{6}", code):
        raise SystemExit("验证码必须是 6 位数字")

    if cfg.get("send_caa", True):
        funnel.otp_typed(c.s)

    print("[4] 校验验证码")
    c.confirm_otp(code)

    first = cfg.get("first_name") or "三郎"    # 名
    last = cfg.get("last_name") or "近藤"      # 姓
    dob = cfg.get("date_of_birth") or random_dob()

    if cfg.get("send_caa", True):
        funnel.otp_success(c.s)
        funnel.birthday_start(c.s)
        time.sleep(3)
        funnel.birthday_next(c.s)

    print(f"[5] 完成注册  {last} {first}  {dob}")
    data = c.register_completion(dob, first, last)
    uid = (data.get("auth_meta_session") or {}).get("frl_account_id")
    print(f"    account_id = {uid}")

    if cfg.get("send_caa", True):
        funnel.create_success(c.s, uid)
        funnel.login_success(c.s, uid)

    # ---- falco 埋点（可选）----
    if cfg.get("send_falco", True):
        falco.send(c.s, c.fp, c.lang, str(uuid.uuid4()), [
            falco.perf("https://muse.ai/"),
            falco.interaction("https://muse.ai/", "page_load", "main_app", "page_load"),
        ])

    print("[6] 引导会话（session bootstrap，缺失会全链 403）")
    token = (data.get("auth_meta_session") or {}).get("frl_access_token")
    onboarding = c.activate_session(token)
    print(f"    resolved_destination = {onboarding.get('resolved_destination')}")
    print(f"    disclosure_version   = {onboarding.get('disclosure_version')}")

    print("[7] 激活会话（accept-tos，单次调用，正文取服务端动态披露）")
    c.accept_tos(onboarding)
    print(f"    invite = {'200 活号' if c.is_live() else '401/403 无 hatch 权限'}")

    print("[8] 唤醒 VM（wake_trigger=mount, open_id, away_ms=0）")
    vm = c.wake_vm()
    if vm is None:
        # wake 失败（vmId 解析不到或 wake 非 200）时继续兑换只会误报 invalid
        raise MuseError("vm_unresolved")
    print(f"    vm_id = {vm}")

    c.stateful_sharing()

    print(f"[9] 兑换邀请码  {invite_code or '(未配置)'}")
    if invite_code:
        ok, reason = c.redeem(invite_code)
        print(f"    redeem = {ok} / {reason}")
        if ok:
            own = c.scratch_code()
            print(f"[10] 自己的邀请码（POST invite 取回，非页面刮开）= {own}")
        else:
            print("    失败原因映射: already_redeemed=本账号已用过码  "
                  "used_up=该码已达使用上限  invalid=码不存在")
    else:
        print("    跳过兑换")

    sess = c.session_cookie()
    print(f"\nhatch_sess 长度 = {len(sess or '')}")
    c.close()
    if mail is not None:
        mail.close()


if __name__ == "__main__":
    try:
        main()
    except MuseError as e:
        if "region_waitlist" in str(e):
            # 引导后服务端判定地区受限：注册已完成、账号保留，但未证明已加入名单
            print(f"地区受限: {e}")
            print("    说明：账号已注册但地区受限，未加入名单；请检查出口节点地区")
        else:
            print(f"协议失败: {e}")
        sys.exit(1)
