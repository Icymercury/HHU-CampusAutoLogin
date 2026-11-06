# -*- coding: utf-8 -*-
"""
河海大学校园网自动登录

命令行：
    CampusAutoLogin.exe --run        后台静默登录（任务计划调用）
    CampusAutoLogin.exe --install    安装开机任务（需管理员）
    CampusAutoLogin.exe --uninstall  卸载开机任务（需管理员）
    CampusAutoLogin.exe --toggle     启用/禁用开机自启
    CampusAutoLogin.exe --status     查看状态

无参数：打开图形界面
"""
import os
import sys
import re
import json
import time
import base64
import socket
import ctypes
import subprocess
import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar
from ctypes import wintypes

if getattr(sys, "frozen", False):
    BASE = os.path.dirname(os.path.abspath(sys.executable))
else:
    BASE = os.path.dirname(os.path.abspath(__file__))

CONFIG_PATH = os.path.join(BASE, "config.json")
STATE_PATH = os.path.join(BASE, "state.json")
LOG_DIR = os.path.join(BASE, "logs")
TASK_NAME = "HHU_AutoLogin"

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 Edg/156.0.0.0")

BUILTIN_SERVICES = [
    ("校园网(Campus NET)", "校园外网服务(out-campus NET)"),
    ("中国移动(CMCC NET)", "中国移动(CMCC NET)"),
    ("中国电信(CTCC NET)", "中国电信(常州)"),
    ("中国联通(CUCC NET)", "中国联通(常州)"),
]
SERVICE_MAP = dict(BUILTIN_SERVICES)
SERVICE_NAMES = [x[0] for x in BUILTIN_SERVICES]

DEFAULTS = {
    "user_id": "",
    "password_enc": "",
    "service": SERVICE_NAMES[0],
    "host": "eportal.hhu.edu.cn",
    "ip_fallback": "",
    "portal_wait": 180,
    "retry_times": 3,
    "retry_interval": 15,
}


# ---------------------------------------------------------------- DPAPI
class _BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_char))]


def _make_blob(data):
    buf = ctypes.create_string_buffer(data, len(data))
    return _BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf


def dpapi_protect(text):
    """机器级加密，同一台机器上 SYSTEM 身份也能解开"""
    raw = text.encode("utf-8")
    bin_blob, _keep = _make_blob(raw)
    out = _BLOB()
    ok = ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(bin_blob), None, None, None, None, 0x4, ctypes.byref(out))
    if not ok:
        raise OSError("加密失败")
    try:
        data = ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)
    return base64.b64encode(data).decode("ascii")


def dpapi_unprotect(b64):
    raw = base64.b64decode(b64)
    bin_blob, _keep = _make_blob(raw)
    out = _BLOB()
    ok = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(bin_blob), None, None, None, None, 0x4, ctypes.byref(out))
    if not ok:
        raise OSError("解密失败")
    try:
        data = ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)
    return data.decode("utf-8")


# ---------------------------------------------------------------- 日志
LOG_SINK = None


def log(msg, level="INFO"):
    line = "%s [%s] %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), level, msg)
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        path = os.path.join(LOG_DIR, time.strftime("%Y-%m-%d") + ".log")
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
    try:
        if sys.stdout is not None:
            print(line)
    except Exception:
        pass
    if LOG_SINK is not None:
        try:
            LOG_SINK(line)
        except Exception:
            pass


# ---------------------------------------------------------------- 配置
def load_config():
    if not os.path.exists(CONFIG_PATH):
        return None
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            data = json.load(f)
        cfg = dict(DEFAULTS)
        cfg.update(data)
        return cfg
    except Exception:
        return None


def save_config(cfg):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def load_state():
    try:
        with open(STATE_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"fail_count": 0, "last_result": ""}


def save_state(st):
    try:
        with open(STATE_PATH, "w", encoding="utf-8") as f:
            json.dump(st, f, ensure_ascii=False)
    except Exception:
        pass


def get_password(cfg):
    enc = cfg.get("password_enc", "")
    if not enc:
        return ""
    try:
        return dpapi_unprotect(enc)
    except Exception:
        return ""


# ---------------------------------------------------------------- 网络
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def euc(s):
    return urllib.parse.quote(s, safe="!'()*-._~")


def make(follow=False):
    jar = http.cookiejar.CookieJar()
    hs = [urllib.request.HTTPCookieProcessor(jar)]
    if not follow:
        hs.append(NoRedirect())
    return urllib.request.build_opener(*hs)


def portal_host(cfg):
    return "http://" + cfg.get("host", "eportal.hhu.edu.cn")


def fetch(url, cfg, data=None, referer=None, follow=False, timeout=10):
    h = {"User-Agent": UA, "Accept": "*/*"}
    if referer:
        h["Referer"] = referer
    if data is not None:
        h["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"
        h["Origin"] = portal_host(cfg)
    req = urllib.request.Request(url, data=data, headers=h)
    try:
        r = make(follow).open(req, timeout=timeout)
        return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        b = b""
        try:
            b = e.read()
        except Exception:
            pass
        return e.code, dict(e.headers), b
    except Exception as e:
        return -1, {}, str(e).encode("utf-8", "ignore")


def tcp_ok(host, port=80, timeout=3):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def probe(cfg):
    for url in ("http://www.baidu.com", "http://connect.rom.miui.com/generate_204"):
        code, hdrs, body = fetch(url, cfg, timeout=8)
        text = body.decode("utf-8", "ignore") if isinstance(body, bytes) else str(body)
        loc = hdrs.get("Location", "")
        blob = (loc + " " + text[:4000]).lower()
        if "eportal" in blob:
            return "offline", loc, text
        if code == 200 or code in (301, 302, 303, 307, 308):
            return "online", loc, text
    return "unknown", "", ""


def extract_query(loc, text):
    for src in (loc, text):
        m = re.search(r"index\.jsp\?([^\"'<>\s\\]+)", src, re.I)
        if m:
            return m.group(1)
    return ""


def service_value(name):
    """界面显示名 → 实际提交的 access type"""
    return SERVICE_MAP.get(name, name)


def fetch_services(cfg, timeout=4):
    """从门户动态拉取服务列表；失败则退回内置列表"""
    try:
        url = portal_host(cfg) + "/eportal/InterFace.do?method=getServices"
        code, _, body = fetch(url, cfg, timeout=timeout)
        text = body.decode("utf-8", "ignore") if isinstance(body, bytes) else str(body)
        data = json.loads(text)
        items = re.findall(r"selectService\('([^']*)','([^']*)','([^']*)'\)",
                           data.get("serviceContent", ""))
        out = [(disp, val) for val, disp, _idx in items]
        if out:
            for disp, val in out:
                SERVICE_MAP[disp] = val
            return out
    except Exception:
        pass
    return list(BUILTIN_SERVICES)


def wait_portal(cfg, timeout=None):
    timeout = timeout or int(cfg.get("portal_wait", 180))
    host = cfg.get("host", "eportal.hhu.edu.cn")
    fb = cfg.get("ip_fallback", "")
    start = time.time()
    first = True
    while time.time() - start < timeout:
        if tcp_ok(host) or (fb and tcp_ok(fb)):
            return True
        if first:
            log("等待接入校园网...")
            first = False
        time.sleep(5)
    return False


def do_login(cfg, query_raw, idx_hint=""):
    pwd = get_password(cfg)
    if not pwd:
        return False, "未读取到密码"
    idx_url = idx_hint if idx_hint and "index.jsp" in idx_hint else \
        ("%s/eportal/index.jsp?%s" % (portal_host(cfg), query_raw))
    payload = ("userId=%s&password=%s&service=%s&queryString=%s"
               "&operatorPwd=&operatorUserId=&validcode=&passwordEncrypt=false"
               % (euc(cfg["user_id"]), euc(pwd), euc(euc(service_value(cfg.get("service", "")))),
                  euc(euc(query_raw))))
    code, _, resp = fetch(portal_host(cfg) + "/eportal/InterFace.do?method=login",
                          cfg, data=payload.encode("utf-8"), referer=idx_url)
    text = resp.decode("utf-8", "ignore") if isinstance(resp, bytes) else str(resp)
    log("登录返回: " + text[:300])
    try:
        j = json.loads(text)
        ok = str(j.get("result", "")).lower() == "success"
        return ok, j.get("message", "")
    except Exception:
        return ('"result":"success"' in text.lower()), ""


def run_once():
    cfg = load_config()
    if not cfg or not cfg.get("user_id") or not get_password(cfg):
        log("尚未配置账号，请先打开程序完成设置", "ERROR")
        return 2

    log("=" * 50)
    log("自动登录启动")

    if not wait_portal(cfg):
        log("超时未检测到校园网，判定不在校园网环境，退出")
        return 0

    state, loc, text = probe(cfg)
    if state == "online":
        log("网络已在线，无需登录")
        st = load_state()
        if st.get("fail_count"):
            st["fail_count"] = 0
            save_state(st)
        return 0

    if state != "offline":
        log("网络状态异常，无法判断", "WARN")
        return 1

    t0 = time.time()
    retry = int(cfg.get("retry_times", 3))
    interval = int(cfg.get("retry_interval", 15))

    for i in range(1, retry + 1):
        state, loc, text = probe(cfg)
        if state == "online":
            log("已在线，跳过")
            return 0
        qs = extract_query(loc, text)
        if not qs:
            time.sleep(2)
            state, loc, text = probe(cfg)
            qs = extract_query(loc, text)
        if not qs:
            log("第 %d 次：未取到会话参数，重试" % i, "WARN")
            time.sleep(interval)
            continue

        ok, msg = do_login(cfg, qs, loc)
        time.sleep(2)
        st2, _, _ = probe(cfg)
        if st2 == "online":
            log("登录成功，耗时 %.1f 秒" % (time.time() - t0))
            state = load_state()
            state["fail_count"] = 0
            state["last_result"] = "success"
            save_state(state)
            return 0
        log("第 %d 次登录未生效：%s" % (i, msg or "无返回信息"), "WARN")
        time.sleep(interval)

    st = load_state()
    st["fail_count"] = int(st.get("fail_count", 0)) + 1
    st["last_result"] = "fail"
    save_state(st)
    log("重试 %d 次仍失败，疑似账号或密码有误" % retry, "ERROR")
    return 1


# ---------------------------------------------------------------- 任务计划
def read_task():
    """返回 (状态文字, 是否已安装, 是否已停用, 是否指向当前程序)"""
    try:
        r = subprocess.run(["schtasks", "/query", "/tn", TASK_NAME, "/fo", "LIST", "/v"],
                           capture_output=True, text=True, errors="ignore", timeout=10)
    except Exception:
        return "未安装", False, False, False
    if r.returncode != 0:
        return "未安装", False, False, False

    disabled = False
    for line in r.stdout.splitlines():
        s = line.strip()
        if s.startswith("状态") or s.lower().startswith("status"):
            disabled = ("禁用" in s) or ("disabled" in s.lower())
            break

    low = r.stdout.lower()
    cur = sys.executable.lower()
    matches = (cur in low) or ("auto_login.py" in low and not getattr(sys, "frozen", False))
    return ("已停用" if disabled else "已启用"), True, disabled, matches


def task_xml():
    if getattr(sys, "frozen", False):
        exe = sys.executable
        cmd_args = "--run"
    else:
        exe = sys.executable
        if exe.lower().endswith("python.exe"):
            pw = exe[:-10] + "pythonw.exe"
            if os.path.exists(pw):
                exe = pw
        cmd_args = '"%s" --run' % os.path.join(BASE, "auto_login.py")
    return """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>河海大学校园网自动登录</Description>
    <URI>\\%s</URI>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger><Enabled>true</Enabled><Delay>PT45S</Delay></BootTrigger>
    <LogonTrigger><Enabled>true</Enabled><Delay>PT30S</Delay></LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT15M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>%s</Command>
      <Arguments>%s</Arguments>
      <WorkingDirectory>%s</WorkingDirectory>
    </Exec>
  </Actions>
</Task>""" % (TASK_NAME, exe, cmd_args, BASE)


def elevated_schtasks(args):
    quoted = ", ".join("'%s'" % a.replace("'", "''") for a in args)
    ps = ("Start-Process -FilePath schtasks.exe -ArgumentList @(%s) "
          "-Verb RunAs -Wait -WindowStyle Hidden" % quoted)
    try:
        subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                       capture_output=True, timeout=90)
    except Exception:
        pass


def install_task():
    xml_path = os.path.join(BASE, "task.xml")
    with open(xml_path, "w", encoding="utf-16") as f:
        f.write(task_xml())
    r = subprocess.run(["schtasks", "/create", "/f", "/tn", TASK_NAME, "/xml", xml_path],
                       capture_output=True, text=True, errors="ignore")
    if r.returncode == 0:
        subprocess.run(["schtasks", "/change", "/tn", TASK_NAME, "/enable"],
                       capture_output=True, text=True, errors="ignore")
    return r.returncode == 0, (r.stdout or r.stderr or "")


def remove_task():
    r = subprocess.run(["schtasks", "/delete", "/f", "/tn", TASK_NAME],
                       capture_output=True, text=True, errors="ignore")
    return r.returncode == 0, (r.stdout or r.stderr or "")


def toggle_task():
    name, inst, dis, matches = read_task()
    if not inst:
        return False, "任务不存在"
    flag = "/enable" if dis else "/disable"
    r = subprocess.run(["schtasks", "/change", "/tn", TASK_NAME, flag],
                       capture_output=True, text=True, errors="ignore")
    return r.returncode == 0, ("" if r.returncode == 0 else (r.stdout or r.stderr or ""))


# ---------------------------------------------------------------- GUI
def gui():
    import queue
    import threading
    import tkinter as tk
    from tkinter import ttk, messagebox

    F = ("Microsoft YaHei UI", 10)
    FB = ("Microsoft YaHei UI", 10, "bold")
    FS = ("Microsoft YaHei UI", 9)

    root = tk.Tk()
    root.title("校园网自动登录")
    root.geometry("470x470")
    root.resizable(False, False)

    q = queue.Queue()
    globals()["LOG_SINK"] = lambda line: q.put(line)

    tk.Label(root, text="河海大学 校园网自动登录",
             font=("Microsoft YaHei UI", 14, "bold")).pack(pady=(16, 2))
    tk.Label(root, text="ePortal 认证 · 开机自动连接", font=FS, fg="#7a7a7a").pack()

    warn_var = tk.StringVar(value="")
    tk.Label(root, textvariable=warn_var, font=FS, fg="#c0392b",
             wraplength=420).pack(pady=(6, 0))

    box = tk.Frame(root)
    box.pack(fill="x", padx=30, pady=10)

    net_var = tk.StringVar(value="检测中...")
    auto_var = tk.StringVar(value="读取中...")
    acc_var = tk.StringVar(value="")

    def row(label, var):
        f = tk.Frame(box)
        f.pack(fill="x", pady=3)
        tk.Label(f, text=label, font=F, width=9, anchor="w").pack(side="left")
        lb = tk.Label(f, textvariable=var, font=FB, anchor="w", fg="#333333")
        lb.pack(side="left")
        return lb

    net_lb = row("网络状态", net_var)
    auto_lb = row("开机自启", auto_var)
    row("当前账号", acc_var)

    btnf = tk.Frame(root)
    btnf.pack(pady=(4, 8))
    btn_login = tk.Button(btnf, text="立即登录", width=10, font=F)
    btn_auto = tk.Button(btnf, text="安装自启", width=10, font=F)
    btn_set = tk.Button(btnf, text="设置", width=8, font=F)
    btn_logs = tk.Button(btnf, text="日志", width=6, font=F)
    for b in (btn_login, btn_auto, btn_set, btn_logs):
        b.pack(side="left", padx=4)

    logbox = tk.Text(root, height=8, font=("Consolas", 9), bg="#f6f6f6",
                     relief="flat", wrap="word", padx=8, pady=6)
    logbox.pack(fill="both", expand=True, padx=30, pady=(2, 16))
    logbox.config(state="disabled")

    def append(line):
        logbox.config(state="normal")
        logbox.insert("end", line + "\n")
        logbox.see("end")
        logbox.config(state="disabled")

    def clear():
        logbox.config(state="normal")
        logbox.delete("1.0", "end")
        logbox.config(state="disabled")

    st = {"busy": False, "installed": False, "disabled": False, "matches": False}

    def set_busy(v):
        st["busy"] = v
        state = "disabled" if v else "normal"
        for b in (btn_login, btn_auto, btn_set, btn_logs):
            b.config(state=state)

    def apply(net_state, name, inst, dis, matches):
        color = {"online": "#0a7d33", "offline": "#c0392b"}.get(net_state, "#7f8c8d")
        net_var.set({"online": "已连接", "offline": "未认证"}.get(net_state, "未知"))
        net_lb.config(fg=color)
        auto_var.set(name + ("" if (not inst or matches) else "（需更新）"))
        auto_lb.config(fg="#0a7d33" if (name == "已启用" and matches) else "#8a8a8a")
        st["installed"], st["disabled"], st["matches"] = inst, dis, matches
        if not inst:
            btn_auto.config(text="安装自启")
        elif not matches:
            btn_auto.config(text="更新自启")
        else:
            btn_auto.config(text=("启用自启" if dis else "停用自启"))
        cfg = load_config()
        acc_var.set(cfg["user_id"] if (cfg and cfg.get("user_id")) else "未设置")
        s = load_state()
        if int(s.get("fail_count", 0)) >= 3:
            warn_var.set("连续登录失败，密码可能已修改，请点「设置」重新输入")
        elif s.get("last_result") == "fail":
            warn_var.set("上次自动登录未成功")
        else:
            warn_var.set("")
        set_busy(False)

    def refresh():
        def work():
            cfg = load_config()
            ns = "unknown"
            if cfg:
                try:
                    ns, _, _ = probe(cfg)
                except Exception:
                    pass
            name, inst, dis, matches = read_task()
            root.after(0, lambda: apply(ns, name, inst, dis, matches))
        threading.Thread(target=work, daemon=True).start()

    def open_settings():
        cfg = load_config() or dict(DEFAULTS)
        win = tk.Toplevel(root)
        win.title("设置")
        win.geometry("440x310")
        win.resizable(False, False)
        win.transient(root)
        win.grab_set()

        body = tk.Frame(win)
        body.pack(fill="x", padx=24, pady=18)

        tk.Label(body, text="学号", font=F).grid(row=0, column=0, sticky="w", pady=6)
        uid_var = tk.StringVar(value=cfg.get("user_id", ""))
        tk.Entry(body, textvariable=uid_var, font=F, width=28).grid(
            row=0, column=1, sticky="w", pady=6)

        tk.Label(body, text="密码", font=F).grid(row=1, column=0, sticky="w", pady=6)
        pw_frame = tk.Frame(body)
        pw_frame.grid(row=1, column=1, sticky="w", pady=6)
        pw_var = tk.StringVar(value=get_password(cfg))
        pw_entry = tk.Entry(pw_frame, textvariable=pw_var, font=F, width=24, show="*")
        pw_entry.pack(side="left")

        eye = tk.Button(pw_frame, text="显示", font=FS, width=4, relief="flat",
                        bg="#eef2f7", cursor="hand2")
        eye.pack(side="left", padx=(6, 0))

        def toggle_eye():
            if pw_entry.cget("show") == "*":
                pw_entry.config(show="")
                eye.config(text="隐藏")
            else:
                pw_entry.config(show="*")
                eye.config(text="显示")
        eye.config(command=toggle_eye)

        tk.Label(body, text="运营商", font=F).grid(row=2, column=0, sticky="w", pady=6)
        svc_var = tk.StringVar(value=cfg.get("service", SERVICE_NAMES[0]))
        cb = ttk.Combobox(body, textvariable=svc_var, values=SERVICE_NAMES,
                          state="readonly", width=26, font=F)
        cb.grid(row=2, column=1, sticky="w", pady=6)

        def reload_services():
            items = fetch_services(cfg)
            names = [d for d, _ in items]
            if names:
                root.after(0, lambda: cb.config(values=names))
        threading.Thread(target=reload_services, daemon=True).start()

        tk.Label(win, text="密码使用 Windows 本机加密保存，不以明文写入磁盘",
                 font=FS, fg="#8a8a8a").pack(pady=(0, 4))

        bar = tk.Frame(win)
        bar.pack(pady=(0, 14))

        def do_save():
            uid = uid_var.get().strip()
            pwd = pw_var.get()
            if not uid:
                messagebox.showwarning("提示", "学号不能为空", parent=win)
                return
            if not pwd:
                messagebox.showwarning("提示", "密码不能为空", parent=win)
                return
            new = dict(cfg)
            new["user_id"] = uid
            new["password_enc"] = dpapi_protect(pwd)
            new["service"] = svc_var.get()
            try:
                save_config(new)
            except Exception as e:
                messagebox.showerror("保存失败", str(e), parent=win)
                return
            s = load_state()
            s["fail_count"] = 0
            s["last_result"] = ""
            save_state(s)
            win.destroy()
            refresh()

        tk.Button(bar, text="保存", width=10, font=F,
                  command=do_save).pack(side="left", padx=6)
        tk.Button(bar, text="取消", width=10, font=F,
                  command=win.destroy).pack(side="left", padx=6)

    def on_login():
        if st["busy"]:
            return
        cfg = load_config()
        if not cfg or not cfg.get("user_id"):
            messagebox.showwarning("提示", "请先在「设置」里填写学号和密码")
            return
        set_busy(True)
        clear()
        append("开始登录...")

        def work():
            try:
                rc = run_once()
                msg = {0: "完成", 1: "登录失败，详见上方日志", 2: "配置不完整"}.get(rc, "结束")
            except Exception as e:
                msg = "出错：%s" % e
            root.after(0, lambda: (append(""), append(">>> " + msg), refresh()))
        threading.Thread(target=work, daemon=True).start()

    def on_auto():
        if st["busy"]:
            return
        set_busy(True)

        def work():
            try:
                if (not st["installed"]) or (not st["matches"]):
                    append("正在安装开机任务，请在系统弹窗中允许...")
                    ok, msg = install_task()
                    append("安装成功" if ok else "安装失败：" + msg[:200])
                else:
                    append("正在" + ("启用" if st["disabled"] else "停用") + "开机自启...")
                    ok, msg = toggle_task()
                    append(("已" + ("启用" if st["disabled"] else "停用"))
                           if ok else "操作失败：" + msg[:200])
            except Exception as e:
                append("操作失败：%s" % e)
            time.sleep(1)
            root.after(0, refresh)
        threading.Thread(target=work, daemon=True).start()

    def on_logs():
        try:
            os.makedirs(LOG_DIR, exist_ok=True)
            os.startfile(LOG_DIR)
        except Exception:
            pass

    btn_login.config(command=on_login)
    btn_auto.config(command=on_auto)
    btn_set.config(command=open_settings)
    btn_logs.config(command=on_logs)

    def drain():
        try:
            while True:
                append(q.get_nowait())
        except queue.Empty:
            pass
        root.after(200, drain)

    root.after(100, drain)
    root.after(300, refresh)

    cfg0 = load_config()
    if not cfg0 or not cfg0.get("user_id"):
        root.after(400, open_settings)

    root.mainloop()
    return 0


# ---------------------------------------------------------------- CLI
def cli_report(text):
    try:
        if sys.stdout is not None:
            print(text)
    except Exception:
        pass
    if getattr(sys, "frozen", False):
        try:
            import tkinter as tk
            from tkinter import messagebox
            r = tk.Tk()
            r.withdraw()
            r.attributes("-topmost", True)
            messagebox.showinfo("校园网自动登录", text)
            r.destroy()
        except Exception:
            pass


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    cmd = sys.argv[1] if len(sys.argv) > 1 else "--gui"
    if cmd == "--gui":
        return gui()
    if cmd == "--run":
        return run_once()
    if cmd == "--install":
        ok, msg = install_task()
        cli_report("安装成功。开机后约 45 秒自动登录。" if ok else "安装失败：" + msg)
        return 0 if ok else 1
    if cmd == "--uninstall":
        ok, msg = remove_task()
        cli_report("已卸载开机自启任务。" if ok else "卸载失败：" + msg)
        return 0 if ok else 1
    if cmd == "--toggle":
        ok, msg = toggle_task()
        cli_report("操作成功。" if ok else "操作失败：" + msg)
        return 0 if ok else 1
    if cmd == "--status":
        name, inst, dis, matches = read_task()
        cfg = load_config()
        ns = "未知"
        if cfg:
            s, _, _ = probe(cfg)
            ns = {"online": "已连接", "offline": "未认证"}.get(s, "未知")
        cli_report("开机自启：%s\n网络状态：%s" % (name, ns))
        return 0
    return gui()


if __name__ == "__main__":
    try:
        sys.exit(main() or 0)
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        cli_report("程序出错：%s" % e)
        sys.exit(1)
