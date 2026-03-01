#!/usr/bin/env python3
"""
Baiduyun Downloader (바이두윈 다운로더)
PCS API + Range 헤더 1MB 청크 방식 다운로드
"""

import sys
import os
import json
import time
import math
import hashlib
import urllib.parse
import argparse
import requests
import threading

# ── 상수 ──────────────────────────────────────────────────────────────────────
APP_VERSION = "1.1.0"
GITHUB_REPO = "owner/baidu-downloader"  # ← GitHub 레포 만들면 여기만 수정
CHUNK_SIZE = 2 * 1024 * 1024  # 2MB
PARALLEL_CONN = 8             # 파일당 동시 연결 수 (기본 8)
MAX_CONCURRENT = 2            # 동시 다운로드 파일 수 (기본 2)
SPEED_LIMIT = 0               # 속도 제한 (bytes/s), 0=무제한 (SPEED_LIMIT_BAIDU alias)
SPEED_LIMIT_BAIDU = 0         # Baidu 속도 제한 (bytes/s)
SPEED_LIMIT_BILI  = 0         # Bilibili 속도 제한 (bytes/s)
SPEED_LIMIT_QUARK = 0         # Quark 속도 제한 (bytes/s)
UA = "netdisk;2.2.51.6;netdisk;10.0.63;PC;PC-Windows;6.2.9200;WindowsBaiduYunGuanJia"
UA_DL = "netdisk;f4pan"  # dlink download User-Agent (higher speed)
APP_ID = 778750
PCS_BASE = "https://pcs.baidu.com/rest/2.0/pcs/file"
PAN_BASE = "https://pan.baidu.com"
# PyInstaller --onefile: __file__은 임시 _MEIPASS 경로가 됨 → exe 위치 기준으로 config 저장
if getattr(sys, 'frozen', False):
    _BASE_DIR = os.path.dirname(sys.executable)
else:
    _BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(_BASE_DIR, "config.json")
QUEUE_PATH = os.path.join(_BASE_DIR, "dl_queue.json")
MAX_RETRY = 5
CHUNKS_PER_URL = 10  # redirect URL 갱신 주기

# ── PySide6 조건부 임포트 ─────────────────────────────────────────────────────
try:
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QTreeWidget, QTreeWidgetItem, QHeaderView, QLabel, QProgressBar,
        QPushButton, QToolBar, QDialog, QFormLayout, QLineEdit, QTextEdit,
        QFileDialog, QMessageBox, QStatusBar, QSizePolicy, QStyle,
        QSplitter, QMenu, QMenuBar, QCheckBox, QSystemTrayIcon, QComboBox, QStyledItemDelegate,
    )
    from PySide6.QtCore import Qt, QThread, Signal, QSize
    from PySide6.QtGui import QAction, QIcon, QFont
    HAS_GUI = True
except ImportError:
    HAS_GUI = False

# ── BDUSS 브라우저 자동 추출 ──────────────────────────────────────────────────

def extract_bduss_from_browsers():
    """Chrome/Edge Cookies DB에서 BDUSS를 직접 추출한다.
    v10 쿠키: DPAPI + AES-GCM 복호화
    v20 쿠키 (Chrome 127+): App-Bound Encryption → 복호화 불가, None 반환
    Returns: (bduss, source_name) or (None, error_message)
    """
    import sqlite3
    import tempfile
    import base64

    local_app = os.environ.get("LOCALAPPDATA", "")
    if not local_app:
        return None, "LOCALAPPDATA 환경변수 없음"

    browsers = [
        ("Edge", os.path.join(local_app, "Microsoft", "Edge", "User Data")),
        ("Chrome", os.path.join(local_app, "Google", "Chrome", "User Data")),
    ]

    for browser_name, user_data_dir in browsers:
        local_state_path = os.path.join(user_data_dir, "Local State")
        if not os.path.exists(local_state_path):
            continue

        # 1. DPAPI 키 획득
        try:
            with open(local_state_path, "r", encoding="utf-8") as f:
                ls = json.load(f)
            enc_key_b64 = ls.get("os_crypt", {}).get("encrypted_key", "")
            if not enc_key_b64:
                continue
            enc_key = base64.b64decode(enc_key_b64)
            if enc_key[:5] != b"DPAPI":
                continue
            import win32crypt
            aes_key = win32crypt.CryptUnprotectData(enc_key[5:], None, None, None, 0)[1]
        except Exception:
            continue

        # 2. Cookies DB 복사 (잠금 파일 우회)
        profiles = ["Default"] + [f"Profile {i}" for i in range(1, 10)]
        for prof in profiles:
            cookies_path = os.path.join(user_data_dir, prof, "Network", "Cookies")
            if not os.path.exists(cookies_path):
                continue

            tmp_db = os.path.join(tempfile.gettempdir(), f"bduss_{browser_name}_{prof}.db")
            try:
                from shadowcopy import shadow_copy
                shadow_copy(cookies_path, tmp_db)
            except Exception:
                try:
                    import shutil
                    shutil.copy2(cookies_path, tmp_db)
                except Exception:
                    continue

            # 3. BDUSS 쿠키 조회 및 복호화
            try:
                conn = sqlite3.connect(tmp_db)
                cur = conn.cursor()
                cur.execute(
                    "SELECT name, encrypted_value FROM cookies "
                    "WHERE host_key LIKE '%baidu.com' AND name IN ('BDUSS', 'BDUSS_BFESS')"
                )
                for name, enc_val in cur.fetchall():
                    if not enc_val or len(enc_val) < 16:
                        continue
                    prefix = enc_val[:3]
                    if prefix == b"v10":
                        # v10: AES-256-GCM (DPAPI 키로 복호화 가능)
                        try:
                            from Cryptodome.Cipher import AES
                            nonce = enc_val[3:15]
                            ciphertext_tag = enc_val[15:]
                            cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
                            val = cipher.decrypt_and_verify(
                                ciphertext_tag[:-16], ciphertext_tag[-16:]
                            ).decode("utf-8")
                            if val and len(val) > 50:
                                conn.close()
                                try:
                                    os.remove(tmp_db)
                                except OSError:
                                    pass
                                return val, f"{browser_name} ({prof})"
                        except Exception:
                            continue
                    elif prefix == b"v20":
                        # v20: Chrome 127+ App-Bound Encryption → DPAPI로 복호화 불가
                        conn.close()
                        try:
                            os.remove(tmp_db)
                        except OSError:
                            pass
                        return None, (
                            f"{browser_name}에 BDUSS가 있지만 Chrome 127+ App-Bound "
                            f"Encryption(v20)으로 암호화되어 자동 추출 불가.\n\n"
                            f"수동 추출 방법:\n"
                            f"1. {browser_name}에서 pan.baidu.com 접속\n"
                            f"2. F12 → Application → Cookies → .baidu.com\n"
                            f"3. BDUSS 값 복사 → 아래에 붙여넣기"
                        )
                conn.close()
            except Exception:
                pass
            finally:
                try:
                    os.remove(tmp_db)
                except OSError:
                    pass

    return None, "브라우저에서 BDUSS 쿠키를 찾을 수 없습니다."


# ── BDUSS 암호화 (Windows DPAPI) ──────────────────────────────────────────────

def _encrypt_bduss(plain):
    """BDUSS를 Windows DPAPI로 암호화 → base64 문자열 반환"""
    try:
        import win32crypt
        import base64
        encrypted = win32crypt.CryptProtectData(
            plain.encode("utf-8"), "bduss", None, None, None, 0)
        return base64.b64encode(encrypted).decode("ascii")
    except Exception:
        return plain  # DPAPI 불가 시 평문 폴백


def _decrypt_bduss(stored):
    """저장된 BDUSS 복호화 (DPAPI base64 또는 평문)"""
    if not stored:
        return stored
    try:
        import win32crypt
        import base64
        raw = base64.b64decode(stored)
        _, decrypted = win32crypt.CryptUnprotectData(raw, None, None, None, 0)
        return decrypted.decode("utf-8")
    except Exception:
        # DPAPI 복호화 실패 → 평문으로 간주 (기존 config 호환)
        return stored


# ── Config 관리 ───────────────────────────────────────────────────────────────

def load_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        # BDUSS 복호화
        if "bduss_enc" in cfg:
            cfg["bduss"] = _decrypt_bduss(cfg["bduss_enc"])
        return cfg
    return {}


def save_config(cfg):
    out = dict(cfg)
    # BDUSS 암호화 저장 (평문 키 제거)
    if "bduss" in out and out["bduss"]:
        out["bduss_enc"] = _encrypt_bduss(out["bduss"])
        out.pop("bduss", None)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)


def get_bduss():
    cfg = load_config()
    bduss = cfg.get("bduss")
    if not bduss:
        print("BDUSS가 설정되지 않았습니다. 먼저 login을 실행하세요.")
        print("  python baidu_dl.py login")
        sys.exit(1)
    return bduss


def get_download_dir():
    cfg = load_config()
    d = cfg.get("download_dir", os.path.join(os.path.expanduser("~"), "Downloads"))
    os.makedirs(d, exist_ok=True)
    return d


# ── 세션 헬퍼 ─────────────────────────────────────────────────────────────────

def make_session(bduss):
    s = requests.Session()
    s.headers["User-Agent"] = UA
    s.cookies.set("BDUSS", bduss, domain=".baidu.com")
    return s


# ── API 함수 ──────────────────────────────────────────────────────────────────

def verify_login(bduss):
    """BDUSS로 로그인 검증, 사용자 정보 반환"""
    s = make_session(bduss)
    url = "https://pan.baidu.com/rest/2.0/xpan/nas?method=uinfo"
    r = s.get(url, timeout=15)
    data = r.json()
    if data.get("errno") != 0:
        return None
    return {
        "name": data.get("baidu_name", ""),
        "uk": data.get("uk", ""),
        "vip": data.get("vip_type", 0),
    }


def list_files(bduss, dir_path="/"):
    """파일 목록 조회"""
    s = make_session(bduss)
    params = {
        "dir": dir_path,
        "num": 100,
        "order": "time",
        "desc": 1,
        "channel": "chunlei",
        "web": 1,
        "clienttype": 0,
    }
    r = s.get(f"{PAN_BASE}/api/list", params=params, timeout=15)
    data = r.json()
    if data.get("errno") != 0:
        print(f"오류: errno={data.get('errno')}")
        return []
    return data.get("list", [])


def get_quota(bduss):
    """클라우드 용량 조회 — (used, total) 바이트 튜플 반환"""
    s = make_session(bduss)
    params = {"method": "info", "channel": "chunlei", "web": 1, "clienttype": 0}
    try:
        r = s.get(f"{PAN_BASE}/api/quota", params=params, timeout=10)
        data = r.json()
        if data.get("errno") == 0:
            return data.get("used", 0), data.get("total", 0)
    except Exception:
        pass
    return None, None


def get_redirect_url(bduss, remote_path, session=None):
    """PCS API로 redirect URL 획득 (302 Location)"""
    s = session or make_session(bduss)
    encoded_path = urllib.parse.quote(remote_path, safe="")
    url = f"{PCS_BASE}?method=download&path={encoded_path}&app_id={APP_ID}"
    r = s.head(url, allow_redirects=False, timeout=30)
    if r.status_code in (301, 302):
        return r.headers.get("Location")
    # HEAD 실패 시 GET으로 재시도
    r = s.get(url, allow_redirects=False, timeout=30)
    if r.status_code in (301, 302):
        return r.headers.get("Location")
    return None


def get_fs_id(bduss, remote_path):
    """remote_path에 대한 fs_id 조회"""
    s = make_session(bduss)
    params = {
        "method": "filemetas",
        "fsids": "[]",
        "path": remote_path,
        "channel": "chunlei",
        "web": 1,
        "clienttype": 0,
    }
    # list API로 파일 정보 획득 (fs_id 포함)
    dir_path = "/".join(remote_path.replace("\\", "/").split("/")[:-1]) or "/"
    fname = remote_path.split("/")[-1]
    r = s.get(f"{PAN_BASE}/api/list", params={
        "dir": dir_path, "num": 1000, "order": "name",
        "channel": "chunlei", "web": 1, "clienttype": 0,
    }, timeout=15)
    data = r.json()
    for item in data.get("list", []):
        if item.get("server_filename") == fname or item.get("path") == remote_path:
            return item.get("fs_id")
    return None


def get_dlink(bduss, remote_path, session=None):
    """locatedownload API로 고속 dlink 획득 (BDUSS 기반, 서명 포함)"""
    s = session or make_session(bduss)
    timestamp = str(int(time.time() * 1000))
    devuid = "0|" + hashlib.md5(bduss.encode()).hexdigest().upper()
    enc = hashlib.sha1(bduss.encode()).hexdigest()
    # uid 획득
    try:
        r = s.get(f"{PAN_BASE}/rest/2.0/xpan/nas?method=uinfo", timeout=10)
        uid = str(r.json().get("uk", "0"))
    except Exception:
        uid = "0"
    rand = hashlib.sha1(
        (enc + uid + "ebrcUYiuxaZv2XGu7KIYKxUrqfnOfpDF" + timestamp + devuid).encode()
    ).hexdigest()

    encoded_path = urllib.parse.quote(remote_path, safe="")
    url = (f"{PCS_BASE}?method=locatedownload&app_id={APP_ID}&ver=2"
           f"&path={encoded_path}&time={timestamp}&rand={rand}&devuid={devuid}")
    try:
        r = s.get(url, timeout=30)
        data = r.json()
        urls = data.get("urls")
        if urls and len(urls) > 0:
            return urls[0].get("url")
    except Exception:
        pass

    # locatedownload 실패 → filemetas dlink 시도
    try:
        fs_id = get_fs_id(bduss, remote_path)
        if fs_id:
            r = s.get(f"{PAN_BASE}/rest/2.0/xpan/multimedia", params={
                "method": "filemetas",
                "fsids": json.dumps([fs_id]),
                "dlink": 1,
                "channel": "chunlei",
                "web": 1,
                "clienttype": 0,
            }, timeout=15)
            data = r.json()
            items = data.get("list", [])
            if items and items[0].get("dlink"):
                return items[0]["dlink"]
    except Exception:
        pass

    return None


def get_download_url(bduss, remote_path, session=None):
    """고속 dlink 우선 시도 → 실패 시 PCS redirect URL 폴백"""
    url = get_dlink(bduss, remote_path, session=session)
    if url:
        return url, True  # (url, is_dlink)
    url = get_redirect_url(bduss, remote_path, session=session)
    return url, False  # (url, is_dlink)


# ── 다운로드 엔진 ─────────────────────────────────────────────────────────────

def format_size(n):
    if n < 1024:
        return f"{n} B"
    elif n < 1024 ** 2:
        return f"{n / 1024:.1f} KB"
    elif n < 1024 ** 3:
        return f"{n / 1024**2:.1f} MB"
    else:
        return f"{n / 1024**3:.2f} GB"


def progress_bar(current, total, width=40, speed=0):
    pct = current / total if total else 0
    filled = int(width * pct)
    bar = "█" * filled + "░" * (width - filled)
    speed_str = f"{format_size(int(speed))}/s" if speed else "..."
    print(f"\r  [{bar}] {pct*100:5.1f}%  {format_size(current)}/{format_size(total)}  {speed_str}  ", end="", flush=True)


def chunk_download(bduss, remote_path, output_path, total_size,
                    progress_callback=None, cancel_flag=None, pause_flag=None):
    """Range 헤더 청크 방식 다운로드 (병렬 연결 지원)

    Args:
        progress_callback: callable(downloaded, total_size, speed) - GUI 진행률 콜백
        cancel_flag: callable() -> bool - True이면 다운로드 취소
        pause_flag: callable() -> bool - True이면 일시정지 대기
    """
    def _print(msg):
        if progress_callback is None:
            print(msg)

    # 이어받기 지원
    downloaded = 0
    if os.path.exists(output_path):
        downloaded = os.path.getsize(output_path)
        if downloaded >= total_size:
            _print(f"  이미 완료됨: {output_path}")
            return True
        if downloaded > 0:
            _print(f"  이어받기: {format_size(downloaded)} 부터 재개")

    remaining = total_size - downloaded

    # 대용량 + 새 다운로드 → 병렬, 이어받기/소용량 → 순차
    if downloaded == 0 and remaining > CHUNK_SIZE * PARALLEL_CONN:
        ok = _download_parallel(
            bduss, remote_path, output_path, total_size,
            progress_callback, cancel_flag, pause_flag, PARALLEL_CONN)
        if ok:
            return True
        # 병렬 실패 시 순차로 재시도
        _print("  병렬 다운로드 실패, 순차 방식으로 재시도...")
        try:
            os.remove(output_path)
        except OSError:
            pass
        downloaded = 0

    return _download_sequential(
        bduss, remote_path, output_path, total_size,
        downloaded, progress_callback, cancel_flag, pause_flag)


def _download_sequential(bduss, remote_path, output_path, total_size,
                          downloaded, progress_callback, cancel_flag, pause_flag):
    """단일 연결 순차 다운로드 (이어받기 지원)"""
    def _print(msg):
        if progress_callback is None:
            print(msg)

    chunk_idx = 0
    dl_url = None
    _is_dlink = False
    start_time = time.time()
    speed = 0
    _last_speed_time = start_time
    _last_speed_bytes = downloaded

    mode = "ab" if downloaded > 0 else "wb"
    with open(output_path, mode) as f:
        while downloaded < total_size:
            if cancel_flag and cancel_flag():
                _print("\n  다운로드 취소됨.")
                return False

            while pause_flag and pause_flag():
                if cancel_flag and cancel_flag():
                    return False
                time.sleep(0.2)

            if dl_url is None or chunk_idx % CHUNKS_PER_URL == 0:
                for attempt in range(MAX_RETRY):
                    dl_url, _is_dlink = get_download_url(bduss, remote_path)
                    if dl_url:
                        break
                    _print(f"\n  URL retry ({attempt+1}/{MAX_RETRY})...")
                    time.sleep(2 ** attempt)
                if not dl_url:
                    _print("\n  URL fetch failed. Download aborted.")
                    return False

            start = downloaded
            end = min(downloaded + CHUNK_SIZE - 1, total_size - 1)
            headers = {
                "User-Agent": UA_DL if _is_dlink else UA,
                "Range": f"bytes={start}-{end}",
            }

            success = False
            for attempt in range(MAX_RETRY):
                if cancel_flag and cancel_flag():
                    return False
                try:
                    chunk_start = time.time()
                    chunk_downloaded = 0
                    r = requests.get(dl_url, headers=headers, timeout=60, stream=True)
                    if r.status_code in (200, 206):
                        for piece in r.iter_content(chunk_size=65536):
                            if cancel_flag and cancel_flag():
                                r.close()
                                return False
                            while pause_flag and pause_flag():
                                if cancel_flag and cancel_flag():
                                    r.close()
                                    return False
                                time.sleep(0.2)
                            try:
                                f.write(piece)
                            except OSError:
                                r.close()
                                return False
                            downloaded += len(piece)
                            chunk_downloaded += len(piece)
                            # 0.5초마다 속도 계산 및 콜백
                            now = time.time()
                            dt = now - _last_speed_time
                            if dt >= 0.5:
                                speed = (downloaded - _last_speed_bytes) / dt
                                _last_speed_time = now
                                _last_speed_bytes = downloaded
                                if progress_callback:
                                    progress_callback(downloaded, total_size, speed)
                                else:
                                    progress_bar(downloaded, total_size, speed=speed)
                            # 속도 제한 (64KB 단위)
                            if SPEED_LIMIT_BAIDU > 0:
                                expected = chunk_downloaded / SPEED_LIMIT_BAIDU
                                actual = now - chunk_start
                                if expected > actual:
                                    time.sleep(min(expected - actual, 0.5))
                        try:
                            f.flush()
                        except OSError:
                            return False
                        success = True
                        break
                    elif r.status_code == 403:
                        dl_url, _is_dlink = get_download_url(bduss, remote_path)
                        if not dl_url:
                            _print(f"\n  URL refresh failed")
                            break
                    else:
                        _print(f"\n  HTTP {r.status_code}, 재시도 ({attempt+1}/{MAX_RETRY})")
                        time.sleep(2 ** attempt)
                except requests.exceptions.RequestException as e:
                    _print(f"\n  네트워크 오류: {e}, 재시도 ({attempt+1}/{MAX_RETRY})")
                    time.sleep(2 ** attempt)

            if not success:
                _print(f"\n  청크 다운로드 실패 (offset={start}). 다운로드 중단.")
                _print(f"  다시 실행하면 이어받기합니다.")
                return False

            chunk_idx += 1

    if not progress_callback:
        print()
    return True


def _download_parallel(bduss, remote_path, output_path, total_size,
                       progress_callback, cancel_flag, pause_flag, num_conn):
    """멀티 커넥션 병렬 다운로드 — 속도 N배 향상"""
    def _print(msg):
        if progress_callback is None:
            print(msg)

    _print(f"  병렬 다운로드: {num_conn}개 연결")

    # 파일 사전 할당
    with open(output_path, "wb") as f:
        f.seek(total_size - 1)
        f.write(b'\0')

    # 세그먼트 분할
    seg_size = total_size // num_conn
    segments = []
    for i in range(num_conn):
        seg_start = i * seg_size
        seg_end = total_size if i == num_conn - 1 else (i + 1) * seg_size
        segments.append((seg_start, seg_end))

    # 공유 상태
    file_lock = threading.Lock()
    progress_lock = threading.Lock()
    seg_progress = [0] * num_conn
    results = [None] * num_conn
    start_time = time.time()
    _all_done = threading.Event()

    fp = open(output_path, "r+b")  # finally에서 close

    # 프로그레스 타이머 스레드: 0.5초 간격 강제 보고
    _last_reported_bytes = [0]
    _last_reported_time = [time.time()]
    def _progress_reporter():
        while not _all_done.is_set():
            _all_done.wait(0.5)
            now = time.time()
            with progress_lock:
                total_dl = sum(seg_progress)
            dt = now - _last_reported_time[0]
            speed = (total_dl - _last_reported_bytes[0]) / dt if dt > 0 else 0
            _last_reported_time[0] = now
            _last_reported_bytes[0] = total_dl
            if progress_callback:
                progress_callback(total_dl, total_size, speed)
            else:
                progress_bar(total_dl, total_size, speed=speed)
    _reporter = threading.Thread(target=_progress_reporter, daemon=True)
    _reporter.start()

    def _seg_worker(seg_id, seg_start, seg_end):
        """세그먼트 워커: 할당된 범위를 독립적으로 다운로드"""
        sess = make_session(bduss)  # 세그먼트별 세션 재사용
        dl_sess = requests.Session()
        dl_url = None
        _is_dlink = False
        chunk_idx = 0
        pos = seg_start

        while pos < seg_end:
            # 취소 체크
            if cancel_flag and cancel_flag():
                results[seg_id] = False
                return
            # 일시정지 대기
            while pause_flag and pause_flag():
                if cancel_flag and cancel_flag():
                    results[seg_id] = False
                    return
                time.sleep(0.2)

            # URL 갱신 (세그먼트별 독립): dlink 우선
            if dl_url is None or chunk_idx % CHUNKS_PER_URL == 0:
                for attempt in range(MAX_RETRY):
                    try:
                        dl_url, _is_dlink = get_download_url(bduss, remote_path, session=sess)
                    except Exception:
                        dl_url = None
                    if dl_url:
                        break
                    time.sleep(2 ** attempt)
                if not dl_url:
                    results[seg_id] = False
                    return

            end = min(pos + CHUNK_SIZE - 1, seg_end - 1)
            headers = {
                "User-Agent": UA_DL if _is_dlink else UA,
                "Range": f"bytes={pos}-{end}",
            }

            success = False
            for attempt in range(MAX_RETRY):
                if cancel_flag and cancel_flag():
                    results[seg_id] = False
                    return
                try:
                    chunk_start = time.time()
                    chunk_downloaded = 0
                    r = dl_sess.get(dl_url, headers=headers, timeout=60, stream=True)
                    if r.status_code in (200, 206):
                        for piece in r.iter_content(chunk_size=65536):
                            if cancel_flag and cancel_flag():
                                r.close()
                                results[seg_id] = False
                                return
                            try:
                                with file_lock:
                                    fp.seek(pos)
                                    fp.write(piece)
                            except OSError:
                                r.close()
                                results[seg_id] = False
                                return
                            pos += len(piece)
                            chunk_downloaded += len(piece)
                            with progress_lock:
                                seg_progress[seg_id] = pos - seg_start
                            # 속도 제한 (스레드별, 64KB 단위)
                            if SPEED_LIMIT_BAIDU > 0:
                                per_thread_limit = SPEED_LIMIT_BAIDU / num_conn
                                expected = chunk_downloaded / per_thread_limit if per_thread_limit > 0 else 0
                                actual = time.time() - chunk_start
                                if expected > actual:
                                    time.sleep(min(expected - actual, 0.5))
                        try:
                            with file_lock:
                                fp.flush()
                        except OSError:
                            results[seg_id] = False
                            return
                        success = True
                        break
                    elif r.status_code == 403:
                        dl_url, _is_dlink = get_download_url(bduss, remote_path, session=sess)
                        if not dl_url:
                            break
                    else:
                        time.sleep(2 ** attempt)
                except requests.exceptions.RequestException:
                    time.sleep(2 ** attempt)

            if not success:
                results[seg_id] = False
                return
            chunk_idx += 1

        results[seg_id] = True

    # 워커 스레드 시작
    threads = []
    for i, (seg_start, seg_end) in enumerate(segments):
        t = threading.Thread(target=_seg_worker, args=(i, seg_start, seg_end),
                             daemon=True)
        t.start()
        threads.append(t)

    # 완료 대기
    try:
        for t in threads:
            t.join()
    finally:
        # 프로그레스 타이머 종료
        _all_done.set()
        _reporter.join(timeout=2)
        fp.close()

    # 최종 프로그레스 보고
    total_dl = sum(seg_progress)
    elapsed = time.time() - start_time
    speed = total_dl / elapsed if elapsed > 0 else 0
    if progress_callback:
        progress_callback(total_dl, total_size, speed)
    else:
        progress_bar(total_dl, total_size, speed=speed)
        print()

    ok = all(r is True for r in results)
    if not ok:
        _print("  일부 세그먼트 다운로드 실패.")
    return ok


# ── Bilibili 다운로드 ─────────────────────────────────────────────────────────

import hashlib
import re

_BILI_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
_BILI_REFERER = "https://www.bilibili.com/"

_WBI_MIXIN_KEY_ENC_TAB = [
    46, 47, 18, 2, 53, 8, 23, 32, 15, 50, 10, 31, 58, 3, 45, 35, 27, 43, 5, 49,
    33, 9, 42, 19, 29, 28, 14, 39, 12, 38, 41, 13, 37, 48, 7, 16, 24, 55, 40,
    61, 26, 17, 0, 1, 60, 51, 30, 4, 22, 25, 54, 21, 56, 59, 6, 63, 57, 62, 11,
    36, 20, 34, 44, 52,
]

_wbi_key_cache = {"key": None, "ts": 0}


def _bili_session():
    s = requests.Session()
    s.headers["User-Agent"] = _BILI_UA
    s.headers["Referer"] = _BILI_REFERER
    return s


def _get_wbi_key(session=None):
    """WBI 서명 키 획득 (캐시 10분)"""
    now = time.time()
    if _wbi_key_cache["key"] and now - _wbi_key_cache["ts"] < 600:
        return _wbi_key_cache["key"]
    s = session or _bili_session()
    r = s.get("https://api.bilibili.com/x/web-interface/nav", timeout=10)
    data = r.json().get("data", {})
    wbi = data.get("wbi_img", {})
    img_url = wbi.get("img_url", "")
    sub_url = wbi.get("sub_url", "")
    img_key = img_url.rsplit("/", 1)[-1].split(".")[0]
    sub_key = sub_url.rsplit("/", 1)[-1].split(".")[0]
    lookup = img_key + sub_key
    wbi_key = "".join(lookup[i] for i in _WBI_MIXIN_KEY_ENC_TAB if i < len(lookup))[:32]
    _wbi_key_cache["key"] = wbi_key
    _wbi_key_cache["ts"] = now
    return wbi_key


def _sign_wbi(params, wbi_key):
    """WBI 서명 적용"""
    params["wts"] = str(round(time.time()))
    cleaned = {}
    for k, v in sorted(params.items()):
        cleaned[k] = str(v).translate({ord(c): "" for c in "!'()*"})
    query = urllib.parse.urlencode(cleaned)
    params["w_rid"] = hashlib.md5((query + wbi_key).encode()).hexdigest()
    return params


def bili_parse_url(url):
    """Bilibili URL에서 BV/AV ID 추출 → bvid 문자열"""
    m = re.search(r"bilibili\.com/video/([ABab][Vv][a-zA-Z0-9]+)", url)
    if m:
        return m.group(1)
    m = re.search(r"bilibili\.com/video/av(\d+)", url)
    if m:
        return None  # av ID는 별도 처리 필요 — 일단 BV만 지원
    m = re.search(r"bvid=([ABab][Vv][a-zA-Z0-9]+)", url)
    if m:
        return m.group(1)
    return None


def bili_get_video_info(bvid, session=None):
    """비디오 정보 조회 → dict(title, cid, aid, pages, pic, duration)"""
    s = session or _bili_session()
    r = s.get("https://api.bilibili.com/x/web-interface/view",
              params={"bvid": bvid}, timeout=10)
    data = r.json()
    if data.get("code") != 0:
        return None
    d = data["data"]
    return {
        "bvid": d["bvid"],
        "aid": d["aid"],
        "title": d.get("title", ""),
        "pic": d.get("pic", ""),
        "duration": d.get("duration", 0),
        "cid": d["cid"],
        "pages": d.get("pages", []),
    }


def bili_get_streams(bvid, cid, session=None, sessdata=None):
    """DASH 스트림 URL 획득 → dict(video=[], audio=[])
    sessdata: SESSDATA 쿠키 값 (VIP 계정이면 4K 가능)
    """
    s = session or _bili_session()
    if sessdata:
        s.cookies.set("SESSDATA", sessdata, domain=".bilibili.com")
    wbi_key = _get_wbi_key(s)
    params = {
        "bvid": bvid,
        "cid": str(cid),
        "fnval": "4048",
        "fourk": "1",
        "qn": "127",
    }
    if not sessdata:
        params["try_look"] = "1"
    params = _sign_wbi(params, wbi_key)
    r = s.get("https://api.bilibili.com/x/player/wbi/playurl",
              params=params, timeout=10)
    data = r.json()
    if data.get("code") != 0:
        return None
    dash = data.get("data", {}).get("dash")
    if not dash:
        return None
    videos = []
    for v in dash.get("video", []):
        videos.append({
            "qn": v.get("id", 0),
            "codec": v.get("codecs", ""),
            "width": v.get("width", 0),
            "height": v.get("height", 0),
            "bandwidth": v.get("bandwidth", 0),
            "url": v.get("baseUrl") or v.get("base_url", ""),
            "backup": v.get("backupUrl") or v.get("backup_url", []),
            "size": v.get("size", 0),
        })
    audios = []
    for a in dash.get("audio", []):
        audios.append({
            "id": a.get("id", 0),
            "codec": a.get("codecs", ""),
            "bandwidth": a.get("bandwidth", 0),
            "url": a.get("baseUrl") or a.get("base_url", ""),
            "backup": a.get("backupUrl") or a.get("backup_url", []),
            "size": a.get("size", 0),
        })
    return {"video": videos, "audio": audios,
            "quality": data["data"].get("quality", 0),
            "accept_quality": data["data"].get("accept_quality", [])}


def _bili_qn_label(qn):
    labels = {6: "240P", 16: "360P", 32: "480P", 64: "720P",
              74: "720P60", 80: "1080P", 112: "1080P+",
              116: "1080P60", 120: "4K", 125: "HDR", 126: "Dolby", 127: "8K"}
    return labels.get(qn, f"{qn}")


# ── Bilibili gRPC (모바일 APP API) — 트라이얼 4K ────────────────────────────

def _pb_varint(value):
    """Protobuf varint 인코딩"""
    buf = bytearray()
    while value > 0x7F:
        buf.append((value & 0x7F) | 0x80)
        value >>= 7
    buf.append(value & 0x7F)
    return bytes(buf)

def _pb_field(field_num, wire_type, data):
    """Protobuf 필드 인코딩"""
    tag = _pb_varint((field_num << 3) | wire_type)
    if wire_type == 0:  # varint
        return tag + _pb_varint(data)
    elif wire_type == 2:  # length-delimited
        if isinstance(data, str):
            data = data.encode("utf-8")
        return tag + _pb_varint(len(data)) + data
    return tag + data

def _pb_read_varint(buf, pos):
    """Protobuf varint 디코딩"""
    result = 0
    shift = 0
    while pos < len(buf):
        b = buf[pos]
        result |= (b & 0x7F) << shift
        pos += 1
        if not (b & 0x80):
            break
        shift += 7
    return result, pos

def _pb_parse(buf):
    """간단한 protobuf 메시지 파싱 → {field_num: [(wire_type, value), ...]}"""
    fields = {}
    pos = 0
    while pos < len(buf):
        tag, pos = _pb_read_varint(buf, pos)
        field_num = tag >> 3
        wire_type = tag & 0x07
        if wire_type == 0:  # varint
            val, pos = _pb_read_varint(buf, pos)
        elif wire_type == 2:  # length-delimited
            length, pos = _pb_read_varint(buf, pos)
            val = buf[pos:pos + length]
            pos += length
        elif wire_type == 5:  # 32-bit
            val = buf[pos:pos + 4]
            pos += 4
        elif wire_type == 1:  # 64-bit
            val = buf[pos:pos + 8]
            pos += 8
        else:
            break
        fields.setdefault(field_num, []).append((wire_type, val))
    return fields

def _pb_get_varint(fields, num, default=0):
    """파싱된 필드에서 varint 값 가져오기"""
    for wt, val in fields.get(num, []):
        if wt == 0:
            return val
    return default

def _pb_get_bytes(fields, num, default=b""):
    """파싱된 필드에서 bytes 값 가져오기"""
    for wt, val in fields.get(num, []):
        if wt == 2:
            return val
    return default

def _pb_get_string(fields, num, default=""):
    b = _pb_get_bytes(fields, num)
    return b.decode("utf-8", errors="replace") if b else default

def _pb_get_all(fields, num):
    """파싱된 필드에서 해당 번호의 모든 값 리스트"""
    return [(wt, val) for wt, val in fields.get(num, [])]


def _bili_grpc_metadata():
    """gRPC 메타데이터 바이너리 헤더 생성 (비로그인)"""
    import base64, uuid
    buvid = str(uuid.uuid4()).upper()
    # x-bili-metadata-bin: Metadata protobuf
    # field 5: mobi_app="android", field 6: device="android",
    # field 8: build=7320200, field 9: channel="master",
    # field 11: buvid=<uuid>, field 12: platform="android"
    meta = (
        _pb_field(5, 2, "android") +
        _pb_field(6, 2, "android") +
        _pb_field(8, 0, 7320200) +
        _pb_field(9, 2, "master") +
        _pb_field(11, 2, buvid) +
        _pb_field(12, 2, "android")
    )
    # x-bili-device-bin: Device protobuf
    # field 1: brand, field 2: model, field 3: os_ver,
    # field 5: build=7320200
    dev = (
        _pb_field(1, 2, "Xiaomi") +
        _pb_field(2, 2, "M2012K11AC") +
        _pb_field(3, 2, "11") +
        _pb_field(5, 0, 7320200)
    )
    # x-bili-fawkes-req-bin: Fawkes protobuf
    # field 1: app_key="android64", field 2: env="prod"
    fawkes = (
        _pb_field(1, 2, "android64") +
        _pb_field(2, 2, "prod")
    )
    return {
        "x-bili-metadata-bin": base64.b64encode(meta).decode(),
        "x-bili-device-bin": base64.b64encode(dev).decode(),
        "x-bili-fawkes-req-bin": base64.b64encode(fawkes).decode(),
    }


def _grpc_wrap(payload):
    """gRPC 페이로드 래핑 (5바이트 헤더: 압축 플래그 + 길이)"""
    import struct
    return struct.pack(">BI", 0, len(payload)) + payload

def _grpc_unwrap(data):
    """gRPC 응답에서 페이로드 추출"""
    import struct
    if len(data) < 5:
        return None
    compressed, length = struct.unpack(">BI", data[:5])
    return data[5:5 + length]


def bili_get_streams_grpc(aid, cid):
    """gRPC PlayViewUnite API로 4K 트라이얼 스트림 획득

    서버가 트라이얼 4K URL을 실제 반환 → 30초 제한은 클라이언트측만 강제
    → 다운로더는 전체 파일 다운로드 가능
    """
    try:
        import httpx
    except ImportError:
        return None

    # PlayViewUniteReq 구성
    # VideoVod 메시지 (field 1 of PlayViewUniteReq)
    vod = (
        _pb_field(1, 0, int(aid)) +   # aid
        _pb_field(2, 0, int(cid)) +   # cid
        _pb_field(3, 0, 127) +        # qn = 127 (8K, 최고 요청)
        _pb_field(4, 0, 0) +          # fnver
        _pb_field(5, 0, 4048) +       # fnval = DASH + 모든 옵션
        _pb_field(8, 0, 1) +          # fourk = true
        _pb_field(10, 0, 2)           # prefer_codec_type = HEVC(2), AVC(0)
    )
    req = _pb_field(1, 2, vod)  # field 1 = vod (VideoVod 메시지)

    grpc_body = _grpc_wrap(req)

    meta = _bili_grpc_metadata()
    headers = {
        "content-type": "application/grpc",
        "user-agent": "Dalvik/2.1.0 (Linux; U; Android 11; M2012K11AC Build/RKQ1.200826.002) 7.32.0 os/android model/M2012K11AC mobi_app/android build/7320200 channel/master innerVer/7320200 osVer/11 network/2",
        "te": "trailers",
        "x-bili-metadata-bin": meta["x-bili-metadata-bin"],
        "x-bili-device-bin": meta["x-bili-device-bin"],
        "x-bili-fawkes-req-bin": meta["x-bili-fawkes-req-bin"],
    }

    url = "https://grpc.biliapi.net/bilibili.app.playerunite.v1.Player/PlayViewUnite"

    try:
        with httpx.Client(http2=True, timeout=15) as client:
            resp = client.post(url, content=grpc_body, headers=headers)
            if resp.status_code != 200:
                return None
            body = _grpc_unwrap(resp.content)
            if not body:
                return None
    except Exception:
        return None

    return _parse_grpc_play_reply(body)


def _parse_grpc_play_reply(body):
    """PlayViewUniteReply protobuf 파싱 → streams dict"""
    reply = _pb_parse(body)

    # field 1 = vod_info (VideoInfo)
    vod_bytes = _pb_get_bytes(reply, 1)
    if not vod_bytes:
        return None

    vod = _pb_parse(vod_bytes)

    # VideoInfo: field 2 = stream_list (repeated Stream)
    stream_entries = _pb_get_all(vod, 2)
    # VideoInfo: field 3 = dash_audio (repeated DashItem)
    audio_entries = _pb_get_all(vod, 3)

    videos = []
    for wt, sdata in stream_entries:
        if wt != 2:
            continue
        stream = _pb_parse(sdata)
        # Stream: field 1 = stream_info (StreamInfo)
        si_bytes = _pb_get_bytes(stream, 1)
        # Stream: field 2 = dash_video (DashVideo)
        dv_bytes = _pb_get_bytes(stream, 2)
        if not si_bytes or not dv_bytes:
            continue

        si = _pb_parse(si_bytes)
        qn = _pb_get_varint(si, 1)       # quality
        codec_str = _pb_get_string(si, 2) # format
        desc = _pb_get_string(si, 3)      # description
        need_vip = _pb_get_varint(si, 6)  # need_vip
        need_login = _pb_get_varint(si, 7) # need_login

        dv = _pb_parse(dv_bytes)
        base_url = _pb_get_string(dv, 1)  # base_url
        # DashVideo: field 2 = backup_url (repeated)
        backups = [v.decode("utf-8", errors="replace")
                   for wt2, v in _pb_get_all(dv, 2) if wt2 == 2]
        bandwidth = _pb_get_varint(dv, 3)
        codecid = _pb_get_varint(dv, 4)
        width = _pb_get_varint(dv, 7)
        height = _pb_get_varint(dv, 8)
        size = _pb_get_varint(dv, 10)

        if not base_url:
            continue

        # codecid: 7=AVC(H.264), 12=HEVC(H.265), 13=AV1
        codec_name = {7: "avc", 12: "hevc", 13: "av1"}.get(codecid, f"c{codecid}")

        videos.append({
            "qn": qn,
            "codec": codec_name,
            "width": width,
            "height": height,
            "bandwidth": bandwidth,
            "url": base_url,
            "backup": backups,
            "size": size,
            "need_vip": bool(need_vip),
        })

    audios = []
    for wt, adata in audio_entries:
        if wt != 2:
            continue
        da = _pb_parse(adata)
        base_url = _pb_get_string(da, 1)
        backups = [v.decode("utf-8", errors="replace")
                   for wt2, v in _pb_get_all(da, 2) if wt2 == 2]
        bandwidth = _pb_get_varint(da, 3)
        codecid = _pb_get_varint(da, 4)
        audio_id = _pb_get_varint(da, 7)
        size = _pb_get_varint(da, 10)

        if not base_url:
            continue
        audios.append({
            "id": audio_id or codecid,
            "codec": f"audio_{codecid}",
            "bandwidth": bandwidth,
            "url": base_url,
            "backup": backups,
            "size": size,
        })

    # field 7 = qn_trial_info (QnTrialInfo)
    trial_bytes = _pb_get_bytes(reply, 7)
    trial_info = None
    if trial_bytes:
        ti = _pb_parse(trial_bytes)
        trial_info = {
            "trial_able": bool(_pb_get_varint(ti, 1)),
            "remaining_times": _pb_get_varint(ti, 2),
            "time_length": _pb_get_varint(ti, 4),
        }

    if not videos:
        return None

    return {
        "video": videos,
        "audio": audios,
        "trial_info": trial_info,
        "source": "grpc",
    }


def bili_download_stream(url, output_path, referer=None,
                         progress_callback=None, cancel_flag=None,
                         pause_flag=None):
    """Bilibili 스트림(m4s) 다운로드"""
    headers = {"User-Agent": _BILI_UA,
               "Referer": referer or _BILI_REFERER}
    try:
        r = requests.get(url, headers=headers, timeout=30, stream=True)
        r.raise_for_status()
    except Exception:
        return False
    total = int(r.headers.get("Content-Length", 0))
    downloaded = 0
    start = time.time()
    last_t = start
    last_b = 0
    with open(output_path, "wb") as f:
        for chunk in r.iter_content(chunk_size=65536):
            while pause_flag and pause_flag():
                if cancel_flag and cancel_flag():
                    r.close()
                    return False
                time.sleep(0.2)
            if cancel_flag and cancel_flag():
                r.close()
                return False
            try:
                f.write(chunk)
            except OSError:
                r.close()
                return False
            downloaded += len(chunk)
            now = time.time()
            dt = now - last_t
            if dt >= 0.5 and progress_callback:
                speed = (downloaded - last_b) / dt
                progress_callback(downloaded, total, speed)
                last_t = now
                last_b = downloaded
            # Bilibili 속도 제한
            if SPEED_LIMIT_BILI > 0:
                expected = downloaded / SPEED_LIMIT_BILI
                actual = now - start
                if expected > actual:
                    time.sleep(min(expected - actual, 0.5))
    if progress_callback:
        progress_callback(downloaded, total, 0)
    return True


def _find_ffmpeg():
    """ffmpeg 실행 파일 경로 찾기"""
    import shutil, subprocess
    # 1) PATH에서 찾기
    path = shutil.which("ffmpeg")
    if path:
        return path
    # 2) exe와 같은 폴더
    if getattr(sys, "frozen", False):
        local = os.path.join(os.path.dirname(sys.executable), "ffmpeg.exe")
        if os.path.isfile(local):
            return local
    # 3) 일반적인 Windows 설치 경로
    for d in [
        r"C:\ffmpeg\bin\ffmpeg.exe",
        r"C:\ffmpeg\ffmpeg.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\ffmpeg\bin\ffmpeg.exe"),
        os.path.expandvars(r"%ProgramFiles%\ffmpeg\bin\ffmpeg.exe"),
        r"C:\ProgramData\chocolatey\bin\ffmpeg.exe",
    ]:
        if os.path.isfile(d):
            return d
    return None

_ffmpeg_path = None

def bili_mux(video_path, audio_path, output_path):
    """ffmpeg로 비디오+오디오 합치기"""
    global _ffmpeg_path
    if not _ffmpeg_path:
        _ffmpeg_path = _find_ffmpeg()
    if not _ffmpeg_path:
        return False
    import subprocess
    cmd = [
        _ffmpeg_path, "-y", "-i", video_path, "-i", audio_path,
        "-c", "copy", "-movflags", "+faststart", output_path
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=300)
        return result.returncode == 0
    except Exception:
        return False


def bili_check_ffmpeg():
    """ffmpeg 사용 가능 여부 확인"""
    global _ffmpeg_path
    _ffmpeg_path = _find_ffmpeg()
    return _ffmpeg_path is not None


# ── 공유 링크 처리 ────────────────────────────────────────────────────────────

def transfer_shared_file(bduss, share_url, extract_code, log=None):
    """공유 링크 파일을 내 클라우드에 저장 (requests API 방식)

    Returns: (saved_path, error_msg) — 성공이면 (path, None), 실패면 (None, msg)
    """
    import re
    def _log(msg):
        if log:
            log(msg)
        print(msg)

    s = requests.Session()
    web_ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/131.0.0.0 Safari/537.36")
    s.headers["User-Agent"] = web_ua
    s.cookies.set("BDUSS", bduss, domain=".baidu.com", path="/")
    s.cookies.set("BDUSS_BFESS", bduss, domain=".baidu.com", path="/")

    # 0. surl 추출
    surl_m = re.search(r'/s/1([A-Za-z0-9_-]+)', share_url)
    if not surl_m:
        return None, tr("err_bad_url")
    surl = surl_m.group(1)

    pwd_m = re.search(r'[?&]pwd=([A-Za-z0-9]+)', share_url)
    if pwd_m and not extract_code:
        extract_code = pwd_m.group(1)

    # 1. 공유 페이지 방문 (BAIDUID 등 필수 쿠키 확보)
    _log("공유 페이지 접근 중...")
    share_page_url = f"{PAN_BASE}/s/1{surl}"
    try:
        r = s.get(share_page_url, timeout=15)
    except requests.exceptions.ConnectionError:
        return None, tr("err_network")
    except requests.exceptions.Timeout:
        return None, tr("err_network")
    except Exception:
        return None, tr("err_network")
    s.headers["Referer"] = share_page_url

    # 2. 추출코드 검증 (verify) → sekey 획득
    sekey_raw = ""  # URL-encoded (from verify API)
    sekey_dec = ""  # URL-decoded (actual value)
    if extract_code:
        _log(f"추출코드 검증: {extract_code}")
        verify_url = f"{PAN_BASE}/share/verify"
        verify_params = {"surl": surl, "channel": "chunlei", "web": 1, "clienttype": 0}
        verify_data = {"pwd": extract_code, "vcode": "", "vcode_str": ""}
        try:
            r = s.post(verify_url, params=verify_params, data=verify_data, timeout=15)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            return None, tr("err_network")
        except Exception:
            return None, tr("err_network")
        try:
            vr = r.json()
        except Exception:
            return None, tr("err_server")
        if vr.get("errno") != 0:
            # errno -12: wrong code, -62: too many attempts
            e = vr.get("errno")
            if e in (-12, -9):
                return None, tr("err_wrong_code")
            elif e == -62:
                return None, tr("err_too_many")
            else:
                return None, tr("err_expired")
        sekey_raw = vr.get("randsk", "")
        sekey_dec = urllib.parse.unquote(sekey_raw)
        _log("추출코드 OK")

    # 3. BDCLND 쿠키 설정 후 공유 페이지 재방문 → shareid, uk, fs_id 파싱
    if sekey_raw:
        s.cookies.set("BDCLND", sekey_raw, domain=".baidu.com", path="/")
    _log("파일 정보 조회 중...")
    try:
        r = s.get(share_page_url, timeout=15)
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        return None, tr("err_network")
    except Exception:
        return None, tr("err_network")
    page_content = r.text

    shareid_m = re.search(r'"shareid":(\d+)', page_content)
    uk_matches = re.findall(r'"(?:share_uk|uk)"\s*:\s*"?(\d+)', page_content)
    fs_id_m = re.findall(r'"fs_id":(\d+)', page_content)

    shareid = shareid_m.group(1) if shareid_m else ""
    # uk=0 필터링 (비로그인 사용자에게 0이 표시됨)
    non_zero_uk = [u for u in uk_matches if u != "0"]
    uk = non_zero_uk[0] if non_zero_uk else (uk_matches[0] if uk_matches else "")
    fs_ids = fs_id_m if fs_id_m else []

    # 4. 파일 목록 API 폴백
    if not fs_ids or not shareid or not uk:
        _log("API로 파일 목록 조회...")
        list_url = f"{PAN_BASE}/rest/2.0/xpan/share"
        list_params = {
            "method": "list", "shorturl": surl,
            "sekey": sekey_dec, "dir": "/", "root": 1,
            "page": 1, "num": 100,
            "channel": "chunlei", "web": 1, "clienttype": 0,
        }
        try:
            r = s.get(list_url, params=list_params, timeout=15)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            return None, tr("err_network")
        except Exception:
            return None, tr("err_network")
        try:
            lr = r.json()
        except Exception:
            return None, tr("err_server")
        if lr.get("errno") == 0:
            file_list = lr.get("list", [])
            if not fs_ids:
                fs_ids = [str(f["fs_id"]) for f in file_list]
            if not shareid:
                shareid = str(lr.get("shareid", lr.get("share_id", "")))
            if not uk:
                uk = str(lr.get("uk", lr.get("share_uk", "")))
            _log(f"목록 OK: {len(file_list)}개 파일")
        else:
            e = lr.get("errno")
            if e in (-9, -21):
                return None, tr("err_expired")
            else:
                return None, tr("err_no_files")

    if not fs_ids:
        return None, tr("err_no_files")
    if not shareid or not uk:
        return None, tr("err_expired")

    _log(f"shareid={shareid}, uk={uk}, files={len(fs_ids)}")

    # 5. 내 클라우드에 저장 (transfer)
    # Cookie 헤더 직접 구성: BDUSS + BDUSS_BFESS + BDCLND + 세션 쿠키 전부
    _log("클라우드에 저장 중...")
    cookie_parts = [f"BDUSS={bduss}", f"BDUSS_BFESS={bduss}"]
    if sekey_raw:
        cookie_parts.append(f"BDCLND={sekey_raw}")
    for c in s.cookies:
        if c.name not in ("BDUSS", "BDUSS_BFESS", "BDCLND"):
            cookie_parts.append(f"{c.name}={c.value}")
    cookie_str = "; ".join(cookie_parts)

    ts = requests.Session()
    ts.headers["User-Agent"] = web_ua
    ts.headers["Cookie"] = cookie_str
    ts.headers["Referer"] = share_page_url
    ts.headers["Origin"] = PAN_BASE

    transfer_url = f"{PAN_BASE}/share/transfer"
    t_params = {
        "shareid": shareid, "from": uk,
        "sekey": sekey_dec,  # decoded sekey in params
        "channel": "chunlei", "web": 1, "clienttype": 0,
    }
    body = {
        "fsidlist": json.dumps([int(fid) for fid in fs_ids]),
        "path": "/",
    }

    try:
        r = ts.post(transfer_url, params=t_params, data=body, timeout=30)
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        return None, tr("err_network")
    except Exception:
        return None, tr("err_network")
    try:
        result = r.json()
    except Exception:
        return None, tr("err_server")

    errno = result.get("errno")
    _log(f"transfer 응답: errno={errno}")

    if errno == 0:
        extra = result.get("extra", {})
        flist = extra.get("list", [])
        if flist:
            saved_path = flist[0].get("to", "")
            _log(f"저장 완료: {saved_path}")
            return saved_path, None
        return "/", None
    elif errno in (4, 12):
        # 4: 중복 파일 (이미 저장됨), 12: 이미 존재
        dup = result.get("duplicated", {}).get("list", [])
        if dup:
            saved_path = dup[0].get("path", "/")
            _log(f"이미 존재: {saved_path}")
            return saved_path, None
        _log("이미 존재하는 파일")
        return "/", None
    else:
        # errno별 사용자 친화적 메시지
        if errno == -7:
            return None, tr("err_no_files")
        elif errno == -10:
            return None, tr("err_quota")
        elif errno in (-1, -3, -9, -21):
            return None, tr("err_expired")
        elif errno in (-6, -62):
            return None, tr("err_too_many")
        else:
            return None, tr("err_unknown")


# ── Quark Pan API ──────────────────────────────────────────────────────────────

QUARK_API_BASE = "https://drive-pc.quark.cn/1/clouddrive"
QUARK_COMMON_PARAMS = {"pr": "ucpro", "fr": "pc"}
_QUARK_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
             "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")


def quark_session(cookie_str):
    """Cookie 문자열로 Quark requests.Session 생성"""
    s = requests.Session()
    s.headers["User-Agent"] = _QUARK_UA
    s.headers["Referer"] = "https://pan.quark.cn/"
    s.headers["Accept"] = "application/json, text/plain, */*"
    # cookie_str → 개별 쿠키 파싱
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            s.cookies.set(k.strip(), v.strip(), domain=".quark.cn")
    return s


def quark_parse_url(url):
    """Quark 공유 URL에서 pwd_id 추출
    예: https://pan.quark.cn/s/abcdef123456
    Returns: pwd_id 문자열 또는 None
    """
    m = re.search(r'pan\.quark\.cn/s/([a-zA-Z0-9]+)', url)
    return m.group(1) if m else None


def quark_get_stoken(pwd_id, cookie_str, passcode=""):
    """공유 링크 stoken 획득
    Returns: (stoken, error_msg)
    """
    s = quark_session(cookie_str)
    url = f"{QUARK_API_BASE}/share/sharepage/token"
    params = dict(QUARK_COMMON_PARAMS)
    body = {"pwd_id": pwd_id, "passcode": passcode}
    try:
        r = s.post(url, params=params, json=body, timeout=15)
        data = r.json()
    except Exception:
        return None, tr("err_network")
    if data.get("status") != 200 and data.get("code") != 0:
        msg = data.get("message", "")
        if "passcode" in msg.lower() or data.get("code") == 41013:
            return None, tr("err_wrong_code")
        return None, msg or tr("err_expired")
    stoken = data.get("data", {}).get("stoken", "")
    if not stoken:
        return None, tr("err_expired")
    return stoken, None


def quark_list_files(pwd_id, stoken, cookie_str, pdir_fid="0"):
    """공유 파일 목록 조회
    Returns: (file_list, error_msg)
    """
    s = quark_session(cookie_str)
    url = f"{QUARK_API_BASE}/share/sharepage/detail"
    params = dict(QUARK_COMMON_PARAMS)
    params.update({
        "pwd_id": pwd_id,
        "stoken": stoken,
        "pdir_fid": pdir_fid,
        "force": 0,
        "_page": 1,
        "_size": 200,
        "_sort": "file_type:asc,updated_at:desc",
    })
    try:
        r = s.get(url, params=params, timeout=15)
        data = r.json()
    except Exception:
        return None, tr("err_network")
    if data.get("status") != 200 and data.get("code") != 0:
        return None, data.get("message", tr("err_expired"))
    file_list = data.get("data", {}).get("list", [])
    return file_list, None


def quark_save_to_drive(pwd_id, stoken, fid_list, fid_token_list, cookie_str, to_pdir_fid="0"):
    """공유 파일을 내 드라이브에 저장
    Returns: (task_id, error_msg)
    """
    s = quark_session(cookie_str)
    url = f"{QUARK_API_BASE}/share/sharepage/save"
    params = dict(QUARK_COMMON_PARAMS)
    body = {
        "pwd_id": pwd_id,
        "stoken": stoken,
        "fid_list": fid_list,
        "fid_token_list": fid_token_list,
        "to_pdir_fid": to_pdir_fid,
    }
    try:
        r = s.post(url, params=params, json=body, timeout=30)
        data = r.json()
    except Exception:
        return None, tr("err_network")
    if data.get("status") != 200 and data.get("code") != 0:
        msg = data.get("message", "")
        if "space" in msg.lower() or data.get("code") == 41017:
            return None, tr("err_quota")
        return None, msg or tr("err_unknown")
    task_id = data.get("data", {}).get("task_id", "")
    return task_id, None


def quark_get_download_url(fid, cookie_str):
    """다운로드 URL 획득
    Returns: (download_url, error_msg)
    """
    s = quark_session(cookie_str)
    url = f"{QUARK_API_BASE}/file/download"
    params = dict(QUARK_COMMON_PARAMS)
    body = {"fids": [fid]}
    try:
        r = s.post(url, params=params, json=body, timeout=15)
        data = r.json()
    except Exception:
        return None, tr("err_network")
    if data.get("status") != 200 and data.get("code") != 0:
        return None, data.get("message", tr("err_unknown"))
    dl_list = data.get("data", [])
    if not dl_list:
        return None, tr("err_no_files")
    dl_url = dl_list[0].get("download_url", "")
    if not dl_url:
        return None, tr("err_no_files")
    return dl_url, None


def quark_download_file(download_url, cookie_str, output_path, total_size=0,
                        progress_callback=None, cancel_flag=None, pause_flag=None):
    """Quark 파일 다운로드 (Range 지원, 속도 제한)
    Returns: True/False
    """
    s = quark_session(cookie_str)
    headers = {"User-Agent": _QUARK_UA, "Referer": "https://pan.quark.cn/"}
    # 이어받기
    downloaded = 0
    if os.path.exists(output_path):
        downloaded = os.path.getsize(output_path)
        if total_size > 0 and downloaded >= total_size:
            return True
    if downloaded > 0:
        headers["Range"] = f"bytes={downloaded}-"
    mode = "ab" if downloaded > 0 else "wb"
    try:
        r = requests.get(download_url, headers=headers, timeout=60, stream=True,
                         cookies=s.cookies)
        if r.status_code not in (200, 206):
            return False
    except Exception:
        return False
    if total_size == 0:
        total_size = int(r.headers.get("Content-Length", 0)) + downloaded
    start_time = time.time()
    last_t = start_time
    last_b = downloaded
    with open(output_path, mode) as f:
        for chunk in r.iter_content(chunk_size=65536):
            while pause_flag and pause_flag():
                if cancel_flag and cancel_flag():
                    r.close()
                    return False
                time.sleep(0.2)
            if cancel_flag and cancel_flag():
                r.close()
                return False
            try:
                f.write(chunk)
            except OSError:
                r.close()
                return False
            downloaded += len(chunk)
            now = time.time()
            dt = now - last_t
            if dt >= 0.5:
                speed = (downloaded - last_b) / dt
                if progress_callback:
                    progress_callback(downloaded, total_size, speed)
                last_t = now
                last_b = downloaded
            # Quark 속도 제한
            if SPEED_LIMIT_QUARK > 0:
                expected = downloaded / SPEED_LIMIT_QUARK
                actual = now - start_time
                if expected > actual:
                    time.sleep(min(expected - actual, 0.5))
    if progress_callback:
        progress_callback(downloaded, total_size, 0)
    return True


# ── CLI 명령 ──────────────────────────────────────────────────────────────────

def cmd_login(args):
    """BDUSS 입력 및 저장"""
    cfg = load_config()

    if args.bduss:
        bduss = args.bduss
    else:
        print("BDUSS를 입력하세요 (브라우저 쿠키에서 복사):")
        bduss = input("> ").strip()

    if not bduss:
        print("BDUSS가 비어있습니다.")
        return

    print("로그인 확인 중...")
    info = verify_login(bduss)
    if info:
        cfg["bduss"] = bduss
        save_config(cfg)
        vip_str = ["일반", "일반VIP", "슈퍼VIP"][info["vip"]] if info["vip"] < 3 else f"VIP{info['vip']}"
        print(f"로그인 성공: {info['name']} ({vip_str})")
    else:
        print("로그인 실패: BDUSS가 유효하지 않습니다.")


def cmd_ls(args):
    """파일 목록"""
    bduss = get_bduss()
    dir_path = args.path or "/"

    print(f"목록: {dir_path}")
    print("-" * 70)

    files = list_files(bduss, dir_path)
    if not files:
        print("  (비어있음)")
        return

    for f in files:
        is_dir = f.get("isdir", 0) == 1
        name = f.get("server_filename", f.get("path", "?"))
        size = f.get("size", 0)
        mtime = time.strftime("%Y-%m-%d %H:%M", time.localtime(f.get("server_mtime", 0)))

        if is_dir:
            print(f"  📁 {name:<40s}          {mtime}")
        else:
            print(f"  📄 {name:<40s} {format_size(size):>10s}  {mtime}")

    print("-" * 70)
    print(f"  총 {len(files)}개 항목")


def cmd_dl(args):
    """파일 다운로드"""
    bduss = get_bduss()
    remote_path = args.path

    # 경로가 /로 시작하지 않으면 추가
    if not remote_path.startswith("/"):
        remote_path = "/" + remote_path

    # 파일 정보 확인
    parent = os.path.dirname(remote_path)
    if not parent:
        parent = "/"
    filename = os.path.basename(remote_path)

    print(f"파일 정보 확인 중: {remote_path}")
    files = list_files(bduss, parent)
    target = None
    for f in files:
        if f.get("path") == remote_path or f.get("server_filename") == filename:
            target = f
            break

    if not target:
        print(f"파일을 찾을 수 없습니다: {remote_path}")
        return

    if target.get("isdir") == 1:
        print("폴더는 다운로드할 수 없습니다. 개별 파일을 지정하세요.")
        return

    total_size = target.get("size", 0)
    fname = target.get("server_filename", filename)
    out_dir = args.output or get_download_dir()
    output_path = os.path.join(out_dir, fname)

    print(f"다운로드: {fname} ({format_size(total_size)})")
    print(f"저장 위치: {output_path}")
    print()

    start = time.time()
    ok = chunk_download(bduss, remote_path, output_path, total_size)
    elapsed = time.time() - start

    if ok:
        actual_size = os.path.getsize(output_path)
        avg_speed = actual_size / elapsed if elapsed > 0 else 0
        print(f"  완료! {format_size(actual_size)} / {elapsed:.1f}초 (평균 {format_size(int(avg_speed))}/s)")

        # MD5 확인 (옵션)
        target_md5 = target.get("md5", "")
        if target_md5 and actual_size == total_size:
            import hashlib
            print(f"  MD5 검증 중...")
            h = hashlib.md5()
            with open(output_path, "rb") as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    h.update(chunk)
            local_md5 = h.hexdigest()
            if local_md5.lower() == target_md5.lower():
                print(f"  MD5 일치: {local_md5}")
            else:
                print(f"  MD5 불일치! 로컬={local_md5}, 서버={target_md5}")
    else:
        print("  다운로드 실패.")


def cmd_share(args):
    """공유 링크 다운로드"""
    bduss = get_bduss()
    share_url = args.url
    code = args.code

    saved_path, err = transfer_shared_file(bduss, share_url, code)
    if not saved_path:
        print(f"공유 파일 저장 실패: {err}")
        print("수동으로 저장 후 dl 명령을 사용하세요.")
        return

    print()
    print(f"다운로드를 시작합니다: {saved_path}")
    # dl 명령 실행을 위해 args 구성
    dl_args = argparse.Namespace(path=saved_path, output=args.output if hasattr(args, "output") else None)
    cmd_dl(dl_args)


def cmd_config(args):
    """설정 관리"""
    cfg = load_config()

    if args.key and args.value:
        cfg[args.key] = args.value
        save_config(cfg)
        print(f"설정 저장: {args.key} = {args.value}")
    elif args.key:
        val = cfg.get(args.key, "(없음)")
        print(f"{args.key} = {val}")
    else:
        print("현재 설정:")
        for k, v in cfg.items():
            display = v
            if k == "bduss" and v:
                display = v[:10] + "..." + v[-5:]
            print(f"  {k} = {display}")


# ── 다국어 번역 ──────────────────────────────────────────────────────────────

_LANG_NAMES = {"en": "English", "ko": "한국어", "ja": "日本語", "zh": "中文"}
_lang = "en"

_T = {
 "en": {
  "menu_file":"File","menu_help":"Help","refresh":"Refresh","share_link":"Add Share Link","settings":"Settings","logout":"Logout","logout_confirm":"Are you sure you want to logout?","select":"",
  "not_logged_in":"Not logged in","name":"Name","size":"Size","modified":"Modified",
  "downloads":"Downloads","clear_done":"Clear Completed",
  "progress":"Progress","speed":"Speed","eta":"ETA","status":"Status",
  "queued":"Queued","downloading":"Downloading","complete":"Complete",
  "failed":"Failed","cancelled":"Cancelled",
  "cancel":"Cancel","remove":"Remove","open_folder":"Open Folder",
  "download":"Download","download_n":"Download ({n} files)",
  "login_title":"Login - Enter BDUSS",
  "login_guide":(
   '<b>How to copy BDUSS (Chrome / Edge)</b><br><br>'
   '1. <a href="https://pan.baidu.com">Open pan.baidu.com</a> (make sure you\'re logged in)<br>'
   '2. Press <b>F12</b> to open Developer Tools<br>'
   '3. Click the <b>Application</b> tab at the top<br>'
   '4. Left menu: <b>Cookies</b> → <b>https://pan.baidu.com</b><br>'
   '5. Find <b>BDUSS</b> in the list<br>'
   '6. Double-click Value → <b>Ctrl+A → Ctrl+C</b> to copy<br>'
   '7. <b>Ctrl+V</b> to paste below'),
  "bduss_label":"<b>BDUSS Value:</b>",
  "bduss_placeholder":"Paste BDUSS value here...",
  "auto_login":"Auto Login (connect automatically on next launch)",
  "btn_login":"Login","btn_cancel":"Cancel","btn_save":"Save",
  "err_empty":"Please enter BDUSS.","err_checking":"Checking...",
  "err_invalid":"Invalid BDUSS.",
  "login_required":"Login Required",
  "login_required_msg":"Login is required to use this application.\nDo you want to try again?",
  "share_title":"Save Share Link","share_url":"Share Link URL:",
  "share_code":"Extract Code:","share_code_ph":"Leave empty if none",
  "settings_title":"Settings","dl_folder":"Download Folder:",
  "browse":"Browse...","language":"Language:",
  "ready":"Ready","loading":"Loading...","login_ok":"Login successful",
  "logged_out":"Logged out","items":"{n} items",
  "queue_stat":"Queue: {t} total | {a} downloading | {q} queued | {d} complete",
  "login_first":"Please login first.",
  "processing_share":"Processing share link...",
  "saved_to_cloud":"Saved to your cloud:\n{path}\n\nRefreshing root folder.",
  "save_failed":"Could not save the shared file.",
  "select_folder":"Select Download Folder",
  "lang_changed":"Language changed. Some items update on next dialog open.",
  "update_available":"Update Available",
  "update_msg":"New version {v} is available.\nCurrent: {c}\n\nUpdate now?",
  "updating":"Downloading update...",
  "update_done":"Update downloaded. Restarting...",
  "update_fail":"Update failed: {e}",
  "no_update":"You are on the latest version ({v}).",
  "check_update":"Check Update",
  "pause":"Pause","resume":"Resume",
  "pause_all":"Pause All","resume_all":"Resume All","pause_selected":"Pause Selected","resume_selected":"Resume Selected",
  "delete_selected":"Delete Selected",
  "paused":"Paused",
  "retrying":"Retrying ({n})...",
  "auto_download":"Auto downloading...",
  "speed_limit":"Speed Limit:",
  "speed_desc":"Free accounts: recommended 1 MB/s or below.",
  "concurrent_files":"Concurrent Downloads","concurrent_desc":"Free accounts: exceeding 2 may cause Baidu to throttle or block.","concurrent_warn":"4+: Free accounts may experience slower speeds or errors.",
  "speed_unlimited":"Unlimited",
  "speed_warn":"⚠ Free accounts may be blocked if speed exceeds 1MB/s.\n   Recommended: 1MB/s or lower for free accounts.",
  "tray_or_quit":"Exit Application",
  "tray_or_quit_msg":"Minimize to tray or quit completely?",
  "tray_minimize":"Minimize to Tray","tray_quit":"Quit",
  "tray_show":"Show","tray_exit":"Exit",
  "err_bad_url":"Invalid share link URL format.",
  "err_expired":"This share link has expired or been deleted.",
  "err_wrong_code":"The extract code is incorrect.",
  "err_no_files":"No files found in this share link.",
  "err_network":"Network error. Please check your connection and try again.",
  "err_server":"Baidu server error. Please try again later.",
  "err_unknown":"An unexpected error occurred. Please try again.",
  "err_quota":"Your cloud storage is full. Please free up space.",
  "err_too_many":"Too many requests. Please wait a moment and try again.",
  "already_in_queue":"Already in queue",
  "speed_limit_enable":"Enable Speed Limit",
  "parallel_conn":"Connections per File",
  "parallel_conn_desc":"Free accounts: exceeding 4 may cause Baidu to throttle.",
  "parallel_conn_warn":"16+: Free accounts may get throttled or blocked.",
  "tray_downloading":"{n} downloading - {pct}%","tray_paused":"{n} paused","tray_idle":"Idle",
  "bili_download":"Bilibili Download","bili_url":"Enter Bilibili URL","bili_analyze":"Analyze","bili_quality":"Quality","bili_no_ffmpeg":"ffmpeg not found. Install ffmpeg to mux video/audio.","bili_analyzing":"Analyzing...","bili_no_streams":"No streams found.","bili_downloading":"Downloading Bilibili video...","bili_muxing":"Muxing video + audio...","bili_complete":"Bilibili download complete.","bili_failed":"Bilibili download failed.","bili_sessdata_hint":"Optional - paste SESSDATA cookie for 4K (VIP)",
  "quark_download":"Quark Pan Download","quark_title":"Quark Pan - Share Link","quark_passcode":"Passcode:","quark_cookie":"Cookie:","quark_cookie_hint":"Paste cookies from browser","quark_need_cookie":"Enter Quark cookie first","quark_saving":"Saving to drive...","quark_select_files":"{n} files found",
  "priority_download":"Download First","settings_general":"General","settings_baidu":"Baidu Pan","settings_bili":"Bilibili","settings_quark":"Quark Pan","bduss_hint":"Paste BDUSS value",
  "bduss_guide":"How to get BDUSS:\n1. Open pan.baidu.com in browser and log in\n2. Press F12 → Application → Cookies → pan.baidu.com\n3. Find 'BDUSS' and copy its value","sessdata_guide":"How to get SESSDATA:\n1. Open bilibili.com in browser and log in\n2. Press F12 → Application → Cookies → bilibili.com\n3. Find 'SESSDATA' and copy its value","quark_cookie_guide":"How to get Cookie:\n1. Open pan.quark.cn in browser and log in\n2. Press F12 → Network → any request → Headers\n3. Copy the entire 'Cookie' header value",
 },
 "ko": {
  "menu_file":"파일","menu_help":"도움말","refresh":"새로고침","share_link":"공유 링크로 추가","settings":"설정","logout":"로그아웃","logout_confirm":"로그아웃 하시겠습니까?","select":"",
  "not_logged_in":"미로그인","name":"이름","size":"크기","modified":"수정일",
  "downloads":"다운로드","clear_done":"완료 항목 삭제",
  "progress":"진행률","speed":"속도","eta":"남은시간","status":"상태",
  "queued":"대기","downloading":"다운로드 중","complete":"완료",
  "failed":"실패","cancelled":"취소됨",
  "cancel":"취소","remove":"삭제","open_folder":"폴더 열기",
  "download":"다운로드","download_n":"다운로드 ({n}개)",
  "login_title":"로그인 - BDUSS 입력",
  "login_guide":(
   '<b>BDUSS 복사 방법 (Chrome / Edge 동일)</b><br><br>'
   '1. <a href="https://pan.baidu.com">pan.baidu.com 열기</a> (로그인 상태 확인)<br>'
   '2. <b>F12</b> 키를 눌러 개발자 도구 열기<br>'
   '3. 상단 탭에서 <b>Application</b> (애플리케이션) 클릭<br>'
   '4. 왼쪽 메뉴 <b>Cookies</b> → <b>https://pan.baidu.com</b> 클릭<br>'
   '5. 쿠키 목록에서 <b>BDUSS</b> 찾기<br>'
   '6. Value 칸을 <b>더블클릭 → Ctrl+A → Ctrl+C</b> 로 복사<br>'
   '7. 아래에 <b>Ctrl+V</b> 로 붙여넣기'),
  "bduss_label":"<b>BDUSS 값:</b>",
  "bduss_placeholder":"여기에 BDUSS 값을 붙여넣으세요...",
  "auto_login":"자동 로그인 (다음 실행 시 자동 접속)",
  "btn_login":"로그인","btn_cancel":"취소","btn_save":"저장",
  "err_empty":"BDUSS를 입력하세요.","err_checking":"확인 중...",
  "err_invalid":"BDUSS가 유효하지 않습니다.",
  "login_required":"로그인 필요",
  "login_required_msg":"이 앱을 사용하려면 로그인이 필요합니다.\n다시 시도하시겠습니까?",
  "share_title":"공유 링크 저장","share_url":"공유 링크 URL:",
  "share_code":"추출코드:","share_code_ph":"없으면 비워두세요",
  "settings_title":"설정","dl_folder":"다운로드 폴더:",
  "browse":"찾아보기...","language":"언어:",
  "ready":"준비","loading":"로딩 중...","login_ok":"로그인 성공",
  "logged_out":"로그아웃","items":"{n}개 항목",
  "queue_stat":"큐: {t}개 전체 | {a}개 다운로드 중 | {q}개 대기 | {d}개 완료",
  "login_first":"먼저 로그인하세요.",
  "processing_share":"공유 링크 처리 중...",
  "saved_to_cloud":"클라우드에 저장 완료:\n{path}\n\n루트 폴더를 새로고침합니다.",
  "save_failed":"공유 파일 저장에 실패했습니다.",
  "select_folder":"다운로드 폴더 선택",
  "lang_changed":"언어가 변경되었습니다.",
  "update_available":"업데이트 있음",
  "update_msg":"새 버전 {v}이(가) 있습니다.\n현재: {c}\n\n지금 업데이트하시겠습니까?",
  "updating":"업데이트 다운로드 중...",
  "update_done":"업데이트 완료. 재시작합니다...",
  "update_fail":"업데이트 실패: {e}",
  "no_update":"최신 버전입니다 ({v}).",
  "check_update":"업데이트 확인",
  "pause":"일시정지","resume":"재개",
  "pause_all":"전체 일시정지","resume_all":"전체 재개","pause_selected":"선택 일시정지","resume_selected":"선택 재개",
  "delete_selected":"선택 삭제",
  "paused":"일시정지됨",
  "retrying":"재시도 ({n})...",
  "auto_download":"자동 다운로드 중...",
  "speed_limit":"속도 제한:",
  "speed_desc":"무료 계정은 1 MB/s 이하를 권장합니다.",
  "concurrent_files":"동시 다운로드 수","concurrent_desc":"무료 계정은 2개를 넘기면 바이두에서 속도 제한을 걸 수 있습니다.","concurrent_warn":"4개 이상: 무료 계정은 속도 저하나 오류가 발생할 수 있습니다.",
  "speed_unlimited":"무제한",
  "speed_warn":"⚠ 무료 계정은 1MB/s 초과 시 차단될 수 있습니다.\n   무료 계정 권장: 1MB/s 이하",
  "tray_or_quit":"프로그램 종료",
  "tray_or_quit_msg":"트레이로 최소화할까요, 완전히 종료할까요?",
  "tray_minimize":"트레이로 최소화","tray_quit":"종료",
  "tray_show":"창 열기","tray_exit":"종료",
  "err_bad_url":"유효하지 않은 공유 링크 형식입니다.",
  "err_expired":"공유 링크가 만료되었거나 삭제되었습니다.",
  "err_wrong_code":"추출코드가 올바르지 않습니다.",
  "err_no_files":"공유 링크에 파일이 없습니다.",
  "err_network":"네트워크 오류입니다. 인터넷 연결을 확인하고 다시 시도하세요.",
  "err_server":"바이두 서버 오류입니다. 잠시 후 다시 시도하세요.",
  "err_unknown":"알 수 없는 오류가 발생했습니다. 다시 시도하세요.",
  "err_quota":"클라우드 저장 공간이 부족합니다. 공간을 확보하세요.",
  "err_too_many":"요청이 너무 많습니다. 잠시 후 다시 시도하세요.",
  "already_in_queue":"이미 큐에 추가된 파일입니다",
  "speed_limit_enable":"속도 제한 사용",
  "parallel_conn":"파일당 연결 수",
  "parallel_conn_desc":"무료 계정은 4개를 넘기면 바이두에서 속도 제한을 걸 수 있습니다.",
  "parallel_conn_warn":"16개 이상: 무료 계정은 속도 제한이나 차단될 수 있습니다.",
  "tray_downloading":"{n}개 다운로드 중 - {pct}%","tray_paused":"{n}개 일시정지","tray_idle":"대기 중",
  "bili_download":"Bilibili 다운로드","bili_url":"Bilibili URL 입력","bili_analyze":"분석","bili_quality":"화질","bili_no_ffmpeg":"ffmpeg를 찾을 수 없습니다. 영상/음성 병합을 위해 ffmpeg를 설치하세요.","bili_analyzing":"분석 중...","bili_no_streams":"스트림을 찾을 수 없습니다.","bili_downloading":"Bilibili 영상 다운로드 중...","bili_muxing":"영상 + 음성 병합 중...","bili_complete":"Bilibili 다운로드 완료.","bili_failed":"Bilibili 다운로드 실패.","bili_sessdata_hint":"선택사항 - 4K용 SESSDATA 쿠키 붙여넣기 (VIP)",
  "quark_download":"Quark 다운로드","quark_title":"Quark 공유 링크","quark_passcode":"추출코드:","quark_cookie":"쿠키:","quark_cookie_hint":"브라우저에서 쿠키 붙여넣기","quark_need_cookie":"Quark 쿠키를 먼저 입력하세요","quark_saving":"드라이브에 저장 중...","quark_select_files":"{n}개 파일 발견",
  "priority_download":"우선 다운로드","settings_general":"일반","settings_baidu":"바이두","settings_bili":"Bilibili","settings_quark":"Quark","bduss_hint":"BDUSS 값 붙여넣기",
  "bduss_guide":"BDUSS 가져오는 방법:\n1. 브라우저에서 pan.baidu.com 접속 후 로그인\n2. F12 → 애플리케이션 → 쿠키 → pan.baidu.com\n3. 'BDUSS' 항목의 값을 복사","sessdata_guide":"SESSDATA 가져오는 방법:\n1. 브라우저에서 bilibili.com 접속 후 로그인\n2. F12 → 애플리케이션 → 쿠키 → bilibili.com\n3. 'SESSDATA' 항목의 값을 복사","quark_cookie_guide":"Cookie 가져오는 방법:\n1. 브라우저에서 pan.quark.cn 접속 후 로그인\n2. F12 → 네트워크 → 아무 요청 → 헤더\n3. 'Cookie' 헤더 값 전체를 복사",
 },
 "ja": {
  "menu_file":"ファイル","menu_help":"ヘルプ","refresh":"更新","share_link":"共有リンクで追加","settings":"設定","logout":"ログアウト","logout_confirm":"ログアウトしますか？","select":"",
  "not_logged_in":"未ログイン","name":"名前","size":"サイズ","modified":"更新日",
  "downloads":"ダウンロード","clear_done":"完了を削除",
  "progress":"進捗","speed":"速度","eta":"残り時間","status":"状態",
  "queued":"待機中","downloading":"ダウンロード中","complete":"完了",
  "failed":"失敗","cancelled":"キャンセル",
  "cancel":"キャンセル","remove":"削除","open_folder":"フォルダを開く",
  "download":"ダウンロード","download_n":"ダウンロード ({n}件)",
  "login_title":"ログイン - BDUSS入力",
  "login_guide":(
   '<b>BDUSSのコピー方法 (Chrome / Edge 共通)</b><br><br>'
   '1. <a href="https://pan.baidu.com">pan.baidu.com を開く</a> (ログイン状態を確認)<br>'
   '2. <b>F12</b>キーで開発者ツールを開く<br>'
   '3. 上部タブから<b>Application</b>をクリック<br>'
   '4. 左メニュー <b>Cookies</b> → <b>https://pan.baidu.com</b><br>'
   '5. Cookie一覧から<b>BDUSS</b>を探す<br>'
   '6. Valueをダブルクリック → <b>Ctrl+A → Ctrl+C</b>でコピー<br>'
   '7. 下の欄に<b>Ctrl+V</b>で貼り付け'),
  "bduss_label":"<b>BDUSS値:</b>",
  "bduss_placeholder":"BDUSSを貼り付けてください...",
  "auto_login":"自動ログイン (次回起動時に自動接続)",
  "btn_login":"ログイン","btn_cancel":"キャンセル","btn_save":"保存",
  "err_empty":"BDUSSを入力してください。","err_checking":"確認中...",
  "err_invalid":"BDUSSが無効です。",
  "login_required":"ログインが必要",
  "login_required_msg":"このアプリにはログインが必要です。\nもう一度試しますか？",
  "share_title":"共有リンク保存","share_url":"共有リンクURL:",
  "share_code":"抽出コード:","share_code_ph":"なければ空欄のまま",
  "settings_title":"設定","dl_folder":"ダウンロードフォルダ:",
  "browse":"参照...","language":"言語:",
  "ready":"準備完了","loading":"読み込み中...","login_ok":"ログイン成功",
  "logged_out":"ログアウト","items":"{n}件",
  "queue_stat":"キュー: {t}件 | {a}件DL中 | {q}件待機 | {d}件完了",
  "login_first":"先にログインしてください。",
  "processing_share":"共有リンク処理中...",
  "saved_to_cloud":"クラウドに保存完了:\n{path}\n\nルートフォルダを更新します。",
  "save_failed":"共有ファイルの保存に失敗しました。",
  "select_folder":"ダウンロードフォルダ選択",
  "lang_changed":"言語が変更されました。",
  "update_available":"アップデートあり",
  "update_msg":"新しいバージョン {v} があります。\n現在: {c}\n\n今すぐ更新しますか？",
  "updating":"アップデートをダウンロード中...",
  "update_done":"更新完了。再起動します...",
  "update_fail":"更新失敗: {e}",
  "no_update":"最新バージョンです ({v})。",
  "check_update":"更新確認",
  "pause":"一時停止","resume":"再開",
  "pause_all":"全て一時停止","resume_all":"全て再開","pause_selected":"選択一時停止","resume_selected":"選択再開",
  "delete_selected":"選択削除",
  "paused":"一時停止中",
  "retrying":"リトライ ({n})...",
  "auto_download":"自動ダウンロード中...",
  "speed_limit":"速度制限:",
  "speed_desc":"無料アカウントは1 MB/s以下を推奨します。",
  "concurrent_files":"同時ダウンロード数","concurrent_desc":"無料アカウントは2つを超えるとBaiduが速度制限をかける場合があります。","concurrent_warn":"4つ以上：無料アカウントは速度低下やエラーが発生する可能性があります。",
  "speed_unlimited":"無制限",
  "speed_warn":"⚠ 無料アカウントは1MB/s超過でブロックされる可能性があります。\n   推奨: 1MB/s以下",
  "tray_or_quit":"アプリ終了",
  "tray_or_quit_msg":"トレイに最小化しますか？完全に終了しますか？",
  "tray_minimize":"トレイに最小化","tray_quit":"終了",
  "tray_show":"表示","tray_exit":"終了",
  "err_bad_url":"無効な共有リンク形式です。",
  "err_expired":"共有リンクが期限切れまたは削除されました。",
  "err_wrong_code":"抽出コードが正しくありません。",
  "err_no_files":"共有リンクにファイルがありません。",
  "err_network":"ネットワークエラーです。接続を確認して再試行してください。",
  "err_server":"Baiduサーバーエラーです。しばらく後に再試行してください。",
  "err_unknown":"予期しないエラーが発生しました。再試行してください。",
  "err_quota":"クラウドストレージが満杯です。空き容量を確保してください。",
  "err_too_many":"リクエストが多すぎます。しばらく後に再試行してください。",
  "already_in_queue":"既にキューに追加済みです",
  "speed_limit_enable":"速度制限を有効にする",
  "parallel_conn":"ファイルごとの接続数",
  "parallel_conn_desc":"無料アカウントは4つを超えるとBaiduが速度制限をかける場合があります。",
  "parallel_conn_warn":"16以上：無料アカウントは速度制限やブロックされる可能性があります。",
  "tray_downloading":"{n}件ダウンロード中 - {pct}%","tray_paused":"{n}件一時停止中","tray_idle":"待機中",
  "bili_download":"Bilibiliダウンロード","bili_url":"Bilibili URLを入力","bili_analyze":"分析","bili_quality":"画質","bili_no_ffmpeg":"ffmpegが見つかりません。動画/音声の結合にffmpegをインストールしてください。","bili_analyzing":"分析中...","bili_no_streams":"ストリームが見つかりません。","bili_downloading":"Bilibili動画ダウンロード中...","bili_muxing":"動画＋音声を結合中...","bili_complete":"Bilibiliダウンロード完了。","bili_failed":"Bilibiliダウンロード失敗。","bili_sessdata_hint":"任意 - 4K用SESSDATAクッキーを貼り付け（VIP）",
  "quark_download":"Quarkダウンロード","quark_title":"Quark共有リンク","quark_passcode":"抽出コード:","quark_cookie":"クッキー:","quark_cookie_hint":"ブラウザからクッキーを貼り付け","quark_need_cookie":"Quarkクッキーを先に入力してください","quark_saving":"ドライブに保存中...","quark_select_files":"{n}件のファイルが見つかりました",
  "priority_download":"優先ダウンロード","settings_general":"一般","settings_baidu":"Baidu Pan","settings_bili":"Bilibili","settings_quark":"Quark Pan","bduss_hint":"BDUSS値を貼り付け",
  "bduss_guide":"BDUSSの取得方法:\n1. ブラウザでpan.baidu.comを開いてログイン\n2. F12→Application→Cookies→pan.baidu.com\n3. 'BDUSS'の値をコピー","sessdata_guide":"SESSデータの取得方法:\n1. ブラウザでbilibili.comを開いてログイン\n2. F12→Application→Cookies→bilibili.com\n3. 'SESSDATA'の値をコピー","quark_cookie_guide":"Cookieの取得方法:\n1. ブラウザでpan.quark.cnを開いてログイン\n2. F12→Network→任意のリクエスト→Headers\n3. 'Cookie'ヘッダーの値をコピー",
 },
 "zh": {
  "menu_file":"文件","menu_help":"帮助","refresh":"刷新","share_link":"通过共享链接添加","settings":"设置","logout":"退出登录","logout_confirm":"确定要退出登录吗？","select":"",
  "not_logged_in":"未登录","name":"文件名","size":"大小","modified":"修改日期",
  "downloads":"下载","clear_done":"清除已完成",
  "progress":"进度","speed":"速度","eta":"剩余时间","status":"状态",
  "queued":"排队中","downloading":"下载中","complete":"已完成",
  "failed":"失败","cancelled":"已取消",
  "cancel":"取消","remove":"删除","open_folder":"打开文件夹",
  "download":"下载","download_n":"下载 ({n}个文件)",
  "login_title":"登录 - 输入BDUSS",
  "login_guide":(
   '<b>BDUSS复制方法 (Chrome / Edge 通用)</b><br><br>'
   '1. <a href="https://pan.baidu.com">打开 pan.baidu.com</a> (确认已登录)<br>'
   '2. 按<b>F12</b>打开开发者工具<br>'
   '3. 点击顶部<b>Application</b>标签<br>'
   '4. 左侧菜单 <b>Cookies</b> → <b>https://pan.baidu.com</b><br>'
   '5. 在列表中找到<b>BDUSS</b><br>'
   '6. 双击Value → <b>Ctrl+A → Ctrl+C</b>复制<br>'
   '7. 在下方<b>Ctrl+V</b>粘贴'),
  "bduss_label":"<b>BDUSS值:</b>",
  "bduss_placeholder":"在此粘贴BDUSS...",
  "auto_login":"自动登录 (下次启动时自动连接)",
  "btn_login":"登录","btn_cancel":"取消","btn_save":"保存",
  "err_empty":"请输入BDUSS。","err_checking":"验证中...",
  "err_invalid":"BDUSS无效。",
  "login_required":"需要登录",
  "login_required_msg":"使用此应用需要登录。\n是否重试？",
  "share_title":"保存共享链接","share_url":"共享链接URL:",
  "share_code":"提取码:","share_code_ph":"没有则留空",
  "settings_title":"设置","dl_folder":"下载文件夹:",
  "browse":"浏览...","language":"语言:",
  "ready":"就绪","loading":"加载中...","login_ok":"登录成功",
  "logged_out":"已退出","items":"{n}个项目",
  "queue_stat":"队列: {t}个 | {a}个下载中 | {q}个排队 | {d}个完成",
  "login_first":"请先登录。",
  "processing_share":"处理共享链接中...",
  "saved_to_cloud":"已保存到云盘:\n{path}\n\n正在刷新根文件夹。",
  "save_failed":"无法保存共享文件。",
  "select_folder":"选择下载文件夹",
  "lang_changed":"语言已更改。",
  "update_available":"有可用更新",
  "update_msg":"新版本 {v} 已发布。\n当前: {c}\n\n立即更新？",
  "updating":"正在下载更新...",
  "update_done":"更新完成，正在重启...",
  "update_fail":"更新失败: {e}",
  "no_update":"已是最新版本 ({v})。",
  "check_update":"检查更新",
  "pause":"暂停","resume":"继续",
  "pause_all":"全部暂停","resume_all":"全部继续","pause_selected":"暂停选中","resume_selected":"继续选中",
  "delete_selected":"删除选中",
  "paused":"已暂停",
  "retrying":"重试 ({n})...",
  "auto_download":"自动下载中...",
  "speed_limit":"速度限制:",
  "speed_desc":"免费账户建议1 MB/s以下。",
  "concurrent_files":"同时下载数","concurrent_desc":"免费账户超过2个可能会被百度限速。","concurrent_warn":"4个以上：免费账户可能速度下降或出错。",
  "speed_unlimited":"无限制",
  "speed_warn":"⚠ 免费账户超过1MB/s可能被封。\n   建议: 1MB/s或更低",
  "tray_or_quit":"退出应用",
  "tray_or_quit_msg":"最小化到托盘还是完全退出？",
  "tray_minimize":"最小化到托盘","tray_quit":"退出",
  "tray_show":"显示","tray_exit":"退出",
  "err_bad_url":"无效的共享链接格式。",
  "err_expired":"共享链接已过期或被删除。",
  "err_wrong_code":"提取码不正确。",
  "err_no_files":"共享链接中没有文件。",
  "err_network":"网络错误，请检查网络连接后重试。",
  "err_server":"百度服务器错误，请稍后重试。",
  "err_unknown":"发生未知错误，请重试。",
  "err_quota":"云存储空间已满，请清理空间。",
  "err_too_many":"请求过多，请稍后重试。",
  "already_in_queue":"已在队列中",
  "speed_limit_enable":"启用速度限制",
  "parallel_conn":"每文件连接数",
  "parallel_conn_desc":"免费账户超过4个可能会被百度限速。",
  "parallel_conn_warn":"16个以上：免费账户可能被限速或封禁。",
  "tray_downloading":"{n}个下载中 - {pct}%","tray_paused":"{n}个已暂停","tray_idle":"空闲",
  "bili_download":"Bilibili下载","bili_url":"输入Bilibili URL","bili_analyze":"分析","bili_quality":"画质","bili_no_ffmpeg":"未找到ffmpeg。请安装ffmpeg以合并视频/音频。","bili_analyzing":"分析中...","bili_no_streams":"未找到可用流。","bili_downloading":"正在下载Bilibili视频...","bili_muxing":"正在合并视频+音频...","bili_complete":"Bilibili下载完成。","bili_failed":"Bilibili下载失败。","bili_sessdata_hint":"可选 - 粘贴SESSDATA Cookie以下载4K（VIP）",
  "quark_download":"夸克网盘下载","quark_title":"夸克网盘 - 共享链接","quark_passcode":"提取码:","quark_cookie":"Cookie:","quark_cookie_hint":"从浏览器粘贴Cookie","quark_need_cookie":"请先输入夸克Cookie","quark_saving":"正在保存到网盘...","quark_select_files":"发现{n}个文件",
  "priority_download":"优先下载","settings_general":"常规","settings_baidu":"百度网盘","settings_bili":"Bilibili","settings_quark":"夸克网盘","bduss_hint":"粘贴BDUSS值",
  "bduss_guide":"BDUSS获取方法:\n1. 在浏览器中打开pan.baidu.com并登录\n2. F12→Application→Cookies→pan.baidu.com\n3. 复制'BDUSS'的值","sessdata_guide":"SESSDATA获取方法:\n1. 在浏览器中打开bilibili.com并登录\n2. F12→Application→Cookies→bilibili.com\n3. 复制'SESSDATA'的值","quark_cookie_guide":"Cookie获取方法:\n1. 在浏览器中打开pan.quark.cn并登录\n2. F12→Network→任意请求→Headers\n3. 复制'Cookie'头的值",
 },
}

def _init_lang():
    global _lang, SPEED_LIMIT, SPEED_LIMIT_BAIDU, SPEED_LIMIT_BILI, SPEED_LIMIT_QUARK
    global MAX_CONCURRENT, PARALLEL_CONN
    cfg = load_config()
    _lang = cfg.get("language", "ko")
    if _lang not in _T:
        _lang = "en"
    # Legacy speed_limit → SPEED_LIMIT_BAIDU
    legacy = cfg.get("speed_limit", 0)
    if not cfg.get("speed_limit_enabled", True):
        legacy = 0
    SPEED_LIMIT_BAIDU = cfg.get("speed_limit_baidu", legacy)
    if not cfg.get("speed_limit_baidu_enabled", cfg.get("speed_limit_enabled", False)):
        SPEED_LIMIT_BAIDU = 0
    SPEED_LIMIT_BILI = cfg.get("speed_limit_bili", 0)
    if not cfg.get("speed_limit_bili_enabled", False):
        SPEED_LIMIT_BILI = 0
    SPEED_LIMIT_QUARK = cfg.get("speed_limit_quark", 0)
    if not cfg.get("speed_limit_quark_enabled", False):
        SPEED_LIMIT_QUARK = 0
    SPEED_LIMIT = SPEED_LIMIT_BAIDU  # alias for backward compat
    MAX_CONCURRENT = cfg.get("max_concurrent", MAX_CONCURRENT)
    PARALLEL_CONN = cfg.get("parallel_conn", PARALLEL_CONN)

def tr(key, **kw):
    text = _T.get(_lang, _T["en"]).get(key, _T["en"].get(key, key))
    if kw:
        text = text.format(**kw)
    return text


# ── PySide6 GUI ──────────────────────────────────────────────────────────────

if HAS_GUI:

    # ── QThread 워커 클래스 ───────────────────────────────────────────────────

    class VerifyLoginWorker(QThread):
        finished = Signal(object)  # user_info dict or None

        def __init__(self, bduss):
            super().__init__()
            self.bduss = bduss

        def run(self):
            try:
                info = verify_login(self.bduss)
                self.finished.emit(info)
            except Exception:
                self.finished.emit(None)

    class ListFilesWorker(QThread):
        finished = Signal(list)

        def __init__(self, bduss, dir_path):
            super().__init__()
            self.bduss = bduss
            self.dir_path = dir_path

        def run(self):
            try:
                files = list_files(self.bduss, self.dir_path)
                self.finished.emit(files)
            except Exception:
                self.finished.emit([])

    class QuotaWorker(QThread):
        quota_loaded = Signal(object, object)  # (used, total) or (None, None)

        def __init__(self, bduss):
            super().__init__()
            self.bduss = bduss

        def run(self):
            used, total = get_quota(self.bduss)
            self.quota_loaded.emit(used, total)

    class DownloadWorker(QThread):
        progress = Signal(int, int, float)  # downloaded, total, speed
        message = Signal(str)
        finished = Signal(bool)

        def __init__(self, bduss, remote_path, output_path, total_size):
            super().__init__()
            self.bduss = bduss
            self.remote_path = remote_path
            self.output_path = output_path
            self.total_size = total_size
            self._cancelled = False
            self._paused = False

        def cancel(self):
            self._cancelled = True

        def pause(self):
            self._paused = True

        def resume(self):
            self._paused = False

        def run(self):
            def _progress(downloaded, total, speed):
                self.progress.emit(downloaded, total, speed)

            def _is_cancelled():
                return self._cancelled

            def _is_paused():
                return self._paused

            ok = chunk_download(
                self.bduss, self.remote_path, self.output_path, self.total_size,
                progress_callback=_progress, cancel_flag=_is_cancelled,
                pause_flag=_is_paused,
            )
            self.finished.emit(ok)

    class ShareTransferWorker(QThread):
        message = Signal(str)
        finished = Signal(object)  # (saved_path, None) or (None, error_msg)

        def __init__(self, bduss, share_url, extract_code):
            super().__init__()
            self.bduss = bduss
            self.share_url = share_url
            self.extract_code = extract_code
            self._cancelled = False

        def cancel(self):
            self._cancelled = True

        def run(self):
            self.message.emit(tr("processing_share"))
            try:
                saved_path, err = transfer_shared_file(
                    self.bduss, self.share_url, self.extract_code,
                    log=lambda msg: self.message.emit(msg),
                )
                if self._cancelled:
                    self.finished.emit((None, "Cancelled"))
                else:
                    self.finished.emit((saved_path, err))
            except requests.exceptions.ConnectionError:
                self.finished.emit((None, tr("err_network")))
            except requests.exceptions.Timeout:
                self.finished.emit((None, tr("err_network")))
            except Exception:
                self.finished.emit((None, tr("err_unknown")))

    class BiliDownloadWorker(QThread):
        """Bilibili 비디오+오디오 다운로드 후 mux"""
        progress = Signal(int, int, float)  # downloaded, total, speed
        finished = Signal(bool)

        def __init__(self, video_url, audio_url, output_path, referer):
            super().__init__()
            self.video_url = video_url
            self.audio_url = audio_url
            self.output_path = output_path
            self.referer = referer
            self._cancelled = False
            self._paused = False

        def cancel(self):
            self._cancelled = True

        def pause(self):
            self._paused = True

        def resume(self):
            self._paused = False

        def run(self):
            import tempfile
            tmp_dir = os.path.dirname(self.output_path)
            base = os.path.splitext(os.path.basename(self.output_path))[0]
            vid_path = os.path.join(tmp_dir, f".{base}_v.m4s")
            aud_path = os.path.join(tmp_dir, f".{base}_a.m4s")

            # 1) 비디오 다운로드
            ok = bili_download_stream(
                self.video_url, vid_path, self.referer,
                progress_callback=lambda d, t, s: self.progress.emit(d, t, s),
                cancel_flag=lambda: self._cancelled,
                pause_flag=lambda: self._paused)
            if not ok or self._cancelled:
                self._cleanup(vid_path, aud_path)
                self.finished.emit(False)
                return

            # 2) 오디오 다운로드
            ok = bili_download_stream(
                self.audio_url, aud_path, self.referer,
                cancel_flag=lambda: self._cancelled,
                pause_flag=lambda: self._paused)
            if not ok or self._cancelled:
                self._cleanup(vid_path, aud_path)
                self.finished.emit(False)
                return

            # 3) mux
            ok = bili_mux(vid_path, aud_path, self.output_path)
            self._cleanup(vid_path, aud_path)
            self.finished.emit(ok)

        def _cleanup(self, *paths):
            for p in paths:
                try:
                    os.remove(p)
                except OSError:
                    pass

    class QuarkShareWorker(QThread):
        """Quark 공유 링크 분석 (stoken → 파일 목록)"""
        files_loaded = Signal(list)  # file list
        error = Signal(str)

        def __init__(self, url, cookie_str, passcode=""):
            super().__init__()
            self.url = url
            self.cookie_str = cookie_str
            self.passcode = passcode

        def run(self):
            pwd_id = quark_parse_url(self.url)
            if not pwd_id:
                self.error.emit(tr("err_bad_url"))
                return
            stoken, err = quark_get_stoken(pwd_id, self.cookie_str, self.passcode)
            if not stoken:
                self.error.emit(err)
                return
            files, err = quark_list_files(pwd_id, stoken, self.cookie_str)
            if files is None:
                self.error.emit(err)
                return
            # stoken, pwd_id를 각 파일에 주입
            for f in files:
                f["_stoken"] = stoken
                f["_pwd_id"] = pwd_id
            self.files_loaded.emit(files)

    class QuarkDownloadWorker(QThread):
        """Quark 파일 다운로드 (save-to-drive → download URL → 스트리밍)"""
        progress = Signal(int, int, float)
        finished = Signal(bool)

        def __init__(self, fid, fid_token, pwd_id, stoken, cookie_str, output_path, total_size, filename):
            super().__init__()
            self.fid = fid
            self.fid_token = fid_token
            self.pwd_id = pwd_id
            self.stoken = stoken
            self.cookie_str = cookie_str
            self.output_path = output_path
            self.total_size = total_size
            self.filename = filename
            self._cancelled = False
            self._paused = False

        def cancel(self):
            self._cancelled = True

        def pause(self):
            self._paused = True

        def resume(self):
            self._paused = False

        def run(self):
            # 1) save to drive
            task_id, err = quark_save_to_drive(
                self.pwd_id, self.stoken,
                [self.fid], [self.fid_token],
                self.cookie_str)
            # save 실패해도 이미 저장된 경우 계속 진행
            if self._cancelled:
                self.finished.emit(False)
                return

            # 2) get download URL (직접 fid로)
            dl_url, err = quark_get_download_url(self.fid, self.cookie_str)
            if not dl_url:
                self.finished.emit(False)
                return

            # 3) download
            ok = quark_download_file(
                dl_url, self.cookie_str, self.output_path, self.total_size,
                progress_callback=lambda d, t, s: self.progress.emit(d, t, s),
                cancel_flag=lambda: self._cancelled,
                pause_flag=lambda: self._paused)
            self.finished.emit(ok)

    class UpdateCheckWorker(QThread):
        """GitHub Releases에서 최신 버전 확인"""
        result = Signal(object)  # dict {"version","download_url"} or None

        def run(self):
            try:
                url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
                r = requests.get(url, timeout=10)
                if r.status_code != 200:
                    self.result.emit(None)
                    return
                data = r.json()
                tag = data.get("tag_name", "").lstrip("v")
                if not tag:
                    self.result.emit(None)
                    return
                # 버전 비교 (간단한 튜플 비교)
                latest = tuple(int(x) for x in tag.split("."))
                current = tuple(int(x) for x in APP_VERSION.split("."))
                if latest <= current:
                    self.result.emit(None)
                    return
                # exe 에셋 URL 찾기
                dl_url = None
                for asset in data.get("assets", []):
                    name = asset.get("name", "")
                    if name.endswith(".exe") and "Setup" not in name:
                        dl_url = asset["browser_download_url"]
                        break
                if not dl_url:
                    # Setup exe라도 사용
                    for asset in data.get("assets", []):
                        if asset.get("name", "").endswith(".exe"):
                            dl_url = asset["browser_download_url"]
                            break
                self.result.emit({"version": tag, "download_url": dl_url})
            except Exception:
                self.result.emit(None)

    class UpdateDownloadWorker(QThread):
        """새 exe 다운로드"""
        progress = Signal(int)  # 퍼센트 0~100
        finished = Signal(bool, str)  # (성공여부, 저장경로 또는 에러)

        def __init__(self, download_url, save_path):
            super().__init__()
            self.download_url = download_url
            self.save_path = save_path

        def run(self):
            try:
                r = requests.get(self.download_url, stream=True, timeout=60)
                total = int(r.headers.get("content-length", 0))
                downloaded = 0
                with open(self.save_path, "wb") as f:
                    for chunk in r.iter_content(chunk_size=CHUNK_SIZE):
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total > 0:
                            self.progress.emit(int(downloaded * 100 / total))
                self.finished.emit(True, self.save_path)
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                self.finished.emit(False, tr("err_network"))
            except Exception:
                self.finished.emit(False, tr("err_unknown"))

    # ── 다이얼로그 ───────────────────────────────────────────────────────────

    class ShareDialog(QDialog):
        def __init__(self, parent=None, initial_url=""):
            super().__init__(parent)
            self.setWindowTitle(tr("share_title"))
            self.setMinimumWidth(450)
            layout = QFormLayout(self)
            self.url_input = QLineEdit()
            self.url_input.setPlaceholderText("https://pan.baidu.com/s/...")

            # URL에서 추출코드 자동 파싱 (?pwd=xxxx 또는 提取码: xxxx)
            parsed_code = ""
            if initial_url:
                import re
                # ?pwd=xxxx 파라미터
                pwd_m = re.search(r'[?&]pwd=([A-Za-z0-9]+)', initial_url)
                if pwd_m:
                    parsed_code = pwd_m.group(1)
                    # URL에서 pwd 파라미터 제거하지 않음 (서버가 처리)
                # 提取码: xxxx 또는 추출코드: xxxx
                code_m = re.search(r'(?:提取码|추출코드|code)[:\s：]+([A-Za-z0-9]+)', initial_url)
                if code_m and not parsed_code:
                    parsed_code = code_m.group(1)
                self.url_input.setText(initial_url.split('\n')[0].strip())
            layout.addRow(tr("share_url"), self.url_input)
            self.code_input = QLineEdit()
            self.code_input.setPlaceholderText(tr("share_code_ph"))
            self.code_input.setMaxLength(8)
            if parsed_code:
                self.code_input.setText(parsed_code)
            layout.addRow(tr("share_code"), self.code_input)
            btn_layout = QHBoxLayout()
            ok_btn = QPushButton(tr("btn_save"))
            ok_btn.clicked.connect(self._on_ok)
            cancel_btn = QPushButton(tr("btn_cancel"))
            cancel_btn.clicked.connect(self.reject)
            btn_layout.addStretch()
            btn_layout.addWidget(ok_btn)
            btn_layout.addWidget(cancel_btn)
            layout.addRow(btn_layout)

            # URL이 있고 코드가 없으면 코드칸에 포커스
            if initial_url and not parsed_code:
                self.code_input.setFocus()

        def _on_ok(self):
            if self.url_input.text().strip():
                self.accept()

    class SettingsDialog(QDialog):
        def __init__(self, parent=None):
            super().__init__(parent)
            self.setWindowTitle(tr("settings_title"))
            self.setMinimumWidth(500)
            self.setMinimumHeight(380)
            cfg = load_config()
            self._parent_win = parent

            from PySide6.QtWidgets import QTabWidget, QSpinBox
            _combo_style = (
                "QComboBox { border: 1px solid palette(mid); border-radius: 3px; padding: 4px 8px; "
                "min-height: 22px; } "
                "QComboBox:hover { border-color: palette(highlight); } "
                "QComboBox::drop-down { border-left: 1px solid palette(mid); width: 20px; } "
                "QComboBox QAbstractItemView { border: 1px solid palette(mid); }")
            _input_style = (
                "QLineEdit { border: 1px solid palette(mid); border-radius: 3px; padding: 4px 8px; }"
                "QLineEdit:hover { border-color: palette(highlight); }")

            main_layout = QVBoxLayout(self)
            tabs = QTabWidget()
            main_layout.addWidget(tabs)

            # ── 일반 탭 ──
            general_tab = QWidget()
            g_lay = QFormLayout(general_tab)

            self.lang_combo = QComboBox()
            self.lang_combo.setStyleSheet(_combo_style)
            for code, name in _LANG_NAMES.items():
                self.lang_combo.addItem(name, code)
            cur_idx = list(_LANG_NAMES.keys()).index(_lang) if _lang in _LANG_NAMES else 0
            self.lang_combo.setCurrentIndex(cur_idx)
            g_lay.addRow(tr("language"), self.lang_combo)

            self.dl_dir_input = QLineEdit(cfg.get("download_dir", get_download_dir()))
            self.dl_dir_input.setStyleSheet(_input_style)
            browse_layout = QHBoxLayout()
            browse_layout.addWidget(self.dl_dir_input)
            browse_btn = QPushButton(tr("browse"))
            browse_btn.clicked.connect(self._browse)
            browse_layout.addWidget(browse_btn)
            g_lay.addRow(tr("dl_folder"), browse_layout)

            self.conc_spin = QSpinBox()
            self.conc_spin.setRange(1, 20)
            self.conc_spin.setStyleSheet(_input_style.replace("QLineEdit", "QSpinBox"))
            self.conc_spin.setValue(cfg.get("max_concurrent", MAX_CONCURRENT))
            conc_row = QHBoxLayout()
            conc_row.addWidget(self.conc_spin)
            conc_row.addWidget(QLabel("(default: 2)"))
            conc_row.addStretch()
            g_lay.addRow(tr("concurrent_files"), conc_row)

            self.pconn_spin = QSpinBox()
            self.pconn_spin.setRange(1, 128)
            self.pconn_spin.setStyleSheet(_input_style.replace("QLineEdit", "QSpinBox"))
            self.pconn_spin.setValue(cfg.get("parallel_conn", PARALLEL_CONN))
            pconn_row = QHBoxLayout()
            pconn_row.addWidget(self.pconn_spin)
            pconn_row.addWidget(QLabel("(default: 8)"))
            pconn_row.addStretch()
            g_lay.addRow(tr("parallel_conn"), pconn_row)

            tabs.addTab(general_tab, tr("settings_general"))

            # ── Helper: 속도 제한 위젯 생성 ──
            def _make_speed_row(cfg_key_enabled, cfg_key_value, default_enabled=False, default_val=1024*1024):
                row = QHBoxLayout()
                chk = QCheckBox(tr("speed_limit_enable"))
                enabled = cfg.get(cfg_key_enabled, default_enabled)
                chk.setChecked(enabled)
                row.addWidget(chk)
                spin = QSpinBox()
                spin.setRange(1, 1000)
                spin.setStyleSheet(_input_style.replace("QLineEdit", "QSpinBox"))
                unit = QComboBox()
                unit.setStyleSheet(_combo_style)
                unit.addItem("KB/s", 1024)
                unit.addItem("MB/s", 1024 * 1024)
                cur = cfg.get(cfg_key_value, default_val)
                if cur >= 1024 * 1024 and cur % (1024 * 1024) == 0:
                    spin.setValue(cur // (1024 * 1024))
                    unit.setCurrentIndex(1)
                else:
                    spin.setValue(max(1, cur // 1024))
                    unit.setCurrentIndex(0)
                spin.setEnabled(enabled)
                unit.setEnabled(enabled)
                chk.toggled.connect(spin.setEnabled)
                chk.toggled.connect(unit.setEnabled)
                row.addWidget(spin)
                row.addWidget(unit)
                return row, chk, spin, unit

            # ── Baidu Pan 탭 ──
            baidu_tab = QWidget()
            b_lay = QFormLayout(baidu_tab)

            bduss_guide = QLabel(tr("bduss_guide"))
            bduss_guide.setStyleSheet("font-size: 11px; color: #666; padding: 4px 0;")
            bduss_guide.setWordWrap(True)
            b_lay.addRow("", bduss_guide)

            self.bduss_input = QLineEdit()
            self.bduss_input.setStyleSheet(_input_style)
            self.bduss_input.setPlaceholderText(tr("bduss_hint"))
            self.bduss_input.setEchoMode(QLineEdit.EchoMode.Password)
            saved_bduss = cfg.get("bduss", "")
            if saved_bduss:
                self.bduss_input.setText(saved_bduss)
            bduss_row = QHBoxLayout()
            bduss_row.addWidget(self.bduss_input)
            self.bduss_verify_btn = QPushButton(tr("btn_login"))
            self.bduss_verify_btn.clicked.connect(self._verify_bduss)
            bduss_row.addWidget(self.bduss_verify_btn)
            b_lay.addRow("BDUSS:", bduss_row)

            self.bduss_status = QLabel("")
            self.bduss_status.setStyleSheet("font-size: 11px;")
            b_lay.addRow("", self.bduss_status)

            self.auto_login_cb = QCheckBox(tr("auto_login"))
            self.auto_login_cb.setChecked(cfg.get("auto_login", False))
            b_lay.addRow("", self.auto_login_cb)

            speed_row_b, self.speed_check_baidu, self.speed_spin_baidu, self.speed_unit_baidu = \
                _make_speed_row("speed_limit_baidu_enabled", "speed_limit_baidu",
                                cfg.get("speed_limit_enabled", False),
                                cfg.get("speed_limit", 1024*1024))
            b_lay.addRow(tr("speed_limit"), speed_row_b)
            b_desc = QLabel(tr("speed_desc"))
            b_desc.setStyleSheet("font-size: 11px;")
            b_desc.setWordWrap(True)
            b_lay.addRow("", b_desc)

            tabs.addTab(baidu_tab, tr("settings_baidu"))

            # ── Bilibili 탭 ──
            bili_tab = QWidget()
            bi_lay = QFormLayout(bili_tab)

            sessdata_guide = QLabel(tr("sessdata_guide"))
            sessdata_guide.setStyleSheet("font-size: 11px; color: #666; padding: 4px 0;")
            sessdata_guide.setWordWrap(True)
            bi_lay.addRow("", sessdata_guide)

            self.sessdata_input = QLineEdit()
            self.sessdata_input.setStyleSheet(_input_style)
            self.sessdata_input.setPlaceholderText(tr("bili_sessdata_hint"))
            self.sessdata_input.setEchoMode(QLineEdit.EchoMode.Password)
            saved_sess = cfg.get("bili_sessdata", "")
            if saved_sess:
                self.sessdata_input.setText(saved_sess)
            bi_lay.addRow("SESSDATA:", self.sessdata_input)

            speed_row_bi, self.speed_check_bili, self.speed_spin_bili, self.speed_unit_bili = \
                _make_speed_row("speed_limit_bili_enabled", "speed_limit_bili")
            bi_lay.addRow(tr("speed_limit"), speed_row_bi)

            tabs.addTab(bili_tab, tr("settings_bili"))

            # ── Quark Pan 탭 ──
            quark_tab = QWidget()
            q_lay = QFormLayout(quark_tab)

            quark_guide = QLabel(tr("quark_cookie_guide"))
            quark_guide.setStyleSheet("font-size: 11px; color: #666; padding: 4px 0;")
            quark_guide.setWordWrap(True)
            q_lay.addRow("", quark_guide)

            self.quark_cookie_input = QLineEdit()
            self.quark_cookie_input.setStyleSheet(_input_style)
            self.quark_cookie_input.setPlaceholderText(tr("quark_cookie_hint"))
            self.quark_cookie_input.setEchoMode(QLineEdit.EchoMode.Password)
            saved_qc = cfg.get("quark_cookie", "")
            if saved_qc:
                self.quark_cookie_input.setText(saved_qc)
            q_lay.addRow(tr("quark_cookie"), self.quark_cookie_input)

            speed_row_q, self.speed_check_quark, self.speed_spin_quark, self.speed_unit_quark = \
                _make_speed_row("speed_limit_quark_enabled", "speed_limit_quark")
            q_lay.addRow(tr("speed_limit"), speed_row_q)

            tabs.addTab(quark_tab, tr("settings_quark"))

            # ── 버튼 ──
            btn_layout = QHBoxLayout()
            ok_btn = QPushButton(tr("btn_save"))
            ok_btn.clicked.connect(self._on_save)
            cancel_btn = QPushButton(tr("btn_cancel"))
            cancel_btn.clicked.connect(self.reject)
            btn_layout.addStretch()
            btn_layout.addWidget(ok_btn)
            btn_layout.addWidget(cancel_btn)
            main_layout.addLayout(btn_layout)

        def _browse(self):
            d = QFileDialog.getExistingDirectory(self, tr("select_folder"), self.dl_dir_input.text())
            if d:
                self.dl_dir_input.setText(d)

        def _verify_bduss(self):
            bduss = self.bduss_input.text().strip()
            if not bduss:
                self.bduss_status.setText(tr("err_empty"))
                self.bduss_status.setStyleSheet("font-size: 11px; color: #e53935;")
                return
            self.bduss_status.setText(tr("err_checking"))
            self.bduss_status.setStyleSheet("font-size: 11px;")
            self.bduss_verify_btn.setEnabled(False)
            QApplication.processEvents()
            info = verify_login(bduss)
            self.bduss_verify_btn.setEnabled(True)
            if info:
                vip_names = ["Free", "VIP", "SVIP"]
                vip_str = vip_names[info["vip"]] if info["vip"] < 3 else f"VIP{info['vip']}"
                self.bduss_status.setText(f"✓ {info['name']} ({vip_str})")
                self.bduss_status.setStyleSheet("font-size: 11px; color: #2e7d32;")
            else:
                self.bduss_status.setText(tr("err_invalid"))
                self.bduss_status.setStyleSheet("font-size: 11px; color: #e53935;")

        def _get_speed_val(self, spin, unit):
            return spin.value() * (unit.currentData() or 1024)

        def _on_save(self):
            global _lang, SPEED_LIMIT, SPEED_LIMIT_BAIDU, SPEED_LIMIT_BILI, SPEED_LIMIT_QUARK
            global MAX_CONCURRENT, PARALLEL_CONN
            cfg = load_config()
            # 일반 탭
            cfg["download_dir"] = self.dl_dir_input.text()
            new_lang = self.lang_combo.currentData()
            lang_changed = (new_lang != _lang)
            cfg["language"] = new_lang
            _lang = new_lang
            conc_val = self.conc_spin.value()
            cfg["max_concurrent"] = conc_val
            MAX_CONCURRENT = conc_val
            pconn_val = self.pconn_spin.value()
            cfg["parallel_conn"] = pconn_val
            PARALLEL_CONN = pconn_val

            # Baidu 탭
            bduss = self.bduss_input.text().strip()
            if bduss:
                cfg["bduss"] = bduss
            cfg["auto_login"] = self.auto_login_cb.isChecked()
            baidu_enabled = self.speed_check_baidu.isChecked()
            cfg["speed_limit_baidu_enabled"] = baidu_enabled
            cfg["speed_limit_enabled"] = baidu_enabled  # legacy compat
            baidu_speed = self._get_speed_val(self.speed_spin_baidu, self.speed_unit_baidu)
            cfg["speed_limit_baidu"] = baidu_speed
            cfg["speed_limit"] = baidu_speed  # legacy compat
            SPEED_LIMIT_BAIDU = baidu_speed if baidu_enabled else 0
            SPEED_LIMIT = SPEED_LIMIT_BAIDU

            # Bilibili 탭
            sessdata = self.sessdata_input.text().strip()
            cfg["bili_sessdata"] = sessdata
            bili_enabled = self.speed_check_bili.isChecked()
            cfg["speed_limit_bili_enabled"] = bili_enabled
            bili_speed = self._get_speed_val(self.speed_spin_bili, self.speed_unit_bili)
            cfg["speed_limit_bili"] = bili_speed
            SPEED_LIMIT_BILI = bili_speed if bili_enabled else 0

            # Quark 탭
            qcookie = self.quark_cookie_input.text().strip()
            cfg["quark_cookie"] = qcookie
            quark_enabled = self.speed_check_quark.isChecked()
            cfg["speed_limit_quark_enabled"] = quark_enabled
            quark_speed = self._get_speed_val(self.speed_spin_quark, self.speed_unit_quark)
            cfg["speed_limit_quark"] = quark_speed
            SPEED_LIMIT_QUARK = quark_speed if quark_enabled else 0

            save_config(cfg)
            # Baidu 로그인 상태 갱신
            if bduss and self._parent_win:
                if not self._parent_win.bduss and bduss:
                    self._parent_win._try_auto_login()
            if lang_changed and self._parent_win:
                self._parent_win._retranslate()
            self.accept()

    # ── Quark 다이얼로그 ────────────────────────────────────────────────────

    class QuarkDialog(QDialog):
        """Quark Pan 공유 링크 다운로드 다이얼로그"""
        files_selected = Signal(list, str)  # [(file_info, ...), cookie_str]

        def __init__(self, parent=None, initial_url=""):
            super().__init__(parent)
            self.setWindowTitle(tr("quark_title"))
            self.setMinimumWidth(550)
            self._parent_win = parent
            self._files = []
            cfg = load_config()

            layout = QVBoxLayout(self)

            # URL 입력
            url_row = QHBoxLayout()
            url_row.addWidget(QLabel("URL:"))
            self.url_input = QLineEdit()
            self.url_input.setPlaceholderText("https://pan.quark.cn/s/...")
            if initial_url:
                self.url_input.setText(initial_url.split('\n')[0].strip())
            url_row.addWidget(self.url_input)
            layout.addLayout(url_row)

            # 추출코드
            code_row = QHBoxLayout()
            code_row.addWidget(QLabel(tr("quark_passcode")))
            self.code_input = QLineEdit()
            self.code_input.setPlaceholderText(tr("share_code_ph"))
            self.code_input.setMaxLength(8)
            code_row.addWidget(self.code_input)
            layout.addLayout(code_row)

            # Cookie 입력
            cookie_row = QHBoxLayout()
            cookie_row.addWidget(QLabel(tr("quark_cookie")))
            self.cookie_input = QLineEdit()
            self.cookie_input.setPlaceholderText(tr("quark_cookie_hint"))
            self.cookie_input.setEchoMode(QLineEdit.EchoMode.Password)
            saved_cookie = cfg.get("quark_cookie", "")
            if saved_cookie:
                self.cookie_input.setText(saved_cookie)
            cookie_row.addWidget(self.cookie_input)
            layout.addLayout(cookie_row)

            # 분석 버튼
            self.analyze_btn = QPushButton(tr("bili_analyze"))
            self.analyze_btn.clicked.connect(self._analyze)
            layout.addWidget(self.analyze_btn)

            # 상태 레이블
            self.status_label = QLabel("")
            self.status_label.setWordWrap(True)
            layout.addWidget(self.status_label)

            # 파일 목록 트리
            self.file_tree = QTreeWidget()
            self.file_tree.setHeaderLabels([tr("name"), tr("size")])
            self.file_tree.setRootIsDecorated(False)
            self.file_tree.setSelectionMode(QTreeWidget.SelectionMode.ExtendedSelection)
            h = self.file_tree.header()
            h.setStretchLastSection(True)
            h.resizeSection(1, 100)
            layout.addWidget(self.file_tree)

            # 버튼 행
            btn_row = QHBoxLayout()
            btn_row.addStretch()
            self.dl_btn = QPushButton(tr("download"))
            self.dl_btn.setEnabled(False)
            self.dl_btn.clicked.connect(self._on_download)
            btn_row.addWidget(self.dl_btn)
            cancel_btn = QPushButton(tr("cancel"))
            cancel_btn.clicked.connect(self.reject)
            btn_row.addWidget(cancel_btn)
            layout.addLayout(btn_row)

            if initial_url and saved_cookie:
                # 자동 분석
                from PySide6.QtCore import QTimer
                QTimer.singleShot(200, self._analyze)

        def _analyze(self):
            url = self.url_input.text().strip()
            cookie = self.cookie_input.text().strip()
            if not cookie:
                self.status_label.setText(tr("quark_need_cookie"))
                return
            if not url:
                return
            # Cookie 저장
            cfg = load_config()
            cfg["quark_cookie"] = cookie
            save_config(cfg)

            self.analyze_btn.setEnabled(False)
            self.status_label.setText(tr("bili_analyzing"))
            self.file_tree.clear()

            passcode = self.code_input.text().strip()
            self._worker = QuarkShareWorker(url, cookie, passcode)
            self._worker.files_loaded.connect(self._on_files_loaded)
            self._worker.error.connect(self._on_error)
            self._worker.start()

        def _on_files_loaded(self, files):
            self.analyze_btn.setEnabled(True)
            self._files = files
            self.file_tree.clear()
            for f in files:
                fname = f.get("file_name", f.get("filename", "?"))
                fsize = f.get("size", 0)
                is_dir = f.get("file_type", 0) == 0 or f.get("dir", False)
                tw = QTreeWidgetItem()
                icon = "📁" if is_dir else "📄"
                tw.setText(0, f"{icon} {fname}")
                tw.setText(1, format_size(fsize) if not is_dir else "-")
                tw.setData(0, Qt.ItemDataRole.UserRole, f)
                self.file_tree.addTopLevelItem(tw)
            self.status_label.setText(tr("quark_select_files", n=len(files)))
            if files:
                self.dl_btn.setEnabled(True)
                # 전체 선택
                self.file_tree.selectAll()

        def _on_error(self, msg):
            self.analyze_btn.setEnabled(True)
            self.status_label.setText(f"Error: {msg}")

        def _on_download(self):
            selected = self.file_tree.selectedItems()
            if not selected:
                return
            files = []
            for item in selected:
                f = item.data(0, Qt.ItemDataRole.UserRole)
                if f:
                    files.append(f)
            cookie = self.cookie_input.text().strip()
            self.files_selected.emit(files, cookie)
            self.accept()

    # ── 체크박스 중앙정렬 Delegate ──────────────────────────────────────────

    class CenterCheckDelegate(QStyledItemDelegate):
        """column 0 체크박스를 셀 중앙에 그리는 delegate"""
        def initStyleOption(self, option, index):
            super().initStyleOption(option, index)
            if index.column() == 0:
                # 텍스트 제거, 체크 인디케이터만 표시
                option.text = ""
                option.features |= option.ViewItemFeature.HasCheckIndicator

        def paint(self, painter, option, index):
            if index.column() == 0:
                # 체크박스를 셀 중앙에 배치
                from PySide6.QtWidgets import QStyle, QStyleOptionButton, QApplication
                cb_opt = QStyleOptionButton()
                cb_rect = QApplication.style().subElementRect(
                    QStyle.SubElement.SE_CheckBoxIndicator, cb_opt)
                cb_opt.rect = option.rect
                cb_opt.rect.setLeft(
                    option.rect.x() + (option.rect.width() - cb_rect.width()) // 2)
                cb_opt.rect.setWidth(cb_rect.width())
                check_val = index.data(Qt.ItemDataRole.CheckStateRole)
                if check_val == Qt.CheckState.Checked or check_val == 2:
                    cb_opt.state |= QStyle.StateFlag.State_On
                else:
                    cb_opt.state |= QStyle.StateFlag.State_Off
                cb_opt.state |= QStyle.StateFlag.State_Enabled
                # 선택 배경 그리기
                if option.state & QStyle.StateFlag.State_Selected:
                    painter.fillRect(option.rect, option.palette.highlight())
                QApplication.style().drawControl(
                    QStyle.ControlElement.CE_CheckBox, cb_opt, painter)
            else:
                super().paint(painter, option, index)

    # ── 체크박스 헤더뷰 ─────────────────────────────────────────────────────

    class CheckBoxHeader(QHeaderView):
        """column 0에 체크박스를 그려주는 커스텀 헤더"""
        select_all_clicked = Signal(bool)

        def __init__(self, orientation, parent=None):
            super().__init__(orientation, parent)
            self._checked = False
            self.setSectionsClickable(True)

        def mousePressEvent(self, event):
            idx = self.logicalIndexAt(event.pos())
            if idx == 0:
                self._checked = not self._checked
                self.select_all_clicked.emit(self._checked)
                self.viewport().update()
            else:
                super().mousePressEvent(event)

        def set_checked(self, checked):
            self._checked = checked
            self.viewport().update()

        def paintSection(self, painter, rect, logical_index):
            painter.save()
            super().paintSection(painter, rect, logical_index)
            painter.restore()
            if logical_index == 0:
                from PySide6.QtGui import QPen, QColor, QBrush
                cb_size = 13
                x = rect.x() + (rect.width() - cb_size) // 2
                y = rect.y() + (rect.height() - cb_size) // 2
                painter.save()
                painter.setRenderHint(painter.RenderHint.Antialiasing)
                # 체크박스 외곽선
                painter.setPen(QPen(QColor("#888"), 1.5))
                painter.setBrush(QBrush(QColor("white")))
                painter.drawRoundedRect(x, y, cb_size, cb_size, 2, 2)
                # 체크 표시
                if self._checked:
                    painter.setPen(QPen(QColor("#2196F3"), 2.5))
                    painter.drawLine(x + 3, y + cb_size // 2, x + cb_size // 2 - 1, y + cb_size - 4)
                    painter.drawLine(x + cb_size // 2 - 1, y + cb_size - 4, x + cb_size - 3, y + 3)
                painter.restore()

    # ── 버튼 아이콘 헬퍼 ────────────────────────────────────────────────────

    def _make_icon(icon_type, size=16, color="#333"):
        """QPainter로 아이콘 직접 그리기"""
        from PySide6.QtGui import QPixmap, QPainter, QColor, QPen, QBrush
        from PySide6.QtCore import QPointF, QRectF
        pix = QPixmap(size, size)
        pix.fill(Qt.GlobalColor.transparent)
        p = QPainter(pix)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        c = QColor(color)
        pen = QPen(c, 1.8)
        p.setPen(pen)
        p.setBrush(QBrush(c))
        m = size * 0.2  # margin

        if icon_type == "pause":
            # ⏸ 두 개의 세로 바
            bw = size * 0.18
            p.drawRoundedRect(QRectF(m, m, bw, size - 2*m), 1, 1)
            p.drawRoundedRect(QRectF(size - m - bw, m, bw, size - 2*m), 1, 1)
        elif icon_type == "play":
            # ▶ 삼각형
            from PySide6.QtGui import QPolygonF
            tri = QPolygonF([
                QPointF(m + 1, m),
                QPointF(size - m, size / 2),
                QPointF(m + 1, size - m),
            ])
            p.drawPolygon(tri)
        elif icon_type == "trash":
            # 🗑 쓰레기통
            p.setPen(QPen(c, 1.5))
            p.setBrush(Qt.BrushStyle.NoBrush)
            # 뚜껑
            p.drawLine(QPointF(m, m + 2), QPointF(size - m, m + 2))
            p.drawLine(QPointF(size * 0.38, m), QPointF(size * 0.62, m))
            # 몸통
            p.drawRoundedRect(QRectF(m + 1, m + 3, size - 2*m - 2, size - 2*m - 3), 1, 1)
            # 세로줄
            mid = size / 2
            p.drawLine(QPointF(mid, m + 5), QPointF(mid, size - m - 1))
        elif icon_type == "broom":
            # 빗자루 (체크 + X 조합 = 정리)
            p.setPen(QPen(c, 2.0))
            p.setBrush(Qt.BrushStyle.NoBrush)
            # 체크마크
            p.drawLine(QPointF(m, size * 0.5), QPointF(size * 0.4, size - m))
            p.drawLine(QPointF(size * 0.4, size - m), QPointF(size - m, m))

        p.end()
        return QIcon(pix)

    # ── 앱 아이콘 ─────────────────────────────────────────────────────────────

    def _get_app_icon():
        """app_icon.ico 로드"""
        # PyInstaller frozen → _MEIPASS 또는 exe 디렉토리
        for base in [getattr(sys, '_MEIPASS', ''), _BASE_DIR, os.path.dirname(__file__)]:
            p = os.path.join(base, "app_icon.ico")
            if os.path.exists(p):
                return QIcon(p)
        return QIcon()

    # ── 메인 윈도우 ──────────────────────────────────────────────────────────

    class BaiduDownloaderWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle(f"Baiduyun Downloader v{APP_VERSION}")
            self.setWindowIcon(_get_app_icon())
            self.setMinimumSize(800, 600)
            self.resize(950, 680)

            self.bduss = None
            self.current_path = "/"
            self.current_files = []

            # 다운로드 큐
            self._dl_queue = []        # list of dict
            self._dl_active = []       # 현재 다운로드 중인 entry 목록

            # 업데이트
            self._update_worker = None
            self._update_dl_worker = None

            self._init_ui()
            self._load_queue()

        def _save_queue(self):
            """다운로드 큐 상태를 파일에 저장"""
            data = []
            for e in self._dl_queue:
                if e.get("type") in ("bilibili", "quark"):
                    continue  # Bilibili/Quark entries not resumable
                status = e["status"]
                # Downloading/Paused → Paused로 저장 (재시작 시 이어받기 가능)
                if status in ("Downloading", "Paused"):
                    status = "Paused"
                data.append({
                    "remote_path": e["remote_path"],
                    "output_path": e["output_path"],
                    "filename": e["filename"],
                    "total_size": e["total_size"],
                    "status": status,
                    "retry_count": e.get("retry_count", 0),
                })
            try:
                with open(QUEUE_PATH, "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
            except Exception:
                pass

        def _load_queue(self):
            """저장된 다운로드 큐 복원"""
            if not os.path.exists(QUEUE_PATH):
                return
            try:
                with open(QUEUE_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                return
            for item in data:
                status = item.get("status", "Queued")
                fname = item.get("filename", "")
                total_size = item.get("total_size", 0)

                tw = QTreeWidgetItem()
                tw.setCheckState(0, Qt.CheckState.Unchecked)
                tw.setTextAlignment(0, Qt.AlignmentFlag.AlignCenter)
                tw.setTextAlignment(1, Qt.AlignmentFlag.AlignCenter)
                tw.setText(2, fname)
                tw.setText(3, format_size(total_size))
                tw.setText(4, "")
                tw.setText(5, "")
                tw.setText(6, "")

                # 상태별 표시
                status_key = {
                    "Queued": "queued", "Paused": "paused",
                    "Complete": "complete", "Failed": "failed",
                    "Cancelled": "cancelled",
                }.get(status, "queued")
                tw.setText(7, tr(status_key))
                self.dl_tree.addTopLevelItem(tw)

                pb = QProgressBar()
                pb.setRange(0, 1000)
                pb.setFixedHeight(18)
                pb.setFormat("%p%")

                if status == "Complete":
                    pb.setValue(1000)
                    pb.setStyleSheet(
                        "QProgressBar::chunk { background-color: #4caf50; border-radius: 3px; }")
                elif status in ("Failed", "Cancelled"):
                    pb.setValue(0)
                    pb.setStyleSheet(
                        "QProgressBar::chunk { background-color: #c0392b; border-radius: 3px; }")
                else:
                    # Paused/Queued: 이어받기 진행률 계산
                    output_path = item.get("output_path", "")
                    if total_size > 0 and os.path.exists(output_path):
                        existing = os.path.getsize(output_path)
                        pct = min(existing / total_size, 1.0)
                        pb.setValue(int(pct * 1000))
                    else:
                        pb.setValue(0)
                self.dl_tree.setItemWidget(tw, 4, pb)

                entry = {
                    "remote_path": item.get("remote_path", ""),
                    "output_path": item.get("output_path", ""),
                    "filename": fname,
                    "total_size": total_size,
                    "status": status,
                    "tw": tw,
                    "pb": pb,
                    "retry_count": item.get("retry_count", 0),
                }
                self._dl_queue.append(entry)
            self._update_status_count()

        def closeEvent(self, event):
            """종료 시 트레이 최소화 / 종료 / 취소 선택"""
            if not self._really_quit:
                msg = QMessageBox(self)
                msg.setWindowTitle(tr("tray_or_quit"))
                msg.setText(tr("tray_or_quit_msg"))
                tray_btn = msg.addButton(tr("tray_minimize"), QMessageBox.ButtonRole.AcceptRole)
                tray_btn.setMinimumWidth(120)
                quit_btn = msg.addButton(tr("tray_quit"), QMessageBox.ButtonRole.DestructiveRole)
                quit_btn.setMinimumWidth(80)
                cancel_btn = msg.addButton(tr("cancel"), QMessageBox.ButtonRole.RejectRole)
                cancel_btn.setMinimumWidth(80)
                msg.setDefaultButton(cancel_btn)
                msg.exec()
                clicked = msg.clickedButton()
                if clicked == tray_btn:
                    event.ignore()
                    self.hide()
                    self._tray_icon.show()
                    return
                elif clicked == cancel_btn or clicked is None:
                    event.ignore()
                    return
            # 완전 종료
            self._tray_icon.hide()
            for entry in self._dl_active[:]:
                w = entry.get("worker")
                if w and w.isRunning():
                    w.cancel()
                    w.quit()
                    w.wait(3000)
            self._save_queue()
            super().closeEvent(event)

        def _init_ui(self):
            # ─ 메뉴바 ─
            menubar = self.menuBar()
            menubar.setContextMenuPolicy(Qt.ContextMenuPolicy.PreventContextMenu)

            # 파일 메뉴
            file_menu = menubar.addMenu(tr("menu_file"))
            self.act_refresh = file_menu.addAction(tr("refresh"))
            self.act_refresh.triggered.connect(self._refresh)
            self.act_share = file_menu.addAction(tr("share_link"))
            self.act_share.triggered.connect(self._open_share_dialog)
            self.act_bili = file_menu.addAction(tr("bili_download"))
            self.act_bili.triggered.connect(lambda: self._open_bili_dialog())
            self.act_quark = file_menu.addAction(tr("quark_download"))
            self.act_quark.triggered.connect(lambda: self._open_quark_dialog())
            file_menu.addSeparator()
            self.act_settings = file_menu.addAction(tr("settings"))
            self.act_settings.triggered.connect(self._open_settings)
            file_menu.addSeparator()
            self.act_quit = file_menu.addAction(tr("tray_quit"))
            self.act_quit.triggered.connect(self.close)

            # 도움말 메뉴
            help_menu = menubar.addMenu(tr("menu_help"))
            self.act_update = help_menu.addAction(tr("check_update"))
            self.act_update.triggered.connect(self._check_update)

            # ─ 중앙: 스플리터 (파일목록 / 다운로드큐) ─
            central = QWidget()
            self.setCentralWidget(central)
            main_layout = QVBoxLayout(central)
            main_layout.setContentsMargins(8, 4, 8, 2)
            main_layout.setSpacing(4)

            # 상단: 경로 + 용량 + 유저 정보
            top_bar = QHBoxLayout()
            self.path_label = QLabel("Baiduyun: /")
            self.path_label.setObjectName("pathLabel")
            top_bar.addWidget(self.path_label)
            top_bar.addStretch()
            self.quota_label = QLabel("")
            self.quota_label.setStyleSheet(
                "font-size: 11px; color: #888; margin-right: 8px; "
                "padding: 1px 6px; border: 1px solid #ccc; border-radius: 3px;")
            self.quota_label.setVisible(False)
            top_bar.addWidget(self.quota_label)
            self.user_label = QLabel(tr("not_logged_in"))
            self.user_label.setStyleSheet("font-size: 12px;")
            top_bar.addWidget(self.user_label)
            self.logout_btn = QPushButton(tr("logout"))
            self.logout_btn.setStyleSheet(
                "QPushButton { border: 1px solid palette(mid); border-radius: 3px; "
                "padding: 2px 6px; font-size: 11px; min-height: 18px; } "
                "QPushButton:hover { background: palette(midlight); }")
            self.logout_btn.clicked.connect(self._logout)
            top_bar.addWidget(self.logout_btn)
            main_layout.addLayout(top_bar)

            splitter = QSplitter(Qt.Orientation.Vertical)

            # ── 상단: 파일 브라우저 ──
            self.tree = QTreeWidget()
            self.tree.setHeaderLabels([tr("name"), tr("size"), tr("modified")])
            self.tree.setRootIsDecorated(False)
            self.tree.setAlternatingRowColors(True)
            self.tree.setSelectionMode(QTreeWidget.SelectionMode.ExtendedSelection)
            header = self.tree.header()
            header.setStretchLastSection(True)
            header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
            header.resizeSection(1, 90)
            header.resizeSection(2, 120)
            self.tree.itemDoubleClicked.connect(self._on_item_double_clicked)
            self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            self.tree.customContextMenuRequested.connect(self._file_context_menu)
            splitter.addWidget(self.tree)

            # ── 하단: 다운로드 큐 ──
            dl_widget = QWidget()
            dl_lay = QVBoxLayout(dl_widget)
            dl_lay.setContentsMargins(0, 4, 0, 0)
            dl_lay.setSpacing(2)

            q_header = QHBoxLayout()
            self.q_title = QLabel(tr("downloads"))
            self.q_title.setObjectName("dlNameLabel")
            q_header.addWidget(self.q_title)
            q_header.addStretch()

            _q_btn_base = (
                "QPushButton {{ border: 1px solid {bd}; border-radius: 4px; "
                "padding: 3px 8px; font-size: 11px; color: {fg}; background: {bg}; }} "
                "QPushButton:hover {{ background: {hover}; }} "
                "QPushButton:pressed {{ background: {press}; }}")
            _btn_pause = _q_btn_base.format(
                bd="#b0b0b0", fg="#555", bg="#f5f5f5", hover="#e8e8e8", press="#ddd")
            _btn_resume = _q_btn_base.format(
                bd="#81c784", fg="#2e7d32", bg="#e8f5e9", hover="#c8e6c9", press="#a5d6a7")
            _btn_delete = _q_btn_base.format(
                bd="#ef9a9a", fg="#c62828", bg="#ffebee", hover="#ffcdd2", press="#ef9a9a")
            _btn_clear = _q_btn_base.format(
                bd="#90caf9", fg="#1565c0", bg="#e3f2fd", hover="#bbdefb", press="#90caf9")

            self.pause_sel_btn = QPushButton(f"  {tr('pause_selected')}")
            self.pause_sel_btn.setIcon(_make_icon("pause", color="#555"))
            self.pause_sel_btn.setIconSize(QSize(12, 12))
            self.pause_sel_btn.setStyleSheet(_btn_pause)
            self.pause_sel_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            self.pause_sel_btn.clicked.connect(self._pause_selected)
            q_header.addWidget(self.pause_sel_btn)

            self.resume_sel_btn = QPushButton(f"  {tr('resume_selected')}")
            self.resume_sel_btn.setIcon(_make_icon("play", color="#2e7d32"))
            self.resume_sel_btn.setIconSize(QSize(12, 12))
            self.resume_sel_btn.setStyleSheet(_btn_resume)
            self.resume_sel_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            self.resume_sel_btn.clicked.connect(self._resume_selected)
            q_header.addWidget(self.resume_sel_btn)

            self.del_sel_btn = QPushButton(f"  {tr('delete_selected')}")
            self.del_sel_btn.setIcon(_make_icon("trash", color="#c62828"))
            self.del_sel_btn.setIconSize(QSize(12, 12))
            self.del_sel_btn.setStyleSheet(_btn_delete)
            self.del_sel_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            self.del_sel_btn.clicked.connect(self._delete_selected)
            q_header.addWidget(self.del_sel_btn)

            self.clear_btn = QPushButton(f"  {tr('clear_done')}")
            self.clear_btn.setIcon(_make_icon("broom", color="#1565c0"))
            self.clear_btn.setIconSize(QSize(12, 12))
            self.clear_btn.setStyleSheet(_btn_clear)
            self.clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            self.clear_btn.clicked.connect(self._clear_completed)
            q_header.addWidget(self.clear_btn)
            dl_lay.addLayout(q_header)

            self.dl_tree = QTreeWidget()
            # column 0 체크박스 중앙정렬
            self.dl_tree.setItemDelegateForColumn(0, CenterCheckDelegate(self.dl_tree))
            # 커스텀 헤더 (column 0에 체크박스 표시)
            dl_h = CheckBoxHeader(Qt.Orientation.Horizontal, self.dl_tree)
            self.dl_tree.setHeader(dl_h)
            self.dl_tree.setHeaderLabels([
                "", "#", tr("name"), tr("size"), tr("progress"),
                tr("speed"), tr("eta"), tr("status")])
            self.dl_tree.setRootIsDecorated(False)
            self.dl_tree.setAlternatingRowColors(True)
            self.dl_tree.setSelectionMode(QTreeWidget.SelectionMode.ExtendedSelection)
            dl_h.setStretchLastSection(True)
            dl_h.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
            dl_h.resizeSection(0, 30)
            dl_h.resizeSection(1, 30)
            dl_h.resizeSection(3, 130)
            dl_h.resizeSection(4, 140)
            dl_h.resizeSection(5, 80)
            dl_h.resizeSection(6, 70)
            dl_h.resizeSection(7, 80)
            # 헤더 체크박스 클릭 → 전체선택/해제 토글
            self._select_all_state = False
            dl_h.select_all_clicked.connect(self._on_dl_header_toggled)
            self.dl_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            self.dl_tree.customContextMenuRequested.connect(self._queue_context_menu)
            dl_lay.addWidget(self.dl_tree)

            splitter.addWidget(dl_widget)
            splitter.setStretchFactor(0, 3)
            splitter.setStretchFactor(1, 2)
            main_layout.addWidget(splitter)

            # ─ 상태바 ─
            self.status = QStatusBar()
            self.setStatusBar(self.status)
            self.status.showMessage(tr("ready"))

            # ─ 시스템 트레이 ─
            self._tray_icon = QSystemTrayIcon(self)
            self._tray_icon.setIcon(_get_app_icon())
            self._tray_icon.setToolTip(f"Baiduyun Downloader v{APP_VERSION}")
            tray_menu = QMenu()
            self._tray_status_act = tray_menu.addAction(tr("tray_idle"))
            self._tray_status_act.setEnabled(False)
            tray_menu.addSeparator()
            tray_show_act = tray_menu.addAction(tr("tray_show"))
            tray_show_act.triggered.connect(self._tray_restore)
            tray_exit_act = tray_menu.addAction(tr("tray_exit"))
            tray_exit_act.triggered.connect(self._tray_quit)
            self._tray_icon.setContextMenu(tray_menu)
            self._tray_icon.activated.connect(self._on_tray_activated)
            self._really_quit = False

        def _tray_restore(self):
            self.showNormal()
            self.activateWindow()

        def _tray_quit(self):
            self._really_quit = True
            self.close()

        def _on_tray_activated(self, reason):
            if reason == QSystemTrayIcon.ActivationReason.Trigger:
                self._tray_restore()

        def _update_tray_status(self):
            active = [e for e in self._dl_queue if e["status"] == "Downloading"]
            if active:
                total_dl = sum(e.get("_downloaded", 0) for e in active)
                total_sz = sum(e.get("total_size", 0) for e in active)
                total_spd = sum(e.get("_speed", 0) for e in active)
                pct = int(total_dl * 100 / total_sz) if total_sz > 0 else 0
                spd_str = f"{format_size(int(total_spd))}/s"
                status_text = f"{tr('tray_downloading', n=len(active), pct=pct)}  {spd_str}"
                tip = f"Baiduyun Downloader\n{status_text}"
            else:
                queued = sum(1 for e in self._dl_queue if e["status"] in ("Queued", "Paused"))
                if queued > 0:
                    status_text = tr("tray_idle")
                else:
                    status_text = tr("tray_idle")
                tip = f"Baiduyun Downloader v{APP_VERSION}"
            self._tray_icon.setToolTip(tip)
            self._tray_status_act.setText(status_text)

        # ── 로그인 ───────────────────────────────────────────────────────────

        def set_login(self, bduss, info):
            self.bduss = bduss
            vip_names = ["Free", "VIP", "SVIP"]
            vip_str = vip_names[info["vip"]] if info["vip"] < 3 else f"VIP{info['vip']}"
            self.user_label.setText(f"  {info['name']} ({vip_str})  ")
            self.status.showMessage(tr("login_ok"))
            self._load_files("/")
            self._refresh_quota()
            # 시작 시 자동 업데이트 체크 (조용히)
            self._check_update(silent=True)

        def _try_auto_login(self):
            """config에서 BDUSS 읽어 비동기 로그인 시도"""
            cfg = load_config()
            bduss = cfg.get("bduss")
            if not bduss:
                self.user_label.setText(tr("not_logged_in"))
                self.status.showMessage(tr("ready"))
                return
            self.status.showMessage(tr("err_checking"))
            self._auto_login_worker = VerifyLoginWorker(bduss)
            def _on_verified(info):
                if info:
                    self.set_login(bduss, info)
                else:
                    self.user_label.setText(tr("not_logged_in"))
                    self.status.showMessage(tr("err_invalid"))
            self._auto_login_worker.finished.connect(_on_verified)
            self._auto_login_worker.start()

        def _refresh_quota(self):
            """클라우드 용량 비동기 조회"""
            if not self.bduss:
                return
            self._quota_worker = QuotaWorker(self.bduss)
            self._quota_worker.quota_loaded.connect(self._on_quota_loaded)
            self._quota_worker.start()

        def _on_quota_loaded(self, used, total):
            if used is not None and total is not None:
                self.quota_label.setText(f"  {format_size(used)} / {format_size(total)}  ")
                self.quota_label.setVisible(True)
            else:
                self.quota_label.setText("")
                self.quota_label.setVisible(False)

        # ── 파일 목록 ────────────────────────────────────────────────────────

        def _load_files(self, path):
            if not self.bduss:
                return
            self.current_path = path
            self.path_label.setText(f"Baiduyun: {path}")
            self.status.showMessage(tr("loading"))
            self.tree.clear()
            self._list_worker = ListFilesWorker(self.bduss, path)
            self._list_worker.finished.connect(self._on_files_loaded)
            self._list_worker.start()

        def _on_files_loaded(self, files):
            self.current_files = files
            self.tree.clear()

            # 상위 폴더 항목 (루트가 아니면)
            if self.current_path != "/":
                parent = os.path.dirname(self.current_path)
                up_item = QTreeWidgetItem()
                up_item.setText(0, "📁 ..")
                up_item.setText(1, "")
                up_item.setText(2, "")
                up_item.setData(0, Qt.ItemDataRole.UserRole,
                                {"isdir": 1, "path": parent if parent else "/"})
                self.tree.addTopLevelItem(up_item)

            for f in files:
                is_dir = f.get("isdir", 0) == 1
                name = f.get("server_filename", os.path.basename(f.get("path", "?")))
                size = f.get("size", 0)
                mtime = time.strftime("%Y-%m-%d %H:%M",
                            time.localtime(f.get("server_mtime", 0)))
                item = QTreeWidgetItem()
                icon = "📁" if is_dir else "📄"
                item.setText(0, f"{icon} {name}")
                item.setText(1, "-" if is_dir else format_size(size))
                item.setText(2, mtime)
                item.setData(0, Qt.ItemDataRole.UserRole, f)
                self.tree.addTopLevelItem(item)
            self.status.showMessage(tr("items", n=len(files)))

        def _on_item_double_clicked(self, item, column):
            f = item.data(0, Qt.ItemDataRole.UserRole)
            if not f:
                return
            if f.get("isdir") == 1:
                self._load_files(f.get("path", "/"))
            else:
                self._enqueue([f])

        def _file_context_menu(self, pos):
            """파일 브라우저 우클릭 메뉴"""
            selected = self.tree.selectedItems()
            files = []
            for sel in selected:
                f = sel.data(0, Qt.ItemDataRole.UserRole)
                if f and f.get("isdir") != 1:
                    files.append(f)
            if not files:
                return
            menu = QMenu(self)
            dl_act = menu.addAction(tr("download_n", n=len(files)) if len(files) > 1
                                    else tr("download"))
            action = menu.exec(self.tree.viewport().mapToGlobal(pos))
            if action == dl_act:
                self._enqueue(files)

        def _refresh(self):
            self._load_files(self.current_path)

        # ── 다운로드 큐 ──────────────────────────────────────────────────────

        def _enqueue(self, file_list):
            """파일 목록을 다운로드 큐에 추가"""
            out_dir = get_download_dir()
            added = False
            for fi in file_list:
                remote_path = fi.get("path")
                total_size = fi.get("size", 0)
                fname = fi.get("server_filename", os.path.basename(remote_path))
                output_path = os.path.join(out_dir, fname)

                # 중복 체크: 같은 remote_path가 이미 큐에 있으면 스킵
                dup = None
                for e in self._dl_queue:
                    if (e["remote_path"] == remote_path
                            and e["status"] not in ("Complete", "Cancelled")
                            and not e.get("_removing")):
                        dup = e
                        break
                if dup:
                    self._flash_item_warn(dup["tw"])
                    continue

                # 큐 트리 행 추가
                tw = QTreeWidgetItem()
                tw.setCheckState(0, Qt.CheckState.Unchecked)
                tw.setTextAlignment(0, Qt.AlignmentFlag.AlignCenter)
                tw.setText(2, fname)
                tw.setText(3, format_size(total_size))
                tw.setText(4, "")
                tw.setText(5, "")
                tw.setText(6, "")
                tw.setText(7, tr("queued"))
                self.dl_tree.addTopLevelItem(tw)

                # 프로그레스바 위젯
                pb = QProgressBar()
                pb.setRange(0, 1000)
                pb.setValue(0)
                pb.setFormat("%p%")
                pb.setFixedHeight(18)
                self.dl_tree.setItemWidget(tw, 4, pb)

                entry = {
                    "remote_path": remote_path,
                    "output_path": output_path,
                    "filename": fname,
                    "total_size": total_size,
                    "status": "Queued",
                    "tw": tw,
                    "pb": pb,
                    "retry_count": 0,
                }
                self._dl_queue.append(entry)
                self._flash_item(tw)
                added = True

            self._update_status_count()
            if added:
                self._save_queue()
                self._process_queue()

        def _flash_item(self, tw):
            """행 추가 시 하이라이트 플래시 효과 (파란색)"""
            from PySide6.QtGui import QColor, QBrush
            from PySide6.QtCore import QTimer
            highlight = QColor("#3d6fa5") if _is_windows_dark_mode() else QColor("#cce5ff")
            cols = tw.columnCount()
            for c in range(cols):
                tw.setBackground(c, QBrush(highlight))
            def _fade1():
                mid = QColor("#354d6b") if _is_windows_dark_mode() else QColor("#e0efff")
                for c in range(cols):
                    tw.setBackground(c, QBrush(mid))
            def _fade2():
                for c in range(cols):
                    tw.setData(c, Qt.ItemDataRole.BackgroundRole, None)
            QTimer.singleShot(400, _fade1)
            QTimer.singleShot(800, _fade2)

        def _flash_item_warn(self, tw):
            """이미 큐에 있는 파일 경고 플래시 효과 (주황색) + 상태 텍스트"""
            from PySide6.QtGui import QColor, QBrush
            from PySide6.QtCore import QTimer
            highlight = QColor("#8a6d3b") if _is_windows_dark_mode() else QColor("#fff3cd")
            cols = tw.columnCount()
            old_status = tw.text(7)
            for c in range(cols):
                tw.setBackground(c, QBrush(highlight))
            tw.setText(7, tr("already_in_queue"))
            # 스크롤하여 보이게
            self.dl_tree.scrollToItem(tw)
            def _fade1():
                mid = QColor("#6b5a36") if _is_windows_dark_mode() else QColor("#ffe8a1")
                for c in range(cols):
                    tw.setBackground(c, QBrush(mid))
            def _fade2():
                for c in range(cols):
                    tw.setData(c, Qt.ItemDataRole.BackgroundRole, None)
                tw.setText(7, old_status)
            QTimer.singleShot(500, _fade1)
            QTimer.singleShot(1200, _fade2)

        def _process_queue(self):
            """큐에서 대기 항목을 찾아 동시 다운로드 수만큼 시작"""
            active_count = len(self._dl_active)
            max_c = MAX_CONCURRENT
            for entry in self._dl_queue:
                if active_count >= max_c:
                    break
                if entry["status"] == "Queued":
                    if entry.get("type") == "quark":
                        self._start_quark_entry(entry)
                    else:
                        self._start_entry(entry)
                    active_count += 1

        def _start_entry(self, entry):
            entry["status"] = "Downloading"
            entry["tw"].setText(7, tr("downloading"))
            self._dl_active.append(entry)

            worker = DownloadWorker(
                self.bduss, entry["remote_path"],
                entry["output_path"], entry["total_size"],
            )
            entry["worker"] = worker
            worker.progress.connect(lambda d, t, s, e=entry: self._on_q_progress_entry(e, d, t, s))
            worker.finished.connect(lambda ok, e=entry: self._on_q_finished_entry(e, ok))
            worker.start()
            self.status.showMessage(f"Downloading: {entry['filename']}")

        def _on_q_progress_entry(self, entry, downloaded, total, speed):
            pct = downloaded / total if total else 0
            entry["pb"].setValue(int(pct * 1000))
            entry["_downloaded"] = downloaded
            entry["_speed"] = speed

            # 사이즈 컬럼에 진행량 표시
            entry["tw"].setText(3, f"{format_size(downloaded)} / {format_size(total)}")

            speed_str = f"{format_size(int(speed))}/s" if speed > 0 else ""
            entry["tw"].setText(5, speed_str)

            if speed > 0:
                secs = (total - downloaded) / speed
                if secs > 604800:  # 7일 이상이면 무한 표시
                    eta = "∞"
                elif secs < 60:
                    eta = f"{int(secs)}s"
                elif secs < 3600:
                    m, s = divmod(int(secs), 60)
                    eta = f"{m}m {s:02d}s"
                elif secs < 86400:
                    h, rem = divmod(int(secs), 3600)
                    m = rem // 60
                    eta = f"{h}h {m:02d}m"
                else:
                    d, rem = divmod(int(secs), 86400)
                    h = rem // 3600
                    eta = f"{d}d {h:02d}h"
                entry["tw"].setText(6, eta)
            else:
                entry["tw"].setText(6, "∞")

            # 상태바: 활성 다운로드 수 + 현재 파일 정보
            active = len(self._dl_active)
            self.status.showMessage(
                f"[{active}/{MAX_CONCURRENT}] {entry['filename']}  |  "
                f"{format_size(downloaded)}/{format_size(total)}  |  {speed_str}"
            )
            self._update_tray_status()

        def _on_q_finished_entry(self, entry, ok):
            # worker 정리
            entry.pop("worker", None)
            if entry in self._dl_active:
                self._dl_active.remove(entry)

            if ok:
                entry["status"] = "Complete"
                entry["tw"].setText(3, format_size(entry["total_size"]))
                entry["tw"].setText(7, tr("complete"))
                entry["tw"].setText(5, "")
                entry["tw"].setText(6, "")
                entry["pb"].setValue(1000)
                entry["pb"].setStyleSheet(
                    "QProgressBar::chunk { background-color: #4caf50; border-radius: 3px; }"
                )
            else:
                if entry["status"] == "Cancelled":
                    entry["tw"].setText(7, tr("cancelled"))
                elif entry.get("retry_count", 0) < 3:
                    entry["retry_count"] = entry.get("retry_count", 0) + 1
                    n = entry["retry_count"]
                    entry["status"] = "Queued"
                    entry["tw"].setText(7, tr("retrying", n=n))
                    entry["tw"].setText(5, "")
                    entry["tw"].setText(6, "")
                    entry["pb"].setValue(0)
                    entry["pb"].setStyleSheet("")
                    self._update_status_count()
                    from PySide6.QtCore import QTimer
                    QTimer.singleShot(3000, self._process_queue)
                    return
                else:
                    entry["status"] = "Failed"
                    entry["tw"].setText(7, tr("failed"))
                entry["tw"].setText(5, "")
                entry["tw"].setText(6, "")
                entry["pb"].setStyleSheet(
                    "QProgressBar::chunk { background-color: #c0392b; border-radius: 3px; }"
                )

            self._update_status_count()
            self._save_queue()
            self._process_queue()

        def _cancel_entry(self, entry):
            if entry["status"] in ("Downloading", "Paused") and "worker" in entry:
                entry["status"] = "Cancelled"
                entry["worker"].resume()
                entry["worker"].cancel()
            elif entry["status"] == "Queued":
                entry["status"] = "Cancelled"
                entry["tw"].setText(7, tr("cancelled"))
                self._update_status_count()

        def _remove_entry(self, entry, animate=True):
            if animate:
                self._fade_out_remove([entry])
            else:
                idx = self.dl_tree.indexOfTopLevelItem(entry["tw"])
                if idx >= 0:
                    self.dl_tree.takeTopLevelItem(idx)
                if entry in self._dl_queue:
                    self._dl_queue.remove(entry)
                self._update_status_count()
                self._save_queue()

        def _clear_completed(self):
            to_remove = [e for e in self._dl_queue
                         if e["status"] in ("Complete", "Failed", "Cancelled")]
            if not to_remove:
                return
            self._fade_out_remove(to_remove)

        def _fade_out_remove(self, entries):
            """페이드아웃 후 행 삭제"""
            from PySide6.QtGui import QColor, QBrush
            from PySide6.QtCore import QTimer
            # 삭제 예정 항목 마킹 (다른 코드에서 중복 조작 방지)
            for entry in entries:
                entry["_removing"] = True
            fade1 = QColor("#5a3030") if _is_windows_dark_mode() else QColor("#f8d7da")
            fade2 = QColor("#3a1a1a") if _is_windows_dark_mode() else QColor("#f5c6cb")
            for entry in entries:
                tw = entry["tw"]
                cols = tw.columnCount()
                for c in range(cols):
                    tw.setBackground(c, QBrush(fade1))
            def _step2():
                for entry in entries:
                    tw = entry["tw"]
                    cols = tw.columnCount()
                    for c in range(cols):
                        tw.setBackground(c, QBrush(fade2))
            def _step3():
                for entry in list(entries):  # 복사본 순회
                    idx = self.dl_tree.indexOfTopLevelItem(entry["tw"])
                    if idx >= 0:
                        self.dl_tree.takeTopLevelItem(idx)
                    if entry in self._dl_queue:
                        self._dl_queue.remove(entry)
                self._update_status_count()
                self._save_queue()
            QTimer.singleShot(200, _step2)
            QTimer.singleShot(450, _step3)

        def _pause_entry(self, entry):
            if entry["status"] == "Downloading" and "worker" in entry:
                entry["worker"].pause()
                entry["status"] = "Paused"
                entry["tw"].setText(7, tr("paused"))
            elif entry["status"] == "Queued":
                entry["status"] = "Paused"
                entry["tw"].setText(7, tr("paused"))

        def _resume_entry(self, entry):
            if entry["status"] != "Paused":
                return
            if "worker" in entry:
                # 활성 worker 있음 → resume
                entry["worker"].resume()
                entry["status"] = "Downloading"
                entry["tw"].setText(7, tr("downloading"))
            else:
                # worker 없음 (앱 재시작 등) → Queued로 변경하여 재다운로드
                entry["status"] = "Queued"
                entry["tw"].setText(7, tr("queued"))
                entry["pb"].setValue(0)
                entry["pb"].setStyleSheet("")
                self._process_queue()

        def _pause_selected(self):
            """체크된 항목 일시정지"""
            for entry in self._dl_queue:
                if entry["tw"].checkState(0) != Qt.CheckState.Checked:
                    continue
                if entry["status"] == "Downloading":
                    self._pause_entry(entry)
                elif entry["status"] == "Queued":
                    entry["status"] = "Paused"
                    entry["tw"].setText(7, tr("paused"))

        def _resume_selected(self):
            """체크된 항목 재개"""
            for entry in self._dl_queue:
                if entry["tw"].checkState(0) != Qt.CheckState.Checked:
                    continue
                if entry["status"] == "Paused":
                    self._resume_entry(entry)
            self._process_queue()

        def _delete_selected(self):
            """체크박스가 체크된 항목 삭제"""
            entries_to_delete = []
            for e in self._dl_queue:
                if e["tw"].checkState(0) == Qt.CheckState.Checked:
                    entries_to_delete.append(e)
            if not entries_to_delete:
                return
            for entry in entries_to_delete:
                if entry["status"] in ("Downloading", "Paused") and "worker" in entry:
                    entry["status"] = "Cancelled"
                    entry["worker"].resume()
                    entry["worker"].cancel()
            self._fade_out_remove(entries_to_delete)

        def _on_dl_header_toggled(self, checked):
            """헤더 체크박스 클릭 → 전체선택/해제"""
            self._select_all_state = checked
            state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
            for e in self._dl_queue:
                e["tw"].setCheckState(0, state)

        def _update_row_numbers(self):
            """dl_tree의 # 컬럼(index 1)에 행 번호 표시"""
            for i in range(self.dl_tree.topLevelItemCount()):
                item = self.dl_tree.topLevelItem(i)
                if item:
                    item.setText(1, str(i + 1))
                    item.setTextAlignment(1, Qt.AlignmentFlag.AlignCenter)

        def _update_status_count(self):
            self._update_row_numbers()
            queued = sum(1 for e in self._dl_queue if e["status"] == "Queued")
            active = sum(1 for e in self._dl_queue if e["status"] == "Downloading")
            done = sum(1 for e in self._dl_queue if e["status"] == "Complete")
            total = len(self._dl_queue)
            if total == 0:
                self.status.showMessage(tr("ready"))
            else:
                self.status.showMessage(
                    tr("queue_stat", t=total, a=active, q=queued, d=done)
                )
            self._update_tray_status()

        def _move_entry_to_top(self, entry):
            """대기/일시정지 항목을 Downloading 항목 바로 뒤로 이동 (우선 다운로드)"""
            if entry["status"] not in ("Queued", "Paused"):
                return
            # _dl_queue에서 제거
            if entry in self._dl_queue:
                self._dl_queue.remove(entry)
            # Downloading 항목들 바로 뒤에 삽입
            insert_idx = 0
            for i, e in enumerate(self._dl_queue):
                if e["status"] == "Downloading":
                    insert_idx = i + 1
            self._dl_queue.insert(insert_idx, entry)

            # dl_tree에서도 이동
            tw = entry["tw"]
            tree_idx = self.dl_tree.indexOfTopLevelItem(tw)
            if tree_idx >= 0:
                self.dl_tree.takeTopLevelItem(tree_idx)
            # tree에서도 Downloading 항목 뒤에 삽입
            tree_insert = 0
            for i in range(self.dl_tree.topLevelItemCount()):
                item = self.dl_tree.topLevelItem(i)
                for e in self._dl_queue:
                    if e["tw"] is item and e["status"] == "Downloading":
                        tree_insert = i + 1
                        break
            self.dl_tree.insertTopLevelItem(tree_insert, tw)
            # 프로그레스바 위젯 재부착
            pb = entry.get("pb")
            if pb:
                self.dl_tree.setItemWidget(tw, 4, pb)
            self._update_row_numbers()
            self.dl_tree.scrollToItem(tw)
            self._flash_item(tw)

        def _queue_context_menu(self, pos):
            """다운로드 큐 우클릭 메뉴"""
            tw = self.dl_tree.itemAt(pos)
            if not tw:
                return
            entry = None
            for e in self._dl_queue:
                if e["tw"] is tw:
                    entry = e
                    break
            if not entry:
                return

            menu = QMenu(self)
            st = entry["status"]
            pause_act = None
            resume_act = None
            cancel_act = None
            remove_act = None
            folder_act = None
            priority_act = None

            if st == "Downloading":
                pause_act = menu.addAction(tr("pause"))
                cancel_act = menu.addAction(tr("cancel"))
            elif st == "Paused":
                resume_act = menu.addAction(tr("resume"))
                priority_act = menu.addAction(tr("priority_download"))
                cancel_act = menu.addAction(tr("cancel"))
            elif st == "Queued":
                priority_act = menu.addAction(tr("priority_download"))
                cancel_act = menu.addAction(tr("cancel"))
            if st in ("Complete", "Failed", "Cancelled"):
                remove_act = menu.addAction(tr("remove"))
            if st == "Complete":
                folder_act = menu.addAction(tr("open_folder"))

            action = menu.exec(self.dl_tree.viewport().mapToGlobal(pos))
            if not action:
                return
            if action == pause_act:
                self._pause_entry(entry)
            elif action == resume_act:
                self._resume_entry(entry)
            elif action == priority_act:
                self._move_entry_to_top(entry)
            elif action == cancel_act:
                self._cancel_entry(entry)
            elif action == remove_act:
                self._remove_entry(entry)
            elif action == folder_act:
                import subprocess
                folder = os.path.dirname(entry["output_path"])
                subprocess.Popen(["explorer", folder])

        # ── 공유 링크 ────────────────────────────────────────────────────────

        def _start_share_transfer(self, url, code):
            """공유 링크 클라우드 저장 시작 (다운로드 큐에 로그 행 + 취소 버튼)"""
            self.status.showMessage(tr("processing_share"))

            # 다운로드 큐에 상태 표시 행 추가
            tw = QTreeWidgetItem()
            tw.setText(2, f"🔗 {url[:50]}...")
            tw.setText(3, "-")
            tw.setText(4, "")
            tw.setText(5, "")
            tw.setText(6, "")
            tw.setText(7, tr("processing_share"))
            self.dl_tree.addTopLevelItem(tw)
            self._share_log_tw = tw

            # 취소 버튼 (빨간 X)
            cancel_btn = QPushButton("✕")
            cancel_btn.setFixedSize(22, 22)
            cancel_btn.setStyleSheet(
                "QPushButton { color: white; background: #c0392b; border: none; "
                "border-radius: 11px; font-weight: bold; font-size: 13px; } "
                "QPushButton:hover { background: #e74c3c; }")
            cancel_btn.clicked.connect(self._cancel_share_transfer)
            self.dl_tree.setItemWidget(tw, 0, cancel_btn)

            self._share_worker = ShareTransferWorker(self.bduss, url, code)
            self._share_worker.message.connect(self._on_share_log)
            self._share_worker.finished.connect(self._on_share_finished)
            self._share_worker.start()

        def _cancel_share_transfer(self):
            """공유 링크 처리 취소"""
            if hasattr(self, '_share_worker') and self._share_worker:
                self._share_worker.cancel()
            # 로그 행 제거
            if hasattr(self, '_share_log_tw') and self._share_log_tw:
                idx = self.dl_tree.indexOfTopLevelItem(self._share_log_tw)
                if idx >= 0:
                    self.dl_tree.takeTopLevelItem(idx)
                self._share_log_tw = None
            self.status.showMessage(tr("cancelled"))

        def _on_share_log(self, msg):
            """공유 링크 처리 로그를 다운로드 큐 행에 표시"""
            self.status.showMessage(msg)
            if hasattr(self, '_share_log_tw') and self._share_log_tw:
                self._share_log_tw.setText(7, msg)

        def _open_share_dialog(self, initial_url=""):
            if not self.bduss:
                QMessageBox.warning(self, tr("login_required"), tr("login_first"))
                return
            dlg = ShareDialog(self, initial_url=initial_url)
            if dlg.exec() == QDialog.DialogCode.Accepted:
                url = dlg.url_input.text().strip()
                code = dlg.code_input.text().strip()
                self._start_share_transfer(url, code)

        def _on_share_finished(self, result):
            saved_path, err = result

            # 로그 행 제거
            if hasattr(self, '_share_log_tw') and self._share_log_tw:
                idx = self.dl_tree.indexOfTopLevelItem(self._share_log_tw)
                if idx >= 0:
                    self.dl_tree.takeTopLevelItem(idx)
                self._share_log_tw = None

            if saved_path:
                self.status.showMessage(tr("auto_download"))
                self._load_files("/")
                # 저장된 파일을 API로 조회하여 자동 다운로드 큐 추가
                dirname = os.path.dirname(saved_path)
                basename = os.path.basename(saved_path)
                try:
                    files = list_files(self.bduss, dirname if dirname else "/")
                    matched = [f for f in files
                               if f.get("server_filename") == basename
                               and f.get("isdir", 0) == 0]
                    if matched:
                        self._enqueue(matched)
                    else:
                        self.status.showMessage(f"Saved: {saved_path}")
                except Exception:
                    self.status.showMessage(f"Saved: {saved_path}")
            else:
                self.status.showMessage(tr("failed"))
                QMessageBox.warning(self, tr("failed"),
                    f"{tr('save_failed')}\n\n{err}")

        # ── Bilibili 다운로드 ─────────────────────────────────────────────────

        def _open_bili_dialog(self, initial_url=""):
            dlg = QDialog(self)
            dlg.setWindowTitle(tr("bili_download"))
            dlg.setMinimumWidth(500)
            lay = QVBoxLayout(dlg)

            # URL 입력
            url_row = QHBoxLayout()
            url_label = QLabel("URL:")
            self._bili_url = QLineEdit()
            if initial_url:
                self._bili_url.setText(initial_url)
            self._bili_url.setPlaceholderText("https://www.bilibili.com/video/BVxxxxxxxx")
            url_row.addWidget(url_label)
            url_row.addWidget(self._bili_url)
            lay.addLayout(url_row)

            # SESSDATA 입력 (선택사항 — VIP 계정이면 4K 가능)
            sess_row = QHBoxLayout()
            sess_label = QLabel("SESSDATA:")
            self._bili_sessdata = QLineEdit()
            self._bili_sessdata.setPlaceholderText(tr("bili_sessdata_hint"))
            self._bili_sessdata.setEchoMode(QLineEdit.EchoMode.Password)
            cfg = load_config()
            saved_sess = cfg.get("bili_sessdata", "")
            if saved_sess:
                self._bili_sessdata.setText(saved_sess)
            sess_row.addWidget(sess_label)
            sess_row.addWidget(self._bili_sessdata)
            lay.addLayout(sess_row)

            # 분석 버튼
            self._bili_analyze_btn = QPushButton(tr("bili_analyze"))
            self._bili_analyze_btn.clicked.connect(lambda: self._bili_analyze(dlg))
            lay.addWidget(self._bili_analyze_btn)

            # 정보 표시
            self._bili_info = QLabel("")
            self._bili_info.setWordWrap(True)
            self._bili_info.setStyleSheet("font-size: 12px; padding: 4px;")
            lay.addWidget(self._bili_info)

            # 화질 선택
            quality_row = QHBoxLayout()
            quality_row.addWidget(QLabel(tr("bili_quality") + ":"))
            self._bili_quality = QComboBox()
            quality_row.addWidget(self._bili_quality)
            quality_row.addStretch()
            lay.addLayout(quality_row)

            # 다운로드 버튼
            btn_row = QHBoxLayout()
            btn_row.addStretch()
            self._bili_dl_btn = QPushButton(tr("download"))
            self._bili_dl_btn.setEnabled(False)
            self._bili_dl_btn.clicked.connect(lambda: self._bili_start_download(dlg))
            btn_row.addWidget(self._bili_dl_btn)
            cancel_btn = QPushButton(tr("cancel"))
            cancel_btn.clicked.connect(dlg.reject)
            btn_row.addWidget(cancel_btn)
            lay.addLayout(btn_row)

            self._bili_streams = None
            self._bili_video_info = None

            if initial_url and bili_parse_url(initial_url):
                from PySide6.QtCore import QTimer
                QTimer.singleShot(200, lambda: self._bili_analyze(dlg))
            dlg.exec()

        def _bili_analyze(self, dlg):
            url = self._bili_url.text().strip()
            bvid = bili_parse_url(url)
            if not bvid:
                self._bili_info.setText("Invalid Bilibili URL")
                return
            self._bili_analyze_btn.setEnabled(False)
            self._bili_info.setText(tr("bili_analyzing"))
            self._bili_quality.clear()

            class _Worker(QThread):
                done = Signal(object, object)
                def __init__(self, bvid, sessdata=""):
                    super().__init__()
                    self.bvid = bvid
                    self.sessdata = sessdata
                def run(self):
                    s = _bili_session()
                    info = bili_get_video_info(self.bvid, s)
                    streams = None
                    if info:
                        streams = bili_get_streams(
                            self.bvid, info["cid"], s,
                            sessdata=self.sessdata or None)
                    self.done.emit(info, streams)

            sessdata = self._bili_sessdata.text().strip()
            # SESSDATA 저장
            if sessdata:
                cfg = load_config()
                cfg["bili_sessdata"] = sessdata
                save_config(cfg)
            self._bili_worker = _Worker(bvid, sessdata)
            def _on_done(info, streams):
                self._bili_analyze_btn.setEnabled(True)
                if not info:
                    self._bili_info.setText("Failed to get video info")
                    return
                if not streams:
                    self._bili_info.setText("Failed to get streams")
                    return
                self._bili_video_info = info
                self._bili_streams = streams
                dur = info["duration"]
                dur_str = f"{dur // 60}:{dur % 60:02d}"
                has_vip_q = any(v["qn"] >= 112 for v in streams["video"])
                info_html = f"<b>{info['title']}</b><br>Duration: {dur_str}"
                if has_vip_q:
                    info_html += " | <font color='green'>VIP streams available</font>"
                else:
                    info_html += " | Max 1080P (SESSDATA for 4K)"
                self._bili_info.setText(info_html)
                # 화질 목록 — 중복 제거, 최고 화질 우선
                seen = set()
                sorted_vids = sorted(streams["video"], key=lambda x: x["qn"], reverse=True)
                for v in sorted_vids:
                    qn = v["qn"]
                    if qn in seen:
                        continue
                    seen.add(qn)
                    codec = v.get("codec", "")
                    size_str = format_size(v["size"]) if v.get("size") else ""
                    label = f"{_bili_qn_label(qn)} ({v['width']}x{v['height']}) [{codec}]"
                    if size_str:
                        label += f" {size_str}"
                    vip = v.get("need_vip", False)
                    if vip:
                        label += " (VIP)"
                    self._bili_quality.addItem(label, qn)
                if self._bili_quality.count() > 0:
                    self._bili_dl_btn.setEnabled(True)

            self._bili_worker.done.connect(_on_done)
            self._bili_worker.start()

        def _bili_start_download(self, dlg):
            if not self._bili_streams or not self._bili_video_info:
                return
            qn = self._bili_quality.currentData()
            info = self._bili_video_info
            streams = self._bili_streams

            # 선택된 화질의 스트림 찾기 (AVC 우선, 없으면 HEVC/AV1)
            video_stream = None
            candidates = [v for v in streams["video"] if v["qn"] == qn]
            for prefer in ["avc", "hevc", "av1"]:
                for v in candidates:
                    if prefer in v.get("codec", ""):
                        video_stream = v
                        break
                if video_stream:
                    break
            if not video_stream and candidates:
                video_stream = candidates[0]
            if not video_stream:
                QMessageBox.warning(self, "Error", "Video stream not found")
                return
            # 최고 비트레이트 오디오
            audio_stream = max(streams["audio"], key=lambda a: a["bandwidth"]) if streams["audio"] else None
            if not audio_stream:
                QMessageBox.warning(self, "Error", "Audio stream not found")
                return

            # ffmpeg 확인
            if not bili_check_ffmpeg():
                QMessageBox.warning(self, "ffmpeg", tr("bili_no_ffmpeg"))
                return

            # 저장 경로
            cfg = load_config()
            dl_dir = cfg.get("download_dir", os.path.join(os.path.expanduser("~"), "Downloads"))
            safe_title = re.sub(r'[\\/*?:"<>|]', "_", info["title"])[:100]
            qn_label = _bili_qn_label(qn)
            output_name = f"{safe_title}_{qn_label}.mp4"
            output_path = os.path.join(dl_dir, output_name)

            dlg.accept()

            # 큐에 추가
            tw = QTreeWidgetItem()
            tw.setCheckState(0, Qt.CheckState.Unchecked)
            tw.setTextAlignment(0, Qt.AlignmentFlag.AlignCenter)
            tw.setText(2, f"[B] {info['title']}")
            total_size = (video_stream.get("size", 0) or 0) + (audio_stream.get("size", 0) or 0)
            tw.setText(3, format_size(total_size) if total_size else "")
            tw.setText(7, "Downloading")
            self.dl_tree.addTopLevelItem(tw)

            pb = QProgressBar()
            pb.setRange(0, 1000)
            pb.setValue(0)
            self.dl_tree.setItemWidget(tw, 4, pb)

            entry = {
                "type": "bilibili",
                "filename": output_name,
                "remote_path": f"bili:{info['bvid']}",
                "output_path": output_path,
                "total_size": total_size,
                "status": "Downloading",
                "tw": tw,
                "pb": pb,
                "_video_url": video_stream["url"],
                "_audio_url": audio_stream["url"],
                "_referer": f"https://www.bilibili.com/video/{info['bvid']}/",
            }
            self._dl_queue.append(entry)

            # Bilibili 워커 시작
            worker = BiliDownloadWorker(
                video_stream["url"], audio_stream["url"],
                output_path,
                f"https://www.bilibili.com/video/{info['bvid']}/",
            )
            entry["worker"] = worker
            worker.progress.connect(lambda d, t, s, e=entry: self._on_q_progress_entry(e, d, t, s))
            worker.finished.connect(lambda ok, e=entry: self._on_bili_finished(e, ok))
            worker.start()

        def _on_bili_finished(self, entry, ok):
            entry.pop("worker", None)
            if ok:
                entry["status"] = "Complete"
                entry["tw"].setText(7, tr("complete"))
                entry["tw"].setText(5, "")
                entry["tw"].setText(6, "")
                entry["pb"].setValue(1000)
                entry["pb"].setStyleSheet(
                    "QProgressBar::chunk { background-color: #4caf50; border-radius: 3px; }")
            else:
                entry["status"] = "Failed"
                entry["tw"].setText(7, tr("failed"))
                entry["pb"].setStyleSheet(
                    "QProgressBar::chunk { background-color: #c0392b; border-radius: 3px; }")
            self._update_status_count()

        # ── Quark 다운로드 ───────────────────────────────────────────────────

        def _open_quark_dialog(self, initial_url=""):
            dlg = QuarkDialog(self, initial_url=initial_url)
            dlg.files_selected.connect(self._quark_enqueue)
            dlg.exec()

        def _quark_enqueue(self, files, cookie_str):
            """Quark 파일들을 다운로드 큐에 추가"""
            out_dir = get_download_dir()
            for f in files:
                fname = f.get("file_name", f.get("filename", "?"))
                fsize = f.get("size", 0)
                fid = f.get("fid", "")
                fid_token = f.get("share_fid_token", f.get("fid_token", ""))
                pwd_id = f.get("_pwd_id", "")
                stoken = f.get("_stoken", "")
                output_path = os.path.join(out_dir, fname)

                # 중복 체크
                dup = None
                for e in self._dl_queue:
                    if (e.get("remote_path") == f"quark:{fid}"
                            and e["status"] not in ("Complete", "Cancelled")
                            and not e.get("_removing")):
                        dup = e
                        break
                if dup:
                    self._flash_item_warn(dup["tw"])
                    continue

                tw = QTreeWidgetItem()
                tw.setCheckState(0, Qt.CheckState.Unchecked)
                tw.setTextAlignment(0, Qt.AlignmentFlag.AlignCenter)
                tw.setText(2, f"[Q] {fname}")
                tw.setText(3, format_size(fsize))
                tw.setText(7, tr("queued"))
                self.dl_tree.addTopLevelItem(tw)

                pb = QProgressBar()
                pb.setRange(0, 1000)
                pb.setValue(0)
                pb.setFormat("%p%")
                pb.setFixedHeight(18)
                self.dl_tree.setItemWidget(tw, 4, pb)

                entry = {
                    "type": "quark",
                    "remote_path": f"quark:{fid}",
                    "output_path": output_path,
                    "filename": fname,
                    "total_size": fsize,
                    "status": "Queued",
                    "tw": tw,
                    "pb": pb,
                    "_quark_fid": fid,
                    "_quark_fid_token": fid_token,
                    "_quark_pwd_id": pwd_id,
                    "_quark_stoken": stoken,
                    "_quark_cookie": cookie_str,
                }
                self._dl_queue.append(entry)
                self._flash_item(tw)

            self._update_status_count()
            self._save_queue()
            self._process_queue()

        def _start_quark_entry(self, entry):
            """Quark 개별 항목 다운로드 시작"""
            entry["status"] = "Downloading"
            entry["tw"].setText(7, tr("downloading"))
            self._dl_active.append(entry)

            worker = QuarkDownloadWorker(
                entry["_quark_fid"],
                entry["_quark_fid_token"],
                entry["_quark_pwd_id"],
                entry["_quark_stoken"],
                entry["_quark_cookie"],
                entry["output_path"],
                entry["total_size"],
                entry["filename"],
            )
            entry["worker"] = worker
            worker.progress.connect(lambda d, t, s, e=entry: self._on_q_progress_entry(e, d, t, s))
            worker.finished.connect(lambda ok, e=entry: self._on_q_finished_entry(e, ok))
            worker.start()
            self.status.showMessage(f"Downloading: {entry['filename']}")

        # ── 설정 ─────────────────────────────────────────────────────────────

        def _open_settings(self):
            dlg = SettingsDialog(self)
            dlg.exec()

        def _retranslate(self):
            """언어 변경 시 UI 텍스트 갱신"""
            # 메뉴바
            menus = self.menuBar().findChildren(QMenu)
            if len(menus) >= 2:
                menus[0].setTitle(tr("menu_file"))
                menus[1].setTitle(tr("menu_help"))
            self.act_refresh.setText(tr("refresh"))
            self.act_share.setText(tr("share_link"))
            self.act_settings.setText(tr("settings"))
            self.act_update.setText(tr("check_update"))
            self.act_quit.setText(tr("tray_quit"))
            self.act_bili.setText(tr("bili_download"))
            self.act_quark.setText(tr("quark_download"))
            self.logout_btn.setText(tr("logout"))
            self.tree.setHeaderLabels([tr("name"), tr("size"), tr("modified")])
            self.q_title.setText(tr("downloads"))
            self.pause_sel_btn.setText(f"  {tr('pause_selected')}")
            self.resume_sel_btn.setText(f"  {tr('resume_selected')}")
            self.del_sel_btn.setText(f"  {tr('delete_selected')}")
            self.clear_btn.setText(f"  {tr('clear_done')}")
            self.dl_tree.setHeaderLabels([
                "", "#", tr("name"), tr("size"), tr("progress"),
                tr("speed"), tr("eta"), tr("status")])
            self._update_status_count()

        @staticmethod
        def _detect_link_type(text):
            """클립보드 텍스트에서 서비스 유형 감지
            Returns: ("baidu", url) | ("bilibili", url) | ("quark", url) | (None, None)
            """
            url = text.split('\n')[0].strip()
            if "pan.baidu.com" in url or "baidu.com/s/" in url:
                return "baidu", url
            if "bilibili.com/video/" in url or "b23.tv/" in url:
                return "bilibili", url
            if "pan.quark.cn/s/" in url:
                return "quark", url
            return None, None

        def keyPressEvent(self, event):
            """Ctrl+V로 공유링크 붙여넣으면 바로 해당 서비스 다이얼로그 열기"""
            if event.modifiers() == Qt.KeyboardModifier.ControlModifier and event.key() == Qt.Key.Key_V:
                clipboard = QApplication.clipboard()
                text = clipboard.text().strip()
                if text:
                    svc, url = self._detect_link_type(text)
                    if svc == "baidu":
                        self._paste_share_link(text)
                        return
                    elif svc == "bilibili":
                        self._open_bili_dialog(initial_url=url)
                        return
                    elif svc == "quark":
                        self._open_quark_dialog(initial_url=url)
                        return
            super().keyPressEvent(event)

        def _paste_share_link(self, text):
            """Ctrl+V: 공유링크 바로 처리. 추출코드 있으면 바로 추가, 없으면 코드 입력창"""
            if not self.bduss:
                QMessageBox.warning(self, tr("login_required"), tr("login_first"))
                return
            import re
            url = text.split('\n')[0].strip()
            # URL에서 추출코드 자동 파싱
            code = ""
            pwd_m = re.search(r'[?&]pwd=([A-Za-z0-9]+)', text)
            if pwd_m:
                code = pwd_m.group(1)
            if not code:
                code_m = re.search(r'(?:提取码|추출코드|code)[:\s：]+([A-Za-z0-9]+)', text)
                if code_m:
                    code = code_m.group(1)

            if code:
                # 코드가 있으면 바로 처리
                self._start_share_transfer(url, code)
            else:
                # 코드가 없으면 코드 입력 다이얼로그
                self._open_share_dialog(initial_url=url)

        def _logout(self):
            """BDUSS 삭제 후 UI 초기화 (설정에서 재입력 안내)"""
            reply = QMessageBox.question(
                self, tr("logout"), tr("logout_confirm"),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
            cfg = load_config()
            cfg.pop("bduss", None)
            cfg.pop("bduss_enc", None)
            cfg["auto_login"] = False
            save_config(cfg)

            self.bduss = None
            self.tree.clear()
            self.current_path = "/"
            self.path_label.setText("Baiduyun: /")
            self.user_label.setText(tr("not_logged_in"))
            self.quota_label.setVisible(False)
            self.status.showMessage(tr("logged_out"))

        # ── 자동 업데이트 ─────────────────────────────────────────────────────

        def _check_update(self, silent=False):
            """GitHub Releases에서 최신 버전 확인"""
            self._update_silent = silent
            self._update_worker = UpdateCheckWorker()
            self._update_worker.result.connect(self._on_update_checked)
            self._update_worker.start()
            if not silent:
                self.status.showMessage(tr("check_update") + "...")

        def _on_update_checked(self, info):
            if info is None:
                if not self._update_silent:
                    QMessageBox.information(self, tr("check_update"),
                        tr("no_update", v=APP_VERSION))
                return

            new_ver = info["version"]
            dl_url = info.get("download_url")
            reply = QMessageBox.question(
                self, tr("update_available"),
                tr("update_msg", v=new_ver, c=APP_VERSION),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes or not dl_url:
                return

            # 새 exe 다운로드 시작
            import tempfile
            tmp_path = os.path.join(tempfile.gettempdir(), "BaiduyunDownloader_new.exe")
            self.status.showMessage(tr("updating"))
            self._update_dl_worker = UpdateDownloadWorker(dl_url, tmp_path)
            self._update_dl_worker.progress.connect(
                lambda p: self.status.showMessage(f"{tr('updating')} {p}%"))
            self._update_dl_worker.finished.connect(
                lambda ok, path: self._on_update_downloaded(ok, path))
            self._update_dl_worker.start()

        def _on_update_downloaded(self, ok, path):
            if not ok:
                QMessageBox.warning(self, tr("update_available"),
                    tr("update_fail", e=path))
                return

            self.status.showMessage(tr("update_done"))

            # bat 스크립트로 exe 교체 후 재시작 (실행 중인 exe 직접 교체 불가)
            if getattr(sys, 'frozen', False):
                exe_path = os.path.abspath(sys.executable)
                new_path = os.path.abspath(path)
                # 경로 검증: 특수문자 방어
                for p in (exe_path, new_path):
                    if any(c in p for c in ('&', '|', '>', '<', '^', '%')):
                        QMessageBox.warning(self, tr("update_available"),
                            tr("update_fail", e="Path contains special characters"))
                        return
                bat = os.path.join(os.path.dirname(new_path), "_update.bat")
                with open(bat, "w", encoding="utf-8") as f:
                    f.write('@echo off\n')
                    f.write('timeout /t 2 /nobreak >nul\n')
                    f.write(f'move /y "{new_path}" "{exe_path}"\n')
                    f.write(f'start "" "{exe_path}"\n')
                    f.write('del "%~f0"\n')
                import subprocess
                subprocess.Popen(["cmd", "/c", bat],
                    creationflags=0x00000008)  # DETACHED_PROCESS
                QApplication.quit()


# ── 메인 ──────────────────────────────────────────────────────────────────────

def main_cli():
    """기존 CLI 모드"""
    parser = argparse.ArgumentParser(
        description="Baiduyun Downloader (바이두윈 다운로더)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예:
  python baidu_dl.py login                        BDUSS 입력 및 저장
  python baidu_dl.py ls /                         루트 폴더 목록
  python baidu_dl.py ls /movies                   특정 폴더 목록
  python baidu_dl.py dl /11115.rar                파일 다운로드
  python baidu_dl.py dl /11115.rar -o D:\\downloads 저장 위치 지정
  python baidu_dl.py share <URL> <추출코드>       공유 링크 다운로드
  python baidu_dl.py config download_dir D:\\dl    다운로드 경로 설정
""",
    )

    sub = parser.add_subparsers(dest="command")

    # login
    p_login = sub.add_parser("login", help="BDUSS 입력 및 로그인")
    p_login.add_argument("--bduss", help="BDUSS 값 직접 입력")

    # ls
    p_ls = sub.add_parser("ls", help="파일 목록 보기")
    p_ls.add_argument("path", nargs="?", default="/", help="경로 (기본: /)")

    # dl
    p_dl = sub.add_parser("dl", help="파일 다운로드")
    p_dl.add_argument("path", help="다운로드할 파일 경로")
    p_dl.add_argument("-o", "--output", help="저장 디렉토리")

    # share
    p_share = sub.add_parser("share", help="공유 링크 다운로드")
    p_share.add_argument("url", help="공유 링크 URL")
    p_share.add_argument("code", help="추출코드")
    p_share.add_argument("-o", "--output", help="저장 디렉토리")

    # config
    p_cfg = sub.add_parser("config", help="설정 관리")
    p_cfg.add_argument("key", nargs="?", help="설정 키")
    p_cfg.add_argument("value", nargs="?", help="설정 값")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    commands = {
        "login": cmd_login,
        "ls": cmd_ls,
        "dl": cmd_dl,
        "share": cmd_share,
        "config": cmd_config,
    }
    commands[args.command](args)


def _is_windows_dark_mode():
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
        )
        val, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
        winreg.CloseKey(key)
        return val == 0
    except Exception:
        return False


_DARK_QSS = """
* {
    background-color: #2b2b2b;
    color: #e0e0e0;
    border: none;
    font-size: 13px;
}
QMainWindow, QDialog {
    background-color: #2b2b2b;
}
QWidget {
    background-color: #2b2b2b;
    color: #e0e0e0;
}
QToolBar {
    background-color: #323232;
    padding: 4px;
    spacing: 4px;
}
QToolBar QToolButton {
    background-color: #3c3f41;
    border: 1px solid #505050;
    border-radius: 4px;
    padding: 5px 12px;
    color: #e0e0e0;
}
QToolBar QToolButton:hover { background-color: #505356; }
QToolBar QToolButton:pressed { background-color: #6275c0; }
QLabel {
    background: transparent;
    color: #e0e0e0;
}
#pathLabel {
    font-weight: bold;
    padding: 2px 4px;
}
#dlNameLabel {
    font-weight: bold;
}
#loginGuide {
    background-color: #313335;
    border: 1px solid #505050;
    border-radius: 6px;
    padding: 12px;
}
#loginGuide a {
    color: #6ea8fe;
}
QTreeWidget {
    background-color: #313335;
    alternate-background-color: #2d2f31;
    border: 1px solid #3c3f41;
    border-radius: 4px;
    outline: none;
}
QTreeWidget::item { padding: 4px 0; }
QTreeWidget::item:selected { background-color: #4e5254; }
QTreeWidget::item:hover { background-color: #3a3d3f; }
QHeaderView::section {
    background-color: #3c3f41;
    color: #a0a0a0;
    border: none;
    border-right: 1px solid #505050;
    padding: 5px 8px;
    font-weight: bold;
}
QProgressBar {
    background-color: #3c3f41;
    border: none;
    border-radius: 6px;
    height: 18px;
    text-align: center;
    color: #ffffff;
}
QProgressBar::chunk {
    background-color: #5b8af5;
    border-radius: 6px;
}
QPushButton {
    background-color: #3c3f41;
    border: 1px solid #505050;
    border-radius: 4px;
    padding: 5px 14px;
    color: #e0e0e0;
}
QPushButton:hover { background-color: #505356; }
QPushButton:pressed { background-color: #6275c0; }
QStatusBar {
    background-color: #323232;
    color: #808080;
}
QStatusBar QLabel {
    color: #808080;
    background: transparent;
}
QTextEdit, QLineEdit {
    background-color: #313335;
    border: 1px solid #505050;
    border-radius: 4px;
    padding: 4px;
    color: #e0e0e0;
    selection-background-color: #5b8af5;
}
QMessageBox {
    background-color: #2b2b2b;
}
QMessageBox QLabel {
    color: #e0e0e0;
    background: transparent;
}
QMessageBox QPushButton {
    min-width: 80px;
}
QFormLayout {
    background-color: #2b2b2b;
}
QScrollBar:vertical {
    background-color: #2b2b2b;
    width: 10px;
    border: none;
}
QScrollBar::handle:vertical {
    background-color: #505050;
    border-radius: 5px;
    min-height: 20px;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal {
    background-color: #2b2b2b;
    height: 10px;
    border: none;
}
QScrollBar::handle:horizontal {
    background-color: #505050;
    border-radius: 5px;
    min-width: 20px;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QMenuBar {
    background-color: #323232;
    color: #e0e0e0;
    border-bottom: 1px solid #505050;
}
QMenuBar::item { padding: 4px 10px; }
QMenuBar::item:selected { background-color: #4e5254; }
QMenu {
    background-color: #313335;
    border: 1px solid #505050;
    color: #e0e0e0;
}
QMenu::item { padding: 5px 20px; }
QMenu::item:selected {
    background-color: #4e5254;
}
QMenu::separator {
    height: 1px;
    background: #505050;
    margin: 3px 8px;
}
"""

_LIGHT_QSS = """
QToolBar { spacing: 4px; }
QToolBar QToolButton { padding: 5px 12px; border-radius: 4px; }
#pathLabel { font-weight: bold; padding: 2px 4px; }
#dlNameLabel { font-weight: bold; }
#loginGuide {
    background-color: #f0f4ff;
    border: 1px solid #c0c8e0;
    border-radius: 6px;
    padding: 12px;
}
QTreeWidget { border-radius: 4px; outline: none; }
QTreeWidget::item { padding: 4px 0; }
QHeaderView::section { padding: 5px 8px; font-weight: bold; }
QProgressBar {
    border: 1px solid #c0c0c0; border-radius: 6px; height: 18px;
    text-align: center;
}
QProgressBar::chunk { background-color: #5b8af5; border-radius: 6px; }
QPushButton { padding: 5px 14px; border-radius: 4px; }
"""


def main_gui():
    """PySide6 GUI 모드 — 로그인 없이 즉시 메인 윈도우 표시"""
    _init_lang()
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    if _is_windows_dark_mode():
        app.setStyleSheet(_DARK_QSS)
    else:
        app.setStyleSheet(_LIGHT_QSS)

    window = BaiduDownloaderWindow()
    # 화면 중앙에 배치
    screen = app.primaryScreen().geometry()
    x = (screen.width() - window.width()) // 2
    y = (screen.height() - window.height()) // 2
    window.move(x, y)
    window.show()
    window.raise_()
    window.activateWindow()

    # 비동기 자동 로그인
    window._try_auto_login()

    sys.exit(app.exec())


def main():
    cli_commands = {"login", "ls", "dl", "share", "config"}
    if len(sys.argv) > 1 and sys.argv[1] in cli_commands:
        main_cli()
    elif HAS_GUI:
        main_gui()
    else:
        main_cli()


if __name__ == "__main__":
    main()
