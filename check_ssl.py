#!/usr/bin/env python3
"""
check_ssl.py

อ่านรายชื่อ domain จากไฟล์ domain list แล้วเชื่อมต่อ TLS ไปยังแต่ละ domain
เพื่อดึงข้อมูล SSL certificate (valid_from, valid_to, days_left) แล้วเขียนผลลัพธ์
ออกเป็น result.json

จุดสำคัญของสคริปต์นี้:

* อ่าน cert ที่ "หมดอายุแล้ว" ได้ — ถ้า verify ไม่ผ่าน จะ handshake ใหม่แบบไม่ verify
  เพื่อดึงวันหมดอายุจริงออกมา แล้วรายงาน days_left เป็นค่าติดลบ (ของเดิมได้ null)
* แยก "cert มีปัญหา" ออกจาก "เชื่อมต่อไม่ได้" ผ่าน field `status` และ `alert`
  ทำให้ downstream (n8n) ไม่แจ้งเตือนผิดเวลา host เข้าไม่ถึงเพราะ network/firewall
* เช็กแบบขนาน + retry เฉพาะ error ที่เป็นแบบชั่วคราว
* แยก scope public / internal ได้ เพราะ GitHub Actions runner อยู่นอกองค์กร
  จึงเช็ก host ที่เปิดเฉพาะ internal ไม่ได้

ใช้ Python built-in ssl/socket เป็นหลัก ส่วน `cryptography` เป็น optional
(ใช้เฉพาะตอนต้องอ่าน cert ที่ verify ไม่ผ่าน) — ถ้าไม่มีก็ยังรันได้ แต่จะไม่ได้
วันหมดอายุของ cert ที่หมดอายุแล้ว
"""

import argparse
import concurrent.futures
import json
import os
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    HAVE_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover - ขึ้นกับ environment
    HAVE_CRYPTOGRAPHY = False

# ---------------------------------------------------------------- configuration

SCOPE_FILES = {
    "public": "domains.txt",
    "internal": "domains-internal.txt",
}
DEFAULT_OUTPUT = "result.json"

# ปรับผ่าน environment variable ได้ (สำหรับรันบน runner ที่เน็ตช้า)
TIMEOUT_SECONDS = float(os.environ.get("SSL_TIMEOUT", "8"))
RETRIES = int(os.environ.get("SSL_RETRIES", "2"))
MAX_WORKERS = int(os.environ.get("SSL_MAX_WORKERS", "10"))
RETRY_BACKOFF_SECONDS = float(os.environ.get("SSL_RETRY_BACKOFF", "1"))
WARN_DAYS = int(os.environ.get("SSL_WARN_DAYS", "30"))
URGENT_DAYS = int(os.environ.get("SSL_URGENT_DAYS", "7"))

# วันที่ในใบรับรอง SSL จะมาในรูปแบบนี้ เช่น "Aug 25 23:59:59 2026 GMT"
CERT_DATE_FORMAT = "%b %d %H:%M:%S %Y %Z"

STATUS_OK = "ok"
STATUS_EXPIRING_SOON = "expiring_soon"
STATUS_EXPIRED = "expired"
STATUS_VERIFY_FAILED = "verify_failed"
STATUS_UNREACHABLE = "unreachable"
STATUS_DNS_ERROR = "dns_error"
STATUS_ERROR = "error"

# สถานะที่เป็น "ปัญหาของตัว certificate จริงๆ" เท่านั้นที่ควรแจ้งเตือนเจ้าของ domain
ALERT_STATUSES = frozenset({STATUS_EXPIRING_SOON, STATUS_EXPIRED, STATUS_VERIFY_FAILED})
# สถานะที่เป็นปัญหา network/infra — ควรแจ้งทีม infra ไม่ใช่แจ้งว่า cert ใกล้หมดอายุ
INFRA_STATUSES = frozenset({STATUS_UNREACHABLE, STATUS_DNS_ERROR, STATUS_ERROR})

_OID_NAMES = (
    {
        NameOID.COMMON_NAME: "commonName",
        NameOID.ORGANIZATION_NAME: "organizationName",
        NameOID.ORGANIZATIONAL_UNIT_NAME: "organizationalUnitName",
        NameOID.COUNTRY_NAME: "countryName",
    }
    if HAVE_CRYPTOGRAPHY
    else {}
)


# ------------------------------------------------------------------ domain list


def normalize_target(raw):
    """แปลงข้อความ 1 บรรทัดให้เป็น (host, port)

    รับได้ทั้ง "example.com", "example.com:8443", "https://example.com/path"
    ใช้ urlsplit แทน str.replace เพื่อไม่ตัดคำผิดตำแหน่งและตัด path/port ให้ถูกต้อง
    """
    text = raw.strip()
    if not text:
        return None
    if "//" not in text:
        text = "//" + text
    parts = urlsplit(text)
    host = (parts.hostname or "").strip().lower()
    if not host:
        return None
    try:
        port = parts.port or 443
    except ValueError:
        return None
    return host, port


def load_domains(path, scope):
    """อ่าน domain list 1 ไฟล์ ตัด comment / บรรทัดว่าง / รายการซ้ำออก"""
    targets = []
    seen = set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"[WARN] ไม่พบไฟล์ {path} — ข้าม scope '{scope}'", file=sys.stderr)
        return targets

    for lineno, line in enumerate(lines, 1):
        line = line.split("#", 1)[0]
        if not line.strip():
            continue
        target = normalize_target(line)
        if target is None:
            print(f"[WARN] {path}:{lineno} อ่านไม่ออก ข้ามบรรทัดนี้", file=sys.stderr)
            continue
        if target in seen:
            print(f"[WARN] {path}:{lineno} {target[0]} ซ้ำ — ข้าม", file=sys.stderr)
            continue
        seen.add(target)
        targets.append({"host": target[0], "port": target[1], "scope": scope})
    return targets


def load_all_domains(scopes):
    targets = []
    seen = set()
    for scope in scopes:
        for target in load_domains(SCOPE_FILES[scope], scope):
            key = (target["host"], target["port"])
            if key in seen:
                print(
                    f"[WARN] {target['host']} อยู่ในหลาย scope — ใช้ scope แรกที่เจอ",
                    file=sys.stderr,
                )
                continue
            seen.add(key)
            targets.append(target)
    return targets


# -------------------------------------------------------------------- TLS logic


def _connect(host, port, verify):
    """handshake แล้วคืน certificate

    verify=True  -> คืน dict จาก getpeercert() (มีข้อมูลครบเมื่อ verify ผ่าน)
    verify=False -> คืน DER bytes เพราะ getpeercert() จะคืน {} เมื่อปิด verification
    """
    if verify:
        context = ssl.create_default_context()
    else:
        context = ssl._create_unverified_context()
    with socket.create_connection((host, port), timeout=TIMEOUT_SECONDS) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            if verify:
                return ssock.getpeercert()
            return ssock.getpeercert(binary_form=True)


def _parse_cert_date(value):
    return datetime.strptime(value, CERT_DATE_FORMAT).replace(tzinfo=timezone.utc)


def _from_peercert_dict(cert):
    return {
        "valid_from": _parse_cert_date(cert["notBefore"]),
        "valid_to": _parse_cert_date(cert["notAfter"]),
        "issuer": dict(x[0] for x in cert.get("issuer", ())),
        "subject": dict(x[0] for x in cert.get("subject", ())),
    }


def _from_der(der):
    """อ่าน cert ที่ verify ไม่ผ่าน (เช่นหมดอายุแล้ว) ด้วย cryptography"""
    cert = x509.load_der_x509_certificate(der)
    # cryptography >= 42 ใช้ *_utc, ของเก่าเป็น naive UTC
    valid_from = getattr(cert, "not_valid_before_utc", None)
    valid_to = getattr(cert, "not_valid_after_utc", None)
    if valid_from is None:
        valid_from = cert.not_valid_before.replace(tzinfo=timezone.utc)
        valid_to = cert.not_valid_after.replace(tzinfo=timezone.utc)

    def name_to_dict(name):
        out = {}
        for attribute in name:
            key = _OID_NAMES.get(attribute.oid)
            if key:
                out[key] = attribute.value
        return out

    return {
        "valid_from": valid_from,
        "valid_to": valid_to,
        "issuer": name_to_dict(cert.issuer),
        "subject": name_to_dict(cert.subject),
    }


def _blank_result(target):
    return {
        "host": target["host"],
        "port": target["port"],
        "scope": target["scope"],
        "status": None,
        "valid": None,
        "cert_verified": None,
        "valid_from": None,
        "valid_to": None,
        "days_left": None,
        "issuer": None,
        "subject": None,
        "alert": False,
        "attempts": 0,
        "error": None,
    }


def _apply_cert(result, info, now):
    days_left = (info["valid_to"] - now).days
    result["valid_from"] = info["valid_from"].isoformat()
    result["valid_to"] = info["valid_to"].isoformat()
    result["days_left"] = days_left
    result["issuer"] = info["issuer"]
    result["subject"] = info["subject"]
    result["valid"] = days_left >= 0
    return days_left


def check_target(target):
    """เช็ก 1 host — คืน dict ที่มี status/alert ชัดเจน ไม่ปล่อยให้ null กำกวม"""
    host, port = target["host"], target["port"]
    result = _blank_result(target)
    now = datetime.now(timezone.utc)
    last_error = None
    total_attempts = RETRIES + 1

    for attempt in range(1, total_attempts + 1):
        result["attempts"] = attempt
        if attempt > 1 and RETRY_BACKOFF_SECONDS > 0:
            # เว้นจังหวะก่อนลองใหม่ กันกรณีปลายทาง rate limit หรือ network สะดุดชั่วคราว
            time.sleep(RETRY_BACKOFF_SECONDS * (attempt - 1))
        try:
            cert = _connect(host, port, verify=True)
            days_left = _apply_cert(result, _from_peercert_dict(cert), now)
            result["cert_verified"] = True
            result["error"] = None
            if days_left < 0:
                result["status"] = STATUS_EXPIRED
            elif days_left <= WARN_DAYS:
                result["status"] = STATUS_EXPIRING_SOON
            else:
                result["status"] = STATUS_OK
            break

        except ssl.SSLCertVerificationError as exc:
            # verify ไม่ผ่าน (หมดอายุ / hostname ไม่ตรง / chain ไม่สมบูรณ์)
            # ยิงซ้ำแบบไม่ verify เพื่อ "อ่านวันหมดอายุจริง" ให้ได้
            result["cert_verified"] = False
            result["error"] = str(exc)
            result["status"] = STATUS_VERIFY_FAILED
            if not HAVE_CRYPTOGRAPHY:
                result["error"] = (
                    f"{exc} (ต้องติดตั้ง cryptography เพื่ออ่านวันหมดอายุของ cert นี้)"
                )
                break
            try:
                der = _connect(host, port, verify=False)
                days_left = _apply_cert(result, _from_der(der), now)
                if days_left < 0:
                    result["status"] = STATUS_EXPIRED
            except Exception as inner:  # noqa: BLE001 - อ่านแบบไม่ verify ก็ยังไม่ได้
                result["error"] = f"{exc} / fallback failed: {inner}"
            break

        except socket.gaierror as exc:
            last_error = exc
            result["status"] = STATUS_DNS_ERROR
        except (socket.timeout, TimeoutError, ConnectionError, OSError) as exc:
            last_error = exc
            result["status"] = STATUS_UNREACHABLE
        except Exception as exc:  # noqa: BLE001 - กันสคริปต์ล้มทั้งรอบ
            result["status"] = STATUS_ERROR
            result["error"] = str(exc) or type(exc).__name__
            break

        # ถึงตรงนี้คือ error แบบชั่วคราว — retry ได้
        result["error"] = str(last_error) or type(last_error).__name__

    result["alert"] = result["status"] in ALERT_STATUSES
    return result


# ------------------------------------------------------------------------ output


def _severity(result):
    if result["status"] == STATUS_EXPIRED:
        return "expired"
    days_left = result["days_left"]
    if days_left is not None and days_left <= URGENT_DAYS:
        return "urgent"
    return "warning"


def build_output(results, scopes):
    counts = {}
    for result in results:
        counts[result["status"]] = counts.get(result["status"], 0) + 1

    alerts = [
        {
            "host": r["host"],
            "status": r["status"],
            "severity": _severity(r),
            "days_left": r["days_left"],
            "valid_to": r["valid_to"],
            "scope": r["scope"],
        }
        for r in results
        if r["alert"]
    ]
    # เรียงจากด่วนที่สุดก่อน, ตัวที่อ่านวันไม่ได้ไปท้ายสุด
    alerts.sort(key=lambda a: (a["days_left"] is None, a["days_left"] or 0))

    infra_issues = [
        {
            "host": r["host"],
            "status": r["status"],
            "scope": r["scope"],
            "error": r["error"],
        }
        for r in results
        if r["status"] in INFRA_STATUSES
    ]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scopes": scopes,
        "thresholds": {"warn_days": WARN_DAYS, "urgent_days": URGENT_DAYS},
        "summary": {
            "total": len(results),
            "alert_count": len(alerts),
            "infra_issue_count": len(infra_issues),
            "by_status": counts,
        },
        # n8n อ่าน 2 key นี้ได้ตรงๆ ไม่ต้องเขียนเงื่อนไขเปรียบเทียบตัวเลขเอง
        "alerts": alerts,
        "infra_issues": infra_issues,
        "results": results,
    }


def print_summary(output):
    for r in output["results"]:
        if r["days_left"] is not None:
            print(
                f"[{r['status'].upper()}] {r['host']}: days_left={r['days_left']} "
                f"(valid_to={r['valid_to']})"
            )
        else:
            print(f"[{r['status'].upper()}] {r['host']}: {r['error']}")

    summary = output["summary"]
    print(
        f"\n=== total={summary['total']} alerts={summary['alert_count']} "
        f"infra_issues={summary['infra_issue_count']} ==="
    )
    for alert in output["alerts"]:
        print(
            f"  ALERT [{alert['severity']}] {alert['host']}: "
            f"days_left={alert['days_left']} valid_to={alert['valid_to']}"
        )
    for issue in output["infra_issues"]:
        print(f"  INFRA [{issue['status']}] {issue['host']}: {issue['error']}")


# -------------------------------------------------------------------------- main


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="เช็ควันหมดอายุ SSL certificate")
    parser.add_argument(
        "--scope",
        default=os.environ.get("SSL_SCOPE", "all"),
        choices=["public", "internal", "all"],
        help=(
            "public = domain ที่เข้าถึงได้จาก internet (GitHub Actions เช็กได้), "
            "internal = domain ที่เปิดเฉพาะในองค์กร (ต้องรันจาก self-hosted runner "
            "หรือเครื่องใน network), all = ทั้งสอง (default)"
        ),
    )
    parser.add_argument(
        "--output",
        default=os.environ.get("SSL_OUTPUT", DEFAULT_OUTPUT),
        help=f"ไฟล์ผลลัพธ์ (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--fail-on-alert",
        action="store_true",
        help="exit code 1 ถ้าเจอ cert ที่หมดอายุ/ใกล้หมดอายุ (ไม่นับ host ที่เข้าไม่ถึง)",
    )
    return parser.parse_args(argv)


def main(argv=None):
    # log ของสคริปต์นี้มีข้อความภาษาไทย ถ้า redirect ลงไฟล์บน Windows
    # stdout จะเป็น cp1252 แล้วสคริปต์จะตายด้วย UnicodeEncodeError
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    args = parse_args(argv)
    scopes = ["public", "internal"] if args.scope == "all" else [args.scope]

    targets = load_all_domains(scopes)
    if not targets:
        print("[ERROR] ไม่มี domain ให้เช็ก", file=sys.stderr)
        return 2

    workers = max(1, min(MAX_WORKERS, len(targets)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(check_target, targets))

    output = build_output(results, scopes)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print_summary(output)

    if args.fail_on_alert and output["alerts"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
