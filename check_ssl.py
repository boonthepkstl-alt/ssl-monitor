#!/usr/bin/env python3
"""
check_ssl.py

อ่านรายชื่อ domain จาก domains.txt แล้วเชื่อมต่อ TLS ไปยังแต่ละ domain
เพื่อดึงข้อมูล SSL certificate (valid_from, valid_to, days_left)
จากนั้นเขียนผลลัพธ์ออกเป็น result.json

ไม่ต้องใช้ API key หรือบริการภายนอกใดๆ ทั้งสิ้น ใช้ Python built-in ssl/socket
module เชื่อมต่อไปยัง domain ปลายทางตรงๆ (port 443)
"""

import json
import socket
import ssl
from datetime import datetime, timezone

DOMAINS_FILE = "domains.txt"
OUTPUT_FILE = "result.json"
TIMEOUT_SECONDS = 8

# วันที่ในใบรับรอง SSL จะมาในรูปแบบนี้ เช่น "Aug 25 23:59:59 2026 GMT"
CERT_DATE_FORMAT = "%b %d %H:%M:%S %Y %Z"


def load_domains(path):
    domains = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # ตัด https://, http:// และ / ท้ายสุดออก เผื่อผู้ใช้ใส่มาแบบ URL เต็ม
            line = line.replace("https://", "").replace("http://", "")
            line = line.rstrip("/")
            domains.append(line)
    return domains


def check_domain(host, port=443):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT_SECONDS) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

        valid_from = datetime.strptime(cert["notBefore"], CERT_DATE_FORMAT).replace(
            tzinfo=timezone.utc
        )
        valid_to = datetime.strptime(cert["notAfter"], CERT_DATE_FORMAT).replace(
            tzinfo=timezone.utc
        )
        now = datetime.now(timezone.utc)
        days_left = (valid_to - now).days

        return {
            "host": host,
            "valid": days_left >= 0,
            "valid_from": valid_from.isoformat(),
            "valid_to": valid_to.isoformat(),
            "days_left": days_left,
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "error": None,
        }
    except Exception as e:
        return {
            "host": host,
            "valid": None,
            "valid_from": None,
            "valid_to": None,
            "days_left": None,
            "issuer": None,
            "error": str(e),
        }


def main():
    domains = load_domains(DOMAINS_FILE)
    results = [check_domain(d) for d in domains]

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "results": results,
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    # แสดงสรุปใน log ของ GitHub Actions ด้วย
    for r in results:
        if r["error"]:
            print(f"[ERROR] {r['host']}: {r['error']}")
        else:
            print(f"[OK] {r['host']}: days_left={r['days_left']} (valid_to={r['valid_to']})")


if __name__ == "__main__":
    main()
