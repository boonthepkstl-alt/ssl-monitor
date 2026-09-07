# SSL Monitor (GitHub Actions + GitHub Pages)

รันเช็ค SSL certificate expiry ของ domain ต่างๆ ให้ **ฟรีอัตโนมัติทุกวัน** โดยใช้ GitHub Actions
เป็นตัวรันสคริปต์ และ GitHub Pages เป็นตัว serve ผลลัพธ์ออกมาเป็น URL ที่ n8n เรียกได้เหมือน API

## โครงสร้างไฟล์

```
ssl-monitor/
├── .github/workflows/ssl-check.yml   # schedule รันทุกวัน 08:00 น. (เวลาไทย)
├── check_ssl.py                      # สคริปต์เช็ก SSL
├── domains.txt                       # domain ที่เข้าถึงได้จาก internet
├── domains-internal.txt              # domain ที่เปิดเฉพาะใน network องค์กร
├── requirements.txt                  # cryptography (ใช้อ่าน cert ที่หมดอายุแล้ว)
├── result.json                       # ผลลัพธ์ scope public (GitHub Actions commit ให้)
└── README.md
```

## public กับ internal ต่างกันอย่างไร (สำคัญ)

GitHub Actions runner อยู่บน cloud **นอก network องค์กร** จึงเช็ก domain ที่เปิดเฉพาะ internal
ไม่ได้เลย (จะได้ `timed out` หรือ DNS ไม่รู้จัก) จึงต้องแยกเป็น 2 ไฟล์:

| ไฟล์ | เนื้อหา | ใครรัน |
| --- | --- | --- |
| `domains.txt` | domain ที่เข้าถึงได้จาก internet (46 รายการ) | GitHub Actions ทุกวันอัตโนมัติ |
| `domains-internal.txt` | domain ที่เปิดเฉพาะใน network องค์กร (12 รายการ) | self-hosted runner หรือเครื่องใน network |

การแยกใช้ผลจริงจากการรันบน GitHub Actions เป็นเกณฑ์ ไม่ได้ใช้ private/public IP เพราะองค์กรใช้
split-horizon DNS — เช่น `edocument.singerthai.co.th` ในออฟฟิศได้ IP `172.16.x.x` แต่จาก internet
เข้าถึงได้ปกติ จึงอยู่ในกลุ่ม public

## วิธีรัน

```bash
pip install -r requirements.txt

# เช็กทั้งสอง scope (default) — ใช้จากเครื่องใน network องค์กร
python check_ssl.py

# เช็กแค่ public — GitHub Actions ใช้อันนี้ เขียนลง result.json
python check_ssl.py --scope public

# เช็กแค่ internal — เขียนแยกไฟล์ไม่ให้ทับของ public
python check_ssl.py --scope internal --output result-internal.json

# ให้ exit code เป็น 1 ถ้าเจอ cert หมดอายุ/ใกล้หมดอายุ (สำหรับใช้ใน CI)
python check_ssl.py --fail-on-alert
```

`cryptography` เป็น optional — ถ้าไม่ติดตั้ง สคริปต์ยังรันได้ แต่จะอ่าน **วันหมดอายุของ cert
ที่หมดอายุไปแล้ว** ไม่ได้ (จะรายงานแค่ `status: verify_failed`)

### ปรับค่าผ่าน environment variable

| ตัวแปร | default | ความหมาย |
| --- | --- | --- |
| `SSL_TIMEOUT` | `8` | timeout ต่อ host (วินาที) |
| `SSL_RETRIES` | `2` | จำนวนครั้งที่ลองซ้ำเมื่อ timeout/DNS พลาด |
| `SSL_MAX_WORKERS` | `10` | จำนวน host ที่เช็กพร้อมกัน |
| `SSL_WARN_DAYS` | `30` | เหลือน้อยกว่านี้ = `expiring_soon` |
| `SSL_URGENT_DAYS` | `7` | เหลือน้อยกว่านี้ = severity `urgent` |

## รูปแบบ result.json

```json
{
  "generated_at": "2026-09-07T01:00:00+00:00",
  "scopes": ["public"],
  "thresholds": { "warn_days": 30, "urgent_days": 7 },
  "summary": {
    "total": 46,
    "alert_count": 1,
    "infra_issue_count": 0,
    "by_status": { "ok": 45, "expired": 1 }
  },
  "alerts": [
    {
      "host": "example.singerthai.app",
      "status": "expired",
      "severity": "expired",
      "days_left": -5,
      "valid_to": "2026-09-02T23:59:59+00:00",
      "scope": "public"
    }
  ],
  "infra_issues": [],
  "results": [
    {
      "host": "app-konga.singerthai.app",
      "port": 443,
      "scope": "public",
      "status": "ok",
      "valid": true,
      "cert_verified": true,
      "valid_from": "2026-08-11T02:25:17+00:00",
      "valid_to": "2027-02-25T02:30:01+00:00",
      "days_left": 170,
      "issuer": { "organizationName": "SSL Corporation", "commonName": "..." },
      "subject": { "commonName": "*.singerthai.app" },
      "alert": false,
      "attempts": 1,
      "error": null
    }
  ]
}
```

### ค่า `status` ที่เป็นไปได้

| status | ความหมาย | นับเป็น alert? |
| --- | --- | --- |
| `ok` | cert ใช้ได้ เหลือเวลามากกว่า `warn_days` | ไม่ |
| `expiring_soon` | cert ใช้ได้ แต่เหลือไม่เกิน `warn_days` | **ใช่** |
| `expired` | cert หมดอายุแล้ว (`days_left` ติดลบ) | **ใช่** |
| `verify_failed` | verify ไม่ผ่านด้วยเหตุอื่น (hostname ไม่ตรง / chain ไม่ครบ) | **ใช่** |
| `unreachable` | เชื่อมต่อไม่ได้ (timeout / connection refused) — ปัญหา network | ไม่ |
| `dns_error` | resolve DNS ไม่ได้ | ไม่ |
| `error` | error อื่นที่ไม่คาดคิด | ไม่ |

`unreachable` / `dns_error` / `error` จะไปอยู่ใน `infra_issues` แยกจาก `alerts`
เพราะเป็นปัญหา network ไม่ใช่ปัญหาของ certificate

## เชื่อมต่อกับ n8n

ตั้ง HTTP Request node เป็น **GET** ไปที่:

```
https://<username>.github.io/ssl-monitor/result.json
```

จากนั้นใช้ **Split Out** node แตก field **`alerts`** (ไม่ใช่ `results`) ออกเป็นทีละ item
แล้วส่งต่อเข้า node ที่ส่งข้อความได้เลย — ไม่ต้องเขียนเงื่อนไขเปรียบเทียบตัวเลขเอง เพราะ
`alerts` มีแต่รายการที่ควรแจ้งเตือนจริงอยู่แล้ว

ตัวอย่าง expression สำหรับข้อความแจ้งเตือน:

```
{{ $json.severity === 'expired'
     ? '🔴 ' + $json.host + ' — หมดอายุไปแล้ว ' + Math.abs($json.days_left) + ' วัน'
     : '⚠️ ' + $json.host + ' — เหลือ ' + $json.days_left + ' วัน (หมดอายุ ' + $json.valid_to + ')' }}
```

> **หมายเหตุสำคัญ — เหตุผลที่ต้องใช้ `alerts`**
>
> ถ้ากรองจาก `results` ด้วยเงื่อนไขแบบ `days_left <= 30` จะเจอบั๊ก: host ที่เช็กไม่สำเร็จมี
> `days_left` เป็น `null` และใน JavaScript `null <= 30` ให้ค่า **`true`** (null ถูก coerce เป็น 0)
> ทำให้ทุก host ที่เชื่อมต่อไม่ได้ถูกแจ้งเตือนเป็น "เหลือ 0 วัน เร่งด่วน" ทั้งหมด
>
> ถ้าจำเป็นต้องกรองจาก `results` เอง ให้เช็ก field `alert` แทน:
> `{{ $json.results.filter(r => r.alert) }}`
> หรือเช็ก null ให้ครบ: `r.days_left !== null && r.days_left <= 30`

ถ้าต้องการให้ n8n เตือนเรื่อง host ที่เข้าไม่ถึงด้วย ให้ทำอีก branch อ่านจาก `infra_issues`
แล้วส่งเข้าช่องของทีม infra แยกจากช่องแจ้งเตือน cert

## การตั้งค่าครั้งแรก

### 1. เปิดใช้งาน GitHub Pages

repo > **Settings** > **Pages** > Source: **Deploy from a branch**, Branch: `main` โฟลเดอร์ `/ (root)` > Save

### 2. ทดสอบรัน workflow

แท็บ **Actions** > workflow **"Check SSL Certificates"** > ปุ่ม **"Run workflow"**

หลังรันเสร็จจะมี `result.json` ถูก commit เข้า repo อัตโนมัติ แล้วเปิดดูได้ที่
`https://<username>.github.io/ssl-monitor/result.json`

### 3. (แนะนำ) ตั้ง self-hosted runner สำหรับ domain internal

`domains-internal.txt` มี 12 domain ที่ GitHub cloud runner เช็กไม่ได้ ทางเลือก:

- **ตั้ง self-hosted runner** ในเน็ตเวิร์กองค์กร (repo > Settings > Actions > Runners) แล้วเพิ่ม job
  ที่ `runs-on: self-hosted` รัน `python check_ssl.py --scope internal --output result-internal.json`
- **หรือ** ให้ n8n server ที่อยู่ใน network รัน `check_ssl.py --scope internal` ตาม cron เอง
  แล้วอ่านผลจากไฟล์ในเครื่องโดยตรง

## หมายเหตุ

- Schedule ตั้งไว้รันทุกวัน 08:00 น. เวลาไทย แก้ค่า cron ได้ใน `.github/workflows/ssl-check.yml`
  (เวลาใน cron เป็น UTC เสมอ)
- GitHub Actions ฟรีไม่จำกัดสำหรับ public repo (private repo มี free quota 2,000 นาที/เดือน
  workflow นี้ใช้เวลาไม่ถึง 1 นาที/ครั้ง)
- เพิ่ม domain ใหม่แล้วไม่ต้องรอรอบ schedule กด "Run workflow" ได้เลย
- domain ซ้ำในไฟล์เดียวกันหรือข้ามไฟล์จะถูกข้ามอัตโนมัติพร้อมขึ้น warning ใน log
