# SSL Monitor (GitHub Actions + GitHub Pages)

รันเช็ค SSL certificate expiry ของ domain ต่างๆ ให้ **ฟรีอัตโนมัติทุกวัน** โดยใช้ GitHub Actions
เป็นตัวรันสคริปต์ และ GitHub Pages เป็นตัว serve ผลลัพธ์ออกมาเป็น URL ที่ n8n เรียกได้เหมือน API
ไม่ต้องมีค่าใช้จ่าย ไม่ต้องพึ่ง API ภายนอกใดๆ และไม่ต้องแก้ config ของ n8n server เลย

## วิธีติดตั้ง

### 1. สร้าง GitHub repository ใหม่

- ไปที่ github.com สร้าง repo ใหม่ (public repo ใช้ GitHub Pages ฟรีได้ทันที
  ถ้าต้องการ private repo ต้องมี GitHub Pro/Team ขึ้นไป)
- ตั้งชื่อ เช่น `ssl-monitor`

### 2. อัปโหลดไฟล์ทั้งหมดในโฟลเดอร์นี้เข้า repo

โครงสร้างไฟล์ที่ต้องมี:

```
ssl-monitor/
├── .github/
│   └── workflows/
│       └── ssl-check.yml
├── check_ssl.py
├── domains.txt
└── README.md
```

จะใช้วิธี upload ผ่านหน้าเว็บ GitHub (drag ไฟล์เข้าไป) หรือ `git push` จากเครื่องก็ได้

### 3. แก้ไขรายชื่อ domain ที่ต้องการ monitor

เปิดไฟล์ `domains.txt` แล้วใส่ domain ที่ต้องการ (1 บรรทัดต่อ 1 domain ไม่ต้องมี `https://`)
ตัวอย่างนี้ตั้งไว้ให้แล้วคือ `app-konga.singerthai.app` — เพิ่ม/ลบ domain อื่นได้ตามต้องการ

### 4. เปิดใช้งาน GitHub Pages

ไปที่ repo > **Settings** > **Pages** (เมนูด้านซ้าย)
- Source: เลือก **"Deploy from a branch"**
- Branch: เลือก `main` (หรือ `master`) และโฟลเดอร์ `/ (root)`
- กด Save

รอ 1-2 นาที ระบบจะให้ URL มา เช่น:
```
https://<username>.github.io/ssl-monitor/
```

### 5. ทดสอบรัน workflow ครั้งแรก (ไม่ต้องรอ schedule)

ไปที่แท็บ **Actions** ของ repo > เลือก workflow **"Check SSL Certificates"** ทางซ้าย
กดปุ่ม **"Run workflow"** (มุมขวา) เพื่อรันทันที

หลังรันเสร็จ (ใช้เวลาประมาณ 10-20 วินาที) จะมีไฟล์ `result.json` ถูก commit เข้า repo อัตโนมัติ

### 6. ตรวจสอบผลลัพธ์

เปิด URL นี้ในเบราว์เซอร์ (แทน `<username>` ด้วยชื่อ GitHub ของคุณ):
```
https://<username>.github.io/ssl-monitor/result.json
```

ควรเห็น JSON หน้าตาแบบนี้:
```json
{
  "generated_at": "2026-08-04T01:00:00+00:00",
  "results": [
    {
      "host": "app-konga.singerthai.app",
      "valid": true,
      "valid_from": "2026-01-01T00:00:00+00:00",
      "valid_to": "2026-12-31T23:59:59+00:00",
      "days_left": 149,
      "issuer": { "organizationName": "Let's Encrypt", "commonName": "R11" },
      "error": null
    }
  ]
}
```

### 7. เชื่อมต่อกับ n8n

ในโหนด **"Check SSL"** ของ n8n workflow เดิม:
- เปลี่ยน Method เป็น **GET**
- ตั้ง URL เป็น `https://<username>.github.io/ssl-monitor/result.json`
- ผลลัพธ์จะมาเป็น array ที่ path `results` — ต้องเพิ่มโหนด **"Split Out"** หรือ **"Item Lists"**
  เพื่อแตก array `$json.results` ออกเป็นทีละ item ก่อนส่งต่อไปยังโหนด "URLs to Monitor" และ
  "Expiry Alert" (เพราะ field เดิมใช้ `$json.result.host` ส่วนอันนี้เป็น `$json.host` ตรงๆ ในแต่ละ item
  หลัง Split Out แล้ว — ต้องแก้ expression ในโหนดถัดไปให้ตรงกับ field name ใหม่)

## หมายเหตุ

- Schedule ตั้งไว้ให้รันทุกวัน 08:00 น. เวลาไทย ถ้าต้องการเปลี่ยนเวลา แก้ค่า cron ในไฟล์
  `.github/workflows/ssl-check.yml` (เวลาที่ตั้งเป็น UTC เสมอ)
- GitHub Actions ฟรีสำหรับ public repo แบบไม่จำกัด (สำหรับ private repo มี free quota
  2,000 นาที/เดือน ซึ่ง workflow นี้ใช้เวลาไม่ถึง 1 นาที/ครั้ง เพียงพอสำหรับใช้งานระยะยาวแน่นอน)
- ถ้าเพิ่ม domain ใหม่ใน `domains.txt` ไม่ต้องรอรอบ schedule ถัดไป กด "Run workflow" มือได้เลย
