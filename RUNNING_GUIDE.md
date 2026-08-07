# دليل تشغيل النظام الكامل (AI-IDS) من الصفر

> دليل دقيق مبني على التنفيذ الفعلي الذي تم في بيئة حقيقية (Windows + VMware + Debian 12 + Kali).
> اتبع الخطوات بالترتيب ولا تتخطَّ أيًا منها.

---

## 1) نبذة سريعة عن النظام

نظام كشف تسلل يعتمد على **المودل فقط** (لا قواعد توقيعات) في مساري التحليل:

| المسار | الوصف |
|---|---|
| تحليل الملفات | `pcap_analysis_service` / `csv_analysis_service` — يمر عبر مودل ML حصرًا |
| الالتقاط المباشر | `cicflowmeter_live_capture_service` — التقاط حزم حية → تدفقات → مودل ML |

### المودلان النشطان (CICIDS2017 — 15 فئة لكل منهما)

| المودل | النوع | الفئات |
|---|---|---|
| Random Forest V3 | random_forest | 15 فئة |
| XGBoost Pipeline V2 | xgboost | 15 فئة |

**الفئات (14 هجوم + BENIGN):**
`BENIGN, Bot, DDoS, DoS GoldenEye, DoS Hulk, DoS Slowhttptest, DoS slowloris, FTP-Patator, Heartbleed, Infiltration, PortScan, SSH-Patator, Web Attack Brute Force, Web Attack Sql Injection, Web Attack XSS`

> المستخدم يختار المودل أثناء التحليل (قائمة اختيار في واجهة Detection و Live Capture، أو عبر `model_id` برمجيًا).

---

## 2) المتطلبات الأساسية

- **VMware Workstation** (أو Player) على ويندوز.
- ملف **Debian 12 netinst**: `debian-12.0.0-amd64-netinst.iso`
- ملف **Kali Linux** ISO/VM.
- **مستودع المشروع**: `https://github.com/salhaihp97-glitc/AI-Driven-IDS.git`

> **مهم جدًا:** النظام يتطلب **Python ≥ 3.12** (لأن `cicflowmeter>=0.5.0` يتطلب ذلك). نسخة Debian 12 الافتراضية (Python 3.11) **لا تصلح** — سنجهّز 3.12 عبر `pyenv`.

---

## 3) تجهيز الجهاز المضيف (Windows) ورفع الكود

> (هذه الخطوة مرة واحدة فقط — تُرفع النسخة النهائية إلى GitHub لتُنقل إلى Debian)

```powershell
cd "مجلد_المشروع"
git add -A
git commit -m "Activate RF V3 & XGB V2 as sole selectable models; disable macro assembly by default"
git push --force-with-lease origin HEAD:main
```

> ملاحظة: المستودع قد يحوي تاريخًا غير مرتبط — استخدم `--force-with-lease` عند الحاجة.

**تحذير الإستثناءات في `.gitignore`** (مهمة لمنع رفع ملفات ضخمة):
- `ml/training/MachineLearningCVE/data/` (بيانات التدريب ~884MB — لا تُرفع)
- `simulated_attacks_demo.*`, `data/*.csv` (مخرجات تشغيل)

---

## 4) إنشاء آلة Debian 12 في VMware

1. **New Virtual Machine** ← اختر `debian-12.0.0-amd64-netinst.iso`.
2. ذاكرة **≥ 2048 MB**، معالج **2 نواة**، قرص **30 GB**.
3. أثناء التركيب:
   - **Install** (نصي أو رسومي).
   - Hostname: `ids`
   - أنشئ مستخدمًا (مثل `salh`) وكلمة مرور root.
   - Partitioning: `Guided - use entire disk` ← قرص واحد.
   - في **Software selection**: علّم فقط على:
     - ☑ **SSH server**
     - ☑ **standard system utilities**
   - GRUB: نعم.
4. أعد التشغيل.

### إعداد الشبكة لآلة Debian (Host-only)

1. أوقف الآلة ← **Settings** ← **Network Adapter** ← **Host-only** ← Ok.
2. شغّلها. ثم تأكد من العنوان:
   ```bash
   ip addr show ens33
   ```
   > المطلوب عنوان `192.168.145.x`. (إذا لم يكن كذلك، جرّب `sudo dhclient ens33`)

---

## 5) تجهيز Kali (المهاجم) — شبكة Host-only

1. من VMware: **Settings** ← **Network Adapter** ← **Host-only**.
2. شغّل Kali وتأكد من عنوانه:
   ```bash
   ip addr show eth0
   ```
   > المطلوب `192.168.145.x` (مثل `192.168.145.128`).

3. **تحقق الاتصال بين الجهازين** (من Kali):
   ```bash
   ping -c 3 <عنوان-Debian>
   ```

---

## 6) تثبيت النظام على Debian

### 6.1 الإنترنت المؤقت (بما أن Host-only بلا إنترنت)

> أثناء التثبيت نحتاج إنترنت لـ `apt`/`pip`. نعيد توجيهه مؤقتًا عبر بطاقة Host.

```bash
sudo ip route add default via 192.168.145.1
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf > /dev/null
```

### 6.2 متطلبات النظام

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git python3-venv python3-pip build-essential libpcap-dev net-tools tshark
```

### 6.3 تثبيت Python 3.12 (ضروري!)

```bash
sudo apt install -y curl git make build-essential libssl-dev zlib1g-dev \
  libbz2-dev libreadline-dev libsqlite3-dev libncurses5-dev libncursesw5-dev \
  xz-utils tk-dev libffi-dev liblzma-dev

curl -sSL https://pyenv.run | bash

echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
echo 'command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(pyenv init -)"' >> ~/.bashrc
source ~/.bashrc

pyenv install 3.12.10
```

> تجميع Python قد يستغرق 5–10 دقائق.

### 6.4 نسخ المشروع وتثبيت المكتبات

```bash
cd ~
git clone https://github.com/salhaihp97-glitc/AI-Driven-IDS.git
cd AI-Driven-IDS
pyenv local 3.12.10
python3 --version   # تأكد: 3.12.10

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

> **خطأ شائع:** إن ظهر `cicflowmeter>=0.5.0 ... Requires-Python >=3.12` فأنت على Python 3.11 — أكمل الخطوة 6.3 أولًا.

### 6.5 إعداد النظام لأول مرة

```bash
cd ~/AI-Driven-IDS
source venv/bin/activate
cp .env.example .env
python cli.py setup
```

> أجب: بقية الخطوات قيم افتراضية (Enter) ما عدا كلمة مرور المسؤول — اكتبها واحفظها.

### 6.6 تسجيل المودلين وتفعيلهما

> **مهم:** التحميل يحتاج 10–60 ثانية (المودل 24MB). **لا تقطع بـ Ctrl+C** وانتظر اكتماله.

```bash
python scripts/register_model.py --name "Random Forest V3" --path "models/random_forest_v3.joblib" --type "random_forest" --version "3.0.0" --activate

python scripts/register_model.py --name "XGBoost Pipeline V2" --path "models/xgboost_pipeline_v2.joblib" --type "xgboost" --version "2.0.0" --activate
```

### 6.7 التحقق

```bash
python cli.py list-models
```

**المطلوب:**
```
2 | Random Forest V3     | random_forest | Yes
1 | XGBoost Pipeline V2  | xgboost       | Yes
```

---

## 7) تشغيل النظام

```bash
cd ~/AI-Driven-IDS
source venv/bin/activate
python cli.py launch
```

- الواجهة تعمل على المنفذ **8501**.
- من الويندوز (المضيف): افتح المتصفح على `http://<عنوان-Debian>:8501` (مثل `http://192.168.145.129:8501`).
- دخول: `admin` / كلمة المرور التي أنشأتها.

---

## 8) اختبار الالتقاط المباشر من Kali

### 8.1 من الواجهة (Debian)

1. صفحة **Live Capture** ← اختر الواجهة `ens33` ← اختر المودل (RF V3 أو XGB V2) ← **Start Capture**.
2. صفحة **Live Flows** لعرض النتائج المباشرة.

### 8.2 الهجمات من Kali (الهدف = عنوان Debian)

| الفئة | الأمر |
|---|---|
| PortScan | `nmap -sS -T4 <عنوان-Debian>` |
| DDoS | `hping3 -S --flood -p 80 <عنوان-Debian>` أو `ab -n 20000 -c 500 http://<عنوان>/` |
| DoS Hulk | `python3 hulk.py http://<عنوان-Debian>/` |
| DoS GoldenEye | `python3 goldeneye.py <عنوان> -s 100 -a 100` |
| DoS slowloris | `slowloris.py -s 200 <عنوان>` |
| DoS Slowhttptest | `slowhttptest -c 1000 -B -g -o slow -i 10 -r 200 -u http://<عنوان>/` |
| FTP-Patator | `hydra -l admin -P rockyou.txt ftp://<عنوان>` |
| SSH-Patator | `hydra -l root -P rockyou.txt ssh://<عنوان>` |
| Web Brute Force | `hydra -l admin -P words.txt <عنوان> http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"` |
| SQLi | `sqlmap -u http://<عنوان>/vuln.php?id=1 --dbs` |
| XSS | حقن `<script>` في صفحة ضعيفة |

**توقعات صادقة:**
- **ممتاز (F1 ≥ 0.99):** DDoS، DoS Hulk، DoS GoldenEye، DoS slowloris، DoS Slowhttptest، FTP/SSH-Patator، PortScan، Infiltration.
- **ضعيف/غير موثوق:** Web XSS، SQL Injection، Bot، Web Brute Force — قد تُحكم BENIGN على الهواء.
- التدفق يُحكم بعد إغلاقه/خموله (~15 ثانية) — انتظر ثوانٍ قبل فحص النتيجة.
- SYN flood من منافذ دوّارة قد يُحكم BENIGN (لا يوجد صف SYN Flood في CICIDS2017).

---

## 9) حل المشاكل الشائعة

| المشكلة | الحل |
|---|---|
| `cicflowmeter Requires-Python >=3.12` | أنت على Python 3.11 — ثبّت 3.12 عبر pyenv (6.3) |
| `no such table: models` | شغّل `python cli.py setup` ثم أعد `list-models` |
| `register_model` يتوقف | المودل 24MB — انتظر 10–60 ثانية، لا تضغط Ctrl+C |
| الالتقاط لا يرى الحركة | تأكد أن Debian وKali كلاهما Host-only، واجري `ping` بينهما أولًا |
| لا يوجد إنترنت على Debian | `sudo ip route add default via 192.168.145.1` + resolv.conf (6.1) |
| الواجهة لا تُفتح من الويندوز | تأكد أنك تفتح على عنوان VMnet1 (192.168.145.x) وليس Wi-Fi |

---

## 10) بنية الملفات المهمة

| الملف | الدور |
|---|---|
| `services/pcap_analysis_service.py` | تحليل PCAP عبر المودل فقط |
| `services/csv_analysis_service.py` | تحليل CSV عبر المودل فقط |
| `services/detection_service.py` | تصنيف + فك attack_type من فئات المودل |
| `services/model_service.py` | تسجيل/تفعيل المودلات + `get_model_classes` |
| `capture/cicflowmeter_live_capture_service.py` | الالتقاط المباشر |
| `models/*.joblib` | النماذج المدربة (RF V3 + XGB V2 + scaler + encoder) |
| `cli.py setup` | تهيئة أولية (ينشئ قاعدة البيانات) |

**متغيرات الإعداد المهمة في `.env`:**
- `AI_IDS_MACRO_FLOW_ENABLED=false` — **أبقِها false** (المودلات per-flow مدربة على صفوف فردية).
- `AI_IDS_ML_DECISION_THRESHOLD=0.5` — عتبة القرار.
