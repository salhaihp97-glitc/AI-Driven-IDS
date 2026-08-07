# دليل تجربة الالتقاط المباشر وتنفيذ هجمات من Kali (VMware)

> دليل عملي دقيق مبني على كود المشروع الفعلي (لا تخمينات).
> كل أمر ومسار واسم ميزة في هذا الملف تحققت منه في الشيفرة المصدرية.

---

## 1) الهدف

اختبار أن الالتقاط المباشر يصنّف التدفقات **بالمودل فقط** (التوقيعات معطّلة افتراضيًا)،
عبر توليد حركة هجومية حقيقية من آلة Kali (VMware) والتأكد من ظهور النتائج في النظام.

---

## 2) البنية المعتمدة (حقائق من الشيفرة)

| العنصر | القيمة الفعلية | المصدر |
|---|---|---|
| وضع الالتقاط | `cicflowmeter` (محرك Python نقي — المحرك الوحيد) | `config/settings.py` ← `AI_IDS_LIVE_CAPTURE_MODE` |
| محرك التوقيعات | **معطّل افتراضيًا** (تصنيف مودل نقي) | `config/settings.py` ← `AI_IDS_SIG_ENGINE_ENABLED=false` |
| النماذج النشطة | RF V3 (id=3)، XGBoost V2 (id=4) — كلاهما 15 فئة / 70 ميزة | `services/model_service` |
| فئات المودل | 14 هجوم + BENIGN (طالع الجدول في §5) | `models/label_encoder.joblib` |
| تغطية الميزات في الالتقاط المباشر | 70/70 (CICFlowMeter يُنتج جميع أعمدة CICIDS2017) | `capture/cicflowmeter_live_capture_service.py` |
| شرط الحد الأدنى للتغطية | 50% (`AI_IDS_ML_MIN_FEATURE_COVERAGE`) | `config/settings.py` |
| ملف النتائج | `data/captured_flows_master.csv` | `AI_IDS_CAPTURED_FLOWS_DIR=data` |
| منفذ الواجهة | `http://localhost:8501` | `cli.py` → `_STREAMLIT_URL` |
| الدخول الافتراضي | `admin` / `admin` | `README.md` |

> ملاحظة: بما أن التوقيعات معطّلة، حكم الالتقاط المباشر = حكم المودل فقط (نفس تحليل الملفات).
> التنبيهات وقوائم الحظر/السماح تبقى مفعّلة للالتقاط المباشر.

---

## 3) التجهيز المسبق (مرة واحدة)

### 3.1 على Windows (المضيف)

```powershell
# تثبيت برنامج الالتقاط (مطلوب لـ Scapy على ويندوز)
# نزّل Npcap من npcap.com وثبّته بتمكين "WinPcap API-compatible Mode"
```

```powershell
cd "AI_IDS_3"
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

تأكد من وجود النماذج النشطة:

```powershell
python cli.py list-models
# يجب أن يظهر: 4 | XGBoost Pipeline V2 | active، و 3 | Random Forest V3 | active
```

عرض واجهات الشبكة المتاحة:

```powershell
python cli.py list-interfaces
```

### 3.2 على Kali (VMware)

1. **وضع الشبكة في VMware = Bridged** (جسر) — وليس NAT ولا Host-only.
   بهذا يمرّ كل حركة المضيف↔كالي عبر بطاقة الشبكة المادية للمضيف ويراها الالتقاط.
   > إذا بقيت NAT، قد لا يرى الالتقاط الحركة القادمة من كالي لأنها عابرة من الجسر الداخلي لـ VMware.
2. داخل كالي تحقق من عنوانك:

```bash
ip addr show
# سجّل عنوان كالي (مثل 192.168.1.50) وعنوان المضيف (windows: ipconfig → IPv4)
```

3. تأكد من إمكانية الاتصال بين الآلتين:

```bash
ping <عنوان_المضيف_ويندوز>
```

---

## 4) تشغيل الالتقاط المباشر

### الخيار أ — واجهة الويب (موصى به)

```powershell
python cli.py launch
# يفتح المتصفح على http://localhost:8501
```

1. سجّل دخول: `admin` / `admin`
2. صفحة **Live Capture**:
   - اختر واجهة الشبكة التي ستراها حركة كالي (الواجهة المرتبطة بجسر الشبكة).
   - اختر المودل: **XGBoost Pipeline V2** (id=4).
   - اضغط **Start Capture**.
3. افتح صفحة **Live Flows** لمشاهدة التدفقات وأحكامها.

### الخيار ب — سطر الأوامر

```powershell
# الالتقاط تفاعلي (يطلب رقم المودل ثم الواجهة)
python cli.py live-capture
# أو        
python cli.py
# ثم اختر من القائمة: 7) Live Capture  و  14) List Interfaces
```

### إيقاف الالتقاط

من الواجهة: زر **Stop**. من الطرفية: `Ctrl+C`.

---

## 5) الهجمات التي تختبرها من Kali

> المودل يصنّف حسب الفئات الـ14 التي تدرّب عليها (من `label_encoder.joblib`).
> التصنيف لكل تدفق: المودل يخرج `attack_type` مطابقًا لإحدى هذه الفئات.

| الهجوم من Kali | الأمر | فئة المودل المقابلة |
|---|---|---|
| فحص منافذ | `nmap -sS -T4 <المضيف>` | `PortScan` |
| DDoS | `hping3 -S --flood -p 80 <المضيف>` | `DDoS` |
| DoS Hulk | `python3 hulk.py http://<المضيف>/` | `DoS Hulk` |
| DoS GoldenEye | `python3 goldeneye.py <المضيف> -s 100 -a 100` | `DoS GoldenEye` |
| DoS slowloris | `slowloris.py -s 200 <المضيف>` | `DoS slowloris` |
| DoS Slowhttptest | `slowhttptest -c 1000 -B -g -o slow -i 10 -r 200 -u http://<المضيف>/` | `DoS Slowhttptest` |
| كسر كلمة مرور FTP | `hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://<المضيف>` | `FTP-Patator` |
| كسر كلمة مرور SSH | `hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<المضيف>` | `SSH-Patator` |
| هجوم Web Brute Force | `hydra -l admin -P words.txt <المضيف> http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"` | `Web Attack – Brute Force` |
| SQL Injection | `sqlmap -u http://<المضيف>/vuln.php?id=1 --dbs` | `Web Attack – Sql Injection` |
| XSS | حقن سكربت في صفحة قابلة للاختراق على المضيف | `Web Attack – XSS` |

> **ملاحظات صادقة حول الهجمات 1 و 2:**
> - فحص `nmap` و `hping3 --flood` يولّدان تدفقات قد لا تشبه تمامًا توزيع CICIDS2017.
>   قد يصرّح المودل عنها **BENIGN** على الهواء مباشرة — وهذا نتيجة حقيقية وليست عطلًا
>   (في السابق كان محرك التوقيعات يغطي SYN flood؛ وهو معطّل الآن بقرار تعطيل التوقيعات).
> - الهجمات التي تتطلب خادمًا على المضيف (Web/XSS/SQLi) تحتاج تشغيل خادم HTTP محلي
>   على ويندوز (مثل `python -m http.server 8080`) أو موقع اختبار ضعيف داخل المعمل.

---

## 6) التحقق من النتائج (بدون تكهنات)

### 6.1 فحص فوري أثناء الهجوم

من واجهة الويب: صفحة **Live Flows** تعيد التحديث بمعدل تختاره (شريط "Refresh interval"،
الافتراضي 5 ثوانٍ). لكل تدفق: الحالة، نوع الهجوم، الخطورة، الثقة، والحكم
(Blocked/Admin Test إن وُجد).

### 6.2 فحص الملف

```powershell
# الملف يُكتب أثناء الالتقاط
Get-Content data\captured_flows_master.csv | Select-Object -First 5
# أعمدة النتيجة: prediction | confidence | attack_type
```

### 6.3 مطابقة الحكم بالحقيقة الأرضية

- **الحقيقة الأرضية** = الأمر الذي شغّلته من كالي (مثال: `nmap`).
- **حكم المودل** = قيمة `attack_type` في الصف الموافق.
- إن تطابق الاثنان: المودل كشف الهجوم على الهواء مباشرة.
- إن أظهر `BENIGN`: هذا نتيجة قياسية حقيقية — حركة الهجوم هذه خارج قدرة المودل الحالية.
  (الوصول لهذه النتيجة هو هدف التجربة: تعرف حدود المودل على حركة حقيقية).

### 6.4 تحقق مبدئي محسوم (قبل الالتقاط المباشر)

إن أردت إثباتًا قاطعًا أن المودل يعمل، ابدأ بتقييم على ملف CICIDS2017 مُعلَّم
(النتيجة تحسم بمقارنة `attack_type` بعمود `Label`):

```python
from services.container import Container
from services.model_evaluation_service import EvaluationResult
c = Container()
xgb = next(m for m in c.model_service.list_models() if m.id == 4)
r = c.model_evaluation_service.evaluate(xgb, "labeled_cicids.csv", label_column="Label")
print(r.accuracy, r.f1, r.mcc, r.fpr, r.fnr)
```

---

## 7) توقعات صادقة (حقائق من ملف تقييم المودل على CICIDS2017)

> الأرقام أدناه من عينة احتجاز 504,160 تدفقًا (`models/models_evaluation_results.json`)،
> وهي مؤشر على القدرة **وليست** قياسًا حيًا. أداء الالتقاط المباشر على حركة حقيقية قد يختلف.

- **ممتاز (F1 ≥ 0.99)**: DDoS، DoS Hulk، DoS GoldenEye، DoS slowloris، DoS Slowhttptest،
  FTP-Patator، SSH-Patator، PortScan، Infiltration.
- **ضعيف/غير موثوق**: Web XSS (F1 ≈ 0.25–0.46)، Bot (≈ 0.72–0.82)،
  Web Brute Force (≈ 0.78–0.83)، SQL Injection (≈ 0.40–0.57)، Heartbleed (دعم 2 عينة فقط).

---

## 8) قيود يجب أن تعرفها (لا نتائج مضمونة)

1. الالتقاط المباشر يصنّف **لكل تدفق** بعد إغلاقه/خموله (افتراضيًا كل 15 ثانية).
2. الهجمات التي لا تشبه توزيع CICIDS2017 قد تُحكم `BENIGN` — هذا طبيعي ومتوقّع.
3. `nmap` السريع يولّد تدفقات قصيرة كثيرة؛ قد لا تُدمج كتدفق واحد دالّ.
4. التوقيعات معطّلة افتراضيًا: لا يوجد أي تجاوز قواعد على حكم المودل في الالتقاط المباشر.
5. **لا تنفّذ الهجمات على شبكة إنتاج** — استخدم معملًا معزولًا (VMware جسر على شبكة خاصة
   أو شبكة تجريبية معزولة بين كالي والمضيف).
6. لتنشيط التوقيعات اختياريًا (تحذير: يعيد تجاوز قواعد على حكم المودل):
   غيّر في `.env` قيمة `AI_IDS_SIG_ENGINE_ENABLED=true` ثم أعد تشغيل التطبيق.

---

## 9) خط سير سريع للتنفيذ

```powershell
# 1) المضيف: قائمة الواجهات ثم تشغيل الواجهة
python cli.py list-interfaces
python cli.py launch

# 2) واجهة الويب: Live Capture ← اختر الواجهة + XGBoost V2 ← Start

# 3) كالي: نفّذ هجومًا وانتظر ظهور التدفق
nmap -sS -T4 192.168.1.100        # المثال

# 4) افحص النتيجة
#    Live Flows + data/captured_flows_master.csv
```
