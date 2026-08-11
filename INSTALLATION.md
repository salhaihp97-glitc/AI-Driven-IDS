# AI-IDS — دليل التحميل والإعداد والتشغيل

نظام كشف الاختراق الذكي (AI-Driven Intrusion Detection System) مبنيّ على التعلم الآلي
ومعمارية نظيفة (Clean Architecture) مع فصول خدمية ومستودعات بيانات منفصلة.
هذا الدليل يأخذك خطوة بخطوة من **التحميل** إلى **الإعداد** ثم **التشغيل** على جهازك.

---

## 1) المتطلبات الأساسية (Prerequisites)

| المتطلّب | النسخة |
| --- | --- |
| Python | **3.13 أو أحدث** |
| pip | متضمّن مع Python |
| Git | أحدث إصدار متاح |
| نظام تشغيل | Windows 10/11 ، Linux ، macOS |

> **ملاحظة للالتقاط المباشر (حزم الشبكة):** للاستفادة من الالتقاط المباشر والفحص الفوري،
> تحتاج صلاحيات رفع مستوى (Root على Linux / **Npcap** على Windows).
> يمكنك دائمًا استخدام تحليل ملفات CSV/PCAP بدون أي صلاحيات إضافية.

---

## 2) تحميل النظام (Download)

استنسخ المستودع إلى جهازك:

```bash
git clone <رابط-مستودعك-على-GitHub>
cd AI_IDS_3
```

> المستودع يتضمّن **النماذج المدربة** مُسبقًا داخل مجلد `models/`
> (RandomForest + XGBoost) ليبدأ النظام عملًا فورًا دون تدريب.

---

## 3) إنشاء البيئة الافتراضية وتثبيت المتطلبات

**Windows (PowerShell):**

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

**Linux / macOS (Bash):**

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 4) إعداد ملف البيئة (Configuration)

أنشئ ملف `.env` من القالب، وعدّل القيم حسب بيئتك:

```bash
cp .env.example .env
```

أهم المتغيرات في `.env`:

| المتغير | الوظيفة |
| --- | --- |
| `AI_IDS_APP_MODE` | وضع التشغيل (`development` / `production`) |
| `AI_IDS_DATABASE_PATH` | موقع ملف قاعدة البيانات (افتراضيًا `data/ai_ids.db`) |
| `AI_IDS_TELEGRAM_BOT_TOKEN` | توكن بوت Telegram لإرسال التنبيهات (اختياري) |
| `AI_IDS_TELEGRAM_CHAT_ID` | رقم المحادثة/المجموعة لإرسال التنبيهات (اختياري) |
| `AI_IDS_ML_DECISION_THRESHOLD` | عتبة قرار النموذج (افتراضي `0.5`) |
| `AI_IDS_ML_MIN_FEATURE_COVERAGE` | الحد الأدنى لتغطية الخصائص المطلوبة (افتراضي `0.5`) |

> اترك الحقول المعلّقة بأمثِلها الافتراضية إن لم تحتج شيئًا منها؛ النظام يعمل بإعدادات افتراضية سليمة.

---

## 5) تهيئة قاعدة البيانات وتسجيل النماذج

عند أول تشغيل، يُنشئ النظام قاعدة البيانات تلقائيًا (مجلد `data/`) ويستحدث
حساب **المدير الافتراضي** (انظر القسم 7).

بما أن النماذج محمّلة في المستودع، سجّلها في منظومة التشغيل (نفّذ مرة واحدة فقط):

```bash
python scripts/register_model.py --name "Random Forest V3" --path models/random_forest_v3.joblib --type random_forest --activate
python scripts/register_model.py --name "XGBoost Pipeline V2" --path models/xgboost_pipeline_v2.joblib --type xgboost --activate
```

> يمكنك أيضًا تسجيل النماذج أو إدارتها لاحقًا من واجهة **Models** داخل النظام.

---

## 6) تشغيل النظام

### واجهة الويب (بريمج Streamlit)

```bash
streamlit run app.py
```

افتح المتصفح على العنوان الظاهر (افتراضيًا: `http://localhost:8501`).

### واجهة الأوامر (CLI)

```bash
python cli.py
```

---

## 7) الحساب الافتراضي والأمان

| الحقل | القيمة |
| --- | --- |
| اسم المستخدم | `admin` |
| كلمة المرور | `admin` |

> **تحذير أمني:** كلمة المرور مشفّرة (bcrypt) داخل قاعدة البيانات، لكن **غيّرها فور أول تسجيل دخول**
> من لوحة **Settings**. لا تنشر حسابًا بكلمة مرور افتراضية في بيئة عامة أبدًا.

---

## 8) تشغيل الاختبارات (Testing)

للتحقق من سلامة النظام بالكامل:

```bash
python -m pytest
```

يجب أن تظهر النتائج **كلها ناجحة** (مع تحذيرات أمان غير مؤثّرة أحيانًا من مكتبة `scikit-learn`).

يمكن أيضًا التحقق من الأساسيات دون تشغيل الواجهة:

```bash
python -m pytest tests/test_services_layer.py -q
```

---

## 9) بنية المشروع (Project Structure)

```
app.py                 → نقطة دخول واجهة Streamlit
cli.py                 → نقطة دخول واجهة الأوامر (قوائم تفاعلية)
capture/               → التقاط الحزم وتحويلها إلى micro-flows (مدخل مباشر + PCAP)
config/                → إعدادات النظام والثوابت
core/                  → الكيانات (Entities) والواجهات المجرّدة والاستثناءات
database/              → طبقة قاعدة البيانات SQLite (اتصال + مخطط + تهيئة)
infrastructure/        → التشفير، التسجيل (Logging)، بوابة Telegram، جدار الحماية
ml/                    → محمّل النماذج، مخطط الخصائص، محرك التوقيعات الشاذة
models/                → النماذج المدربة مسبقًا + أسماء الخصائص (sidecar)
repositories/          → تنفيذ نمط Repository للوصول للبيانات
scripts/               → أدوات سطر أوامر (تسجيل نموذج، تحقق، فحص أمني)
services/              → طبقة منطق الأعمال + حاوية حقن الاعتماديات (Container)
ui/pages/              → صفحات واجهة العرض (Dashboard، Detection، Alerts، ...)
tests/                 → مجموعة الاختبارات الآلية
```

---

## 10) استكشاف الأخطاء وإصلاحها (Troubleshooting)

| المشكلة | الحل |
| --- | --- |
| `PermissionError` عند الالتقاط المباشر | ثبّت **Npcap** (Windows) أو شغّل بصلاحيات Root (Linux). يُمكنك البدء بتحليل CSV/PCAP |
| `ModuleNotFoundError` | تأكد أنك فعّلت البيئة الافتراضية وأن `pip install -r requirements.txt` اكتمل |
| خطأ توصيل قاعدة البيانات | تأكد أن مجلد `data/` قابل للكتابة، واحذف `data/ai_ids.db` إن تلف (يُعاد إنشاؤه تلقائيًا) |
| النماذج غير مسجّلة | نفّذ أوامر القسم 5 أو سجّلها من واجهة **Models** |
| تحذيرات `InconsistentVersionWarning` | غير مؤذية — فرق نسخ بين `scikit-learn` وقت التدريب والتشغيل |

---

## 11) مزيد من التوثيق

| المستند | المحتوى |
| --- | --- |
| `README.md` | نظرة عامة على النظام وبناه المعمارية |
| `ARCHITECTURE.md` | شرح معماري تفصيلي للطبقات وأنابيب الاستخراج |
| `TESTING_GUIDE.md` | استراتيجيات ونطاق الاختبارات |
| `DEPLOYMENT_FILES.txt` | قائمة ملفات النشر المطلوبة على آلة جديدة |
| `requirements.txt` | حزم الاعتماديات |