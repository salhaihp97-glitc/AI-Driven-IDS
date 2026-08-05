# دليل تشغيل اختبارات AI-IDS

## المتطلبات الأولية

```bash
pip install -r requirements.txt
```

---

## 1. تشغيل جميع الاختبارات

```bash
python -m pytest tests/ -v
```

---

## 2. تشغيل اختبارات NFR فقط (المتطلبات غير الوظيفية)

```bash
python -m pytest tests/test_nfr_comprehensive.py -v
```

---

## 3. تشغيل قسم معين من NFR

```bash
# الأداء
python -m pytest tests/test_nfr_comprehensive.py::TestPerformanceNFR -v

# سهولة الاستخدام
python -m pytest tests/test_nfr_comprehensive.py::TestUsabilityNFR -v

# الأمان
python -m pytest tests/test_nfr_comprehensive.py::TestSecurityNFR -v

# قابلية الصيانة
python -m pytest tests/test_nfr_comprehensive.py::TestMaintainabilityNFR -v

# التوافق
python -m pytest tests/test_nfr_comprehensive.py::TestCompatibilityNFR -v

# الاعتمادية
python -m pytest tests/test_nfr_comprehensive.py::TestReliabilityNFR -v

# قابلية الاختبار
python -m pytest tests/test_nfr_comprehensive.py::TestTestabilityNFR -v

# اختبار قبول المستخدم
python -m pytest tests/test_nfr_comprehensive.py::TestUserAcceptanceNFR -v

# قابلية التوسع
python -m pytest tests/test_nfr_comprehensive.py::TestScalabilityNFR -v

# الإتاحية
python -m pytest tests/test_nfr_comprehensive.py::TestAvailabilityNFR -v
```

---

## 4. تشغيل اختبار واحد محدد

```bash
python -m pytest tests/test_nfr_comprehensive.py::TestPerformanceNFR::test_perf_single_detection_latency -v
```

---

## 5. تشغيل اختبارات محددة حسب الملف

```bash
# اختبارات قاعدة البيانات
python -m pytest tests/test_database.py -v

# اختبارات الأمان
python -m pytest tests/test_security.py -v

# اختبارات الطبقةML
python -m pytest tests/test_ml_layer.py -v

# اختبارات الطبقات
python -m pytest tests/test_services_layer.py -v

# اختبارات المستودعات
python -m pytest tests/test_repositories.py -v

# اختبارات Telegram
python -m pytest tests/test_telegram_notifier.py -v

# اختبارات الطبقة الأصلية
python -m pytest tests/test_capture_layer.py -v

# اختبارات تكامل النماذج
python -m pytest tests/test_model_integration.py -v
```

---

## 6. خيارات مفيدة

```bash
# عرض مختصر فقط
python -m pytest tests/ -q

# عرض أخطاء فقط
python -m pytest tests/ --tb=short

# إيقاف عند أول خطأ
python -m pytest tests/ -x

# تشغيل اختبارات تحمل كلمة مفتاحية
python -m pytest tests/ -k "circuit_breaker"

# تشغيل اختبارات تحمل كلمة مفتاحية (استبعاد)
python -m pytest tests/ -k "not slow"
```

---

## هيكل الملفات

```
tests/
├── conftest.py                  # الإعدادات العامة والـ Fixtures
├── test_nfr_comprehensive.py    # 68 اختبار — المتطلبات غير الوظيفية (10 أقسام)
├── test_model_integration.py    # 29 اختبار — تكامل النماذج (RF + XGBoost)
├── test_database.py             # اختبارات قاعدة البيانات
├── test_security.py             # اختبارات الأمان
├── test_ml_layer.py             # اختبارات ML Pipeline
├── test_services_layer.py       # اختبارات الخدمات
├── test_repositories.py         # اختبارات المستودعات
├── test_telegram_notifier.py    # اختبارات Telegram
└── test_capture_layer.py        # اختبارات التقاط الحزم
```

---

## ملخص أقسام NFR (68 اختبار)

| # | القسم | العدد |
|---|---|---|
| 1 | الأداء (Performance) | 10 |
| 2 | سهولة الاستخدام (Usability) | 6 |
| 3 | الأمان (Security) | 8 |
| 4 | قابلية الصيانة (Maintainability) | 7 |
| 5 | التوافق (Compatibility) | 4 |
| 6 | الاعتمادية (Reliability) | 7 |
| 7 | قابلية الاختبار (Testability) | 5 |
| 8 | اختبار قبول المستخدم (UAT) | 7 |
| 9 | قابلية التوسع (Scalability) | 6 |
| 10 | الإتاحية (Availability) | 8 |
| **المجموع** | | **68** |

---

## ملاحظات

- جميع الاختبارات تعزل قاعدة بيانات SQLite مؤقتة — لا تؤثر على البيانات الحقيقية
- اختبارات NFR لا تحتاج اتصال إنترنت (إلا اختبار Circuit Breaker يرسل طلب Telegram فاشل عمداً)
- Credentials الافتراضية: `admin` / `admin`
- للتشغيل كمسؤول (Admin) على Windows: بعض اختبارات PCAP تحتاج صلاحيات عالية
