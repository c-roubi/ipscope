# IPScope v0.9

أداة Reverse IP Lookup: بتدخلها IP أو نطاق أو دومين، وبترجعلك الدومينات المستضافة عليه من 8 مصادر.

## التثبيت (Windows / Linux / macOS)

لازم Python 3.10 أو أحدث.

```bash
cd ipscope
pip install -e .
```

## الواجهة الرسومية (Desktop)

```bash
pip install -e .[gui]
ipscope-gui          # أو: ipscope gui
```

واجهة داكنة بتصميم macOS، مبنية بـ pywebview، وفيها:

| الصفحة | شو فيها |
|---|---|
| **Scan** | إدخال الأهداف أو استيرادها من ملف، اختيار المصادر والخيارات، تقدم مباشر، وسجل حي |
| **Results** | قائمة الـ IPs مع المزود ونوع الاستضافة، فلترة حسب الحالة، بحث بالدومين أو العنوان أو التقنية، تجميع حسب الدومين الرئيسي، نسخ، فتح بالمتصفح، وتصدير |
| **History** | كل الفحوصات، مع إكمال الموقوف وفتحه وحذفه |
| **API Keys** | إضافة المفاتيح وحذفها، والمصادر بتتفعل تلقائياً بعد إضافة المفتاح |
| **Settings** | الإعدادات الافتراضية، والكاش، ومجلد البيانات |

الفحص بيشتغل بالخلفية. زر Stop بيوقفه، وبتقدر تكمله بعدين من History، والواجهة والـ CLI بيشاركوا نفس قاعدة البيانات.

## نسخة ويندوز (.exe)

البناء بيطلّع مجلد `IPScope` فيه برنامجين بيتشاركوا نفس الملفات:
- **`IPScope.exe`**: الواجهة الرسومية، بدون نافذة أوامر
- **`ipscope.exe`**: سطر الأوامر

وبيطلّع كمان مثبّت `IPScope-Setup-x.y.z.exe`. المثبّت بيعمل اختصارات بقائمة ابدأ وسطح المكتب، وفيه خيار يضيف `ipscope` للـ PATH، وبيفحص إذا WebView2 موجود على الجهاز.

### الطريقة 1: على جهاز ويندوز

1. ثبّت Python 3.10 أو أحدث من python.org، وعلّم على **Add to PATH** وقت التثبيت.
2. إذا بدك المثبّت كمان، ثبّت Inno Setup 6.
3. شغّل:
   ```bat
   packaging\build.bat
   ```

النتيجة بتطلع بـ `dist\IPScope\` (البرنامج) و `dist\installer\` (المثبّت).

### الطريقة 2: GitHub Actions (بدون ما تثبّت أي شي)

1. ارفع المشروع على مستودع GitHub.
2. من تبويب **Actions**، اختار **Build Windows** واضغط **Run workflow**.
3. لما يخلص، بتلاقي تحت **Artifacts** المثبّت ونسخة portable بملف zip.

وإذا رفعت tag، مثلاً `git tag v0.9.0 && git push --tags`، بينشر الملفات كـ Release.

### ملاحظات

- **WebView2:** الواجهة بتحتاج Microsoft Edge WebView2 Runtime. هو موجود على ويندوز 11 وعلى ويندوز 10 المحدّث.
- **الأنتي فايروس:** البرامج المبنية بـ PyInstaller أحياناً بيعلّم عليها الأنتي فايروس بالغلط. خففت هالشي بإني ما استخدمت UPX وضفت معلومات الإصدار للملف. الحل الكامل هو **توقيع الملف بشهادة Code Signing**، خصوصاً إذا بدك توزعه.
- **أخطاء التشغيل:** إذا الواجهة ما فتحت، تفاصيل الخطأ بتنحفظ بـ `%USERPROFILE%\.ipscope\gui-error.log`.

## تجهيز قائمة IPs عليها مواقع كثيرة

```bash
ipscope scan AS47583 --max-hosts 2048 --preset fast --label hostinger   # Hostinger
ipscope scan AS22612 --max-hosts 2048 --preset fast --label namecheap   # Namecheap
ipscope top -n 100 --min-domains 200 -o busy_ips.txt                    # أعلى 100 IP، بدون CDN
```

## الاستخدام السريع (CLI)

```bash
ipscope scan 8.8.8.8                          # IP واحد
ipscope scan 1.2.3.0/28                       # نطاق CIDR
ipscope scan example.com                      # دومين (بيحوله لـ IP أول)
ipscope scan AS24940 --max-hosts 4096         # كل نطاقات ASN
ipscope scan -f ips.txt -o results.csv        # من ملف، وحفظ CSV
ipscope scan 8.8.8.8 -V                       # تأكد مين لسا على نفس الـ IP
ipscope scan 8.8.8.8 --only-active -o live.txt
ipscope scan 8.8.8.8 --active                 # يقرأ شهادة TLS من السيرفر
ipscope scan -f ips.txt -q > domains.txt      # دومينات بس
```

## معلومات الـ IP وكشف الـ CDN

كل IP بينعرف تلقائياً شو الـ ASN تبعه ومين مزوده، عبر Team Cymru DNS. هاد مجاني وبدون مفتاح، ولو بدك توقفه استخدم `--no-ip-info`. وبيتصنف لنوع من هدول:

| النوع | المعنى |
|---|---|
| `cdn-edge` | الـ IP تابع لـ CDN (Cloudflare، Akamai، Fastly، Imperva…). النتائج مواقع ما إلها علاقة ببعض، والسيرفر الحقيقي مخفي |
| `shared` | 50 دومين أو أكثر: استضافة مشتركة |
| `multi-site` | من 5 لـ 49 دومين |
| `single-site` | من 1 لـ 4 دومينات |

الأداة بتطلع تحذير واضح لما يكون الـ IP تابع لـ CDN.

## إدخال ASN

`ipscope scan AS13335` بيجيب كل نطاقات الـ IPv4 المعلنة للـ ASN من RIPEstat. هاد كمان مجاني وبدون مفتاح.
- الحد الكلي بيتحكم فيه `--max-hosts`، والنطاقات الأصغر بتنفحص أول.
- نطاقات IPv6 بتنتخطى لأنها كبيرة كثير.

## فحص المواقع (`--probe`)

```bash
ipscope scan 5.9.10.10 -V --probe -o report.csv
```

لكل دومين بيجيب: كود الـ HTTP، والرابط النهائي بعد التحويلات، وعنوان الصفحة (بيدعم العربي)، والـ Server، والتقنيات المستخدمة.
- **التقنيات:** بيكشف حوالي 40 تقنية، مثل WordPress و Laravel و Next.js و Shopify و Cloudflare و nginx… ومع `-V` بيفحص بس الدومينات الـ active.
- **الحد:** `--probe-limit 200` لكل IP، والأعلى ثقة بينفحص أول.
- **ملاحظة:** هاد **فحص active**، يعني بيتصل بالمواقع نفسها.

## طرق مجانية بدون أي API

### 1. التواصل مع السيرفر مباشرة (`--active`)

```bash
ipscope scan 5.9.10.10 --active
```

- **`tls`:** بيقرأ شهادات TLS من 10 بورتات بنفس الوقت:
  - الويب: 443، 8443
  - cPanel و WHM و Webmail: 2083، 2087، 2096
  - الإيميل: 465، 993، 995
  - SMTP مع STARTTLS: 25، 587، ومنه كمان بيقرأ اسم السيرفر من رسالة الترحيب
- **`http`:** بيطلب `http(s)://IP` مباشرة، وبيلتقط التحويلات (redirect) وروابط `canonical` و `og:url`.
- **الشهادات الافتراضية** (`localhost.localdomain`، `default.domain`، Traefik، Kubernetes…) بتنفلتر تلقائياً.

هاي الطريقة ممتازة للسيرفرات اللي عليها موقع واحد أو كم موقع. بس على الاستضافة المشتركة بتكشف الموقع الافتراضي بس.

### 2. فهرس محلي خاص فيك (`local`)

```bash
ipscope index build domains.txt            # استيراد + resolve
ipscope index add com.zone.gz              # ملف zone (مثلاً من ICANN CZDS)
ipscope index add fdns_a.json.gz --only 5.9.0.0/16 --only 51.75.0.0/16   # Rapid7 FDNS، نطاقاتك بس
ipscope index resolve                      # بيكمل من وين وقف (Ctrl+C آمن)
ipscope index resolve --retry-failed       # بيعيد اللي فشلوا
ipscope index resolve --refresh-days 30    # بيحدّث الأسماء القديمة
ipscope index stats
ipscope index lookup 5.9.10.10
```

بعد ما تبني الفهرس، مصدر `local` بيتفعل تلقائياً ببداية كل فحص. بيرد فوراً، بدون إنترنت، وبدون حدود. ومن الواجهة الرسومية، صفحة **Local index** بتعمل نفس الشي.

أرقام مقاسة (مع DNS وهمي بيرد بعد 50ms):

| العملية | السرعة |
|---|---|
| استيراد مليون دومين | 5.9 ثانية |
| استيراد مليون سجل Rapid7 FDNS | 9.5 ثانية (بدون resolve) |
| Resolve | ~8,900 اسم/ثانية، يعني مليون اسم بحوالي دقيقتين |
| البحث بالفهرس | ~136,000 IP/ثانية |
| حجم الفهرس | ~232 MB لكل 2 مليون اسم |

> ملف Rapid7 الكامل (fdns_a) حجمه أكثر من 30 GB مضغوط. استخدم `--only` بنطاقاتك حتى يضل الفهرس صغير.

## الأداء مع عشرات آلاف الـ IPs

أرقام مقاسة بمصادر وهمية بترد فوراً، حتى تبيّن سرعة الأداة نفسها بدون الـ APIs:

| الحالة | النتيجة |
|---|---|
| 50,000 IP (250 ألف دومين) | 18.7 ثانية، والذاكرة ثابتة ~95 MB |
| 2,000 IP على استضافة مشتركة (600 ألف دومين) | 26.6 ثانية، والذاكرة ~108 MB |
| التحقق من الـ DNS (`-V`) | ~3,800 دومين/ثانية (كان 119) |
| فتح 600 ألف دومين بالواجهة | أقل من ثانية. البحث والتنقل بين الصفحات من 0.1 لـ 1.5 ثانية |
| تصدير CSV لـ 600 ألف سطر | 3.5 ثانية، بدون ما تزيد الذاكرة |

كيف صارت هيك:
- **التخزين:** كل دومين بيتخزن كسطر بقاعدة البيانات. الواجهة والـ CLI والتصدير بيقرأوا منها صفحة صفحة، أو بشكل متدفق (stream).
- **التحقق من الـ DNS:** بيستخدم dnspython async، 200 استعلام بنفس الوقت، مع كاش، وإذا الدومين بيظهر على أكثر من IP بينسأل عنه مرة وحدة بس. إذا الاستعلام فشل (timeout)، الدومين بيتصنف `unknown` مش `dead`.
- **المصدر اللي حصته بتخلص أو مفاتيحه كلها بتنرفض** بيتوقف لباقي الفحص بدل ما يفشل مع كل IP. وإذا كل المصادر توقفت، الفحص بيوقف ومنقدر نكمله بعدين.
- **الـ CLI مع الفحوصات الكبيرة** بيعرض ملخص وأعلى الـ IPs بس، والنتائج الكاملة بتطلع بـ `-o` أو `-q`.

**ملاحظة:** السرعة الحقيقية بتعتمد على حدود الـ APIs. بالمصادر المجانية (1 طلب/ثانية)، 50 ألف IP بياخدوا حوالي 14 ساعة.

## الدومينات الرئيسية والثقة

- `--roots` بيجمع النتائج حسب الدومين الرئيسي، مثل `shop.example.co.uk` → `example.co.uk`. بيعتمد على Public Suffix List، وبيشتغل بدون إنترنت.
- **الثقة (0-100):** بتعتمد على عدد المصادر اللي أكدت الدومين، وحالته بالـ DNS.
  - مصدر واحد = 40، مصدرين = 65، ثلاثة أو أكثر = 85
  - active بيزيد 15، historical بينقص 15، dead بينقص 30

```bash
ipscope scan 5.9.10.10 --roots -q > roots.txt
```

## التوقيف والإكمال

كل IP بيخلص فحصه بينحفظ فوراً بقاعدة البيانات.

```bash
ipscope scan -f big_list.txt --label "client-x"   # اضغط Ctrl+C بأي وقت
ipscope resume                                    # بيكمل آخر فحص ما خلص
ipscope resume 7                                  # أو فحص معين
ipscope history                                   # كل الفحوصات
ipscope show 7 -o report.json                     # تصدير فحص قديم
ipscope delete 7
```

إذا انطفى الجهاز أو كرش البرنامج، `resume` بيكمل كمان.

## الكاش

نتيجة كل مصدر لكل IP بتنحفظ 24 ساعة، فإعادة الفحص ما بتصرف من حدود الـ API.

```bash
ipscope scan 8.8.8.8 --cache-ttl 72      # مدة الكاش بالساعات
ipscope scan 8.8.8.8 --no-cache          # تجاهل الكاش
ipscope cache stats
ipscope cache clear --older-than 168
```

الأخطاء ما بتنحفظ بالكاش، فالطلب الفاشل بيتعاد بالمرة الجاية.

## مفاتيح الـ API

```bash
ipscope keys set virustotal                # بيطلب المفتاح مخفي
ipscope keys set virustotal KEY2 --add     # مفتاح إضافي للتدوير
ipscope keys list                          # بيعرضهم مقنّعين: abcd…1234
ipscope keys delete shodan
```

- **التخزين:** بـ Windows Credential Manager أو macOS Keychain. إذا ما في keyring بالنظام، بتنحفظ بـ `~/.ipscope/keys.json` بصلاحيات للمالك بس.
- **متغيرات البيئة** بتغلب على المخزّن، مثل `IPSCOPE_VIRUSTOTAL_KEY=k1,k2`.
- **التدوير:** إذا مفتاح انرفض (401/403)، أو انتهت حصته (429، أو "API count exceeded" بـ HackerTarget)، الأداة بتنتقل للمفتاح اللي بعده تلقائياً.
- **المصادر اللي بتحتاج مفتاح** بتنضاف للفحص تلقائياً لما تحطلها مفتاح، وبدونه بتنتخطى مع تنبيه.

## المصادر

| المصدر | المفتاح | ملاحظات |
|---|---|---|
| `local` | - | فهرسك المحلي: فوري وبدون حدود (`ipscope index build`) |
| `dnsrift` | اختياري | DNSRift API، مجاني بدون مفتاح |
| `thc` | - | ip.thc.org، مجاني بدون مفتاح، قاعدة بيانات ضخمة. حده حوالي 0.5 طلب/ثانية |
| `hackertarget` | اختياري | المجاني 20 استعلام باليوم |
| `otx` | اختياري | AlienVault passive DNS، وفيه تاريخ first/last seen |
| `internetdb` | - | Shodan InternetDB، مجاني |
| `ptr` | - | Reverse DNS |
| `webscan` | - | webscan.cc، مجاني بس ما إله توثيق رسمي. **مش مفعّل افتراضياً** |
| `virustotal` | **لازم** | passive DNS، المجاني 4 طلبات/دقيقة |
| `securitytrails` | **لازم** | |
| `shodan` | **لازم** | |
| `rapiddns` | **لازم** | الـ API الرسمي، بده عضوية Pro |
| `networksdb` | **لازم** | الـ API الرسمي، المفتاح المجاني 1,000 طلب بالشهر |
| `tls` / `http` | - | **active**: بيتصلوا بالسيرفر نفسه (`--active`) |

### الأوضاع الجاهزة (Presets)

```bash
ipscope scan -f ips.txt --preset fast      # أسرع المصادر الكبيرة بس
ipscope scan -f ips.txt --preset free      # كل المصادر المجانية الـ passive
ipscope scan -f ips.txt --preset full      # كل اللي مجهّز عندك، ومعه tls و http
ipscope scan -f ips.txt --preset offline   # الفهرس المحلي بس، بدون شبكة
```

ونفس الأوضاع موجودة كأزرار فوق قائمة المصادر بالواجهة الرسومية.

## خيارات السرعة والعرض

| الخيار | بالواجهة (Settings) | بالـ CLI |
|---|---|---|
| حفظ الدومين الرئيسي بس | Save root domains only | `--roots-only` |
| الوقوف عند أول مصدر بيلاقي نتائج | Stop at the first match | `--first-hit` |
| تخطي الـ IPs اللي انفحصت قبل | Skip IPs scanned before | `--skip-scanned` |
| إخفاء أسماء المصادر (لتصوير الشاشة) | Hide source names | - |

- **حفظ الدومين الرئيسي:** الدومين الرئيسي بياخد أفضل حالة من فروعه. يعني إذا `shop.example.com` شغال على الـ IP، بيتسجل `example.com` كـ active.
- **إخفاء المصادر:** بيشيل أسماء المصادر من صفحة الفحص والنتائج والسجل والقائمة الجانبية وملفات التصدير. اختيار المصادر نفسه صار بصفحة Settings، وصفحة الفحص فيها أزرار الأوضاع بس.

## الدومينات الفرعية (Subdomains)

```bash
ipscope subdomains example.com                 # من local و dnsrift و thc و otx و crt.sh و rapiddns
ipscope subdomains example.com -V -o subs.csv  # مع resolve: مين شغال وعلى أي IP
ipscope subdomains -f domains.txt -q > all.txt
```

هاد بحث passive بالكامل، يعني ما في ولا طلب بيوصل للدومين المستهدف نفسه.

كل مصدر إله rate limit خاص فيه، وبيعيد المحاولة مع انتظار بيزيد كل مرة.

## حالات الدومين (مع `-V`)

- **active**: لسا بيشاور على نفس الـ IP
- **historical**: كان عليه وانتقل
- **dead**: ما إله سجل DNS

## التصدير

الصيغة بتنحدد من امتداد الملف:
- `.txt`: دومينات بس
- `.csv`: بيفتح بـ Excel مباشرة. فيه ASN والمزود ونوع الاستضافة والدومين الرئيسي والثقة، ونتائج الـ probe
- `.json`: كامل مع الأخطاء

## البيانات والبروكسي

- كل شي بـ `~/.ipscope/` (قاعدة البيانات `ipscope.db`). تقدر تغيرها بـ `--home PATH` أو `IPSCOPE_HOME`.
- البروكسي: الأداة بتحترم `HTTPS_PROXY` و `HTTP_PROXY`.

## إضافة مصدر جديد

```python
# ipscope/sources/mysource.py
class MySource(Source):
    name = "mysource"
    rate = 1.0                        # طلبات بالثانية
    key_env = "IPSCOPE_MYSOURCE_KEY"
    requires_key = True

    def _auth(self, key):             # (params, headers) لكل طلب
        return {}, {"X-Key": key}

    async def _lookup(self, ip):
        data = await self._fetch(f"https://api.example/{ip}", as_json=True)
        return [DomainRecord(d, self.name) for d in (data or {}).get("domains", [])]
```

بعدين ضيفه لـ `REGISTRY` بـ `ipscope/sources/__init__.py`. الـ retry والتدوير والكاش بيشتغلوا لحالهم.

## الاختبارات

```bash
pip install pytest
pytest -q
```

الاختبارات ما بتلمس الـ keyring الحقيقي تبع جهازك.

## ملاحظة

استخدمها فقط على أهداف عندك إذن تفحصها، والتزم بشروط استخدام كل API.
