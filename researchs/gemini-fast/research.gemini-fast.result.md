# Research Result for gemini-fast

SecOps-RSS-Crawler-Classifier: Akıllı Siber Tehdit İstihbaratı Toplama, Sınıflandırma ve Analiz Sistemi
Bu rapor, siber güvenlik dünyasındaki gelişmeleri (zafiyetler, exploitler ve haberler) RSS kaynaklarından toplayan, doğal dil işleme (NLP) ile sınıflandıran ve risk tabanlı puanlama algoritmalarıyla önceliklendiren bir sistemin teknik mimarisini ve uygulama standartlarını incelemektedir.

1. Temel Çalışma Prensipleri
Sistemin operasyonel döngüsü; veri toplama (ingestion), işleme (normalization), analiz (classification) ve puanlama (scoring) aşamalarından oluşan bir boru hattı (pipeline) mimarisine dayanmaktadır.

Veri Toplama (RSS Parsing): NVD (National Vulnerability Database), Exploit-DB ve CISA gibi kritik kaynakların RSS/Atom beslemeleri XML formatında çekilir. Modern sistemler, ham XML verisini daha esnek olan JSON formatına dönüştürerek işleme koyar.   

Doğal Dil İşleme (NLP) ve Sınıflandırma: Toplanan metinler; tokenizasyon, kök bulma (lemmatization) ve stop-word temizliği gibi ön işleme aşamalarından geçer. Sınıflandırma için TF-IDF gibi istatistiksel yöntemlerin yanı sıra ModernBERT veya BERTopic gibi derin öğrenme modelleri kullanılarak haberler; "Web", "Network", "Ransomware" gibi kategorilere veya MITRE ATT&CK taktiklerine otomatik olarak eşlenir.   

Dinamik Puanlama ve Önceliklendirme: Sadece teknik şiddete (CVSS) bakmak yerine, olasılık temelli EPSS (Exploit Prediction Scoring System) ve aktif istismar verisi (CISA KEV) birleştirilerek eyleme dönüştürülebilir bir risk skoru hesaplanır.

Çapraz Referans ve Doğrulama: Aynı olayın farklı kaynaklardan (örneğin hem NVD hem de bir güvenlik blogu) raporlanması, bilginin güven skoru (confidence score) değerini artırır. Benzer metinlerin tespiti için Jaccard benzerliği veya "fuzzy hashing" algoritmaları kullanılır.   

2. En İyi Uygulama Yöntemleri ve Endüstri Standartları
Sistemin sürdürülebilirliği ve doğruluğu için aşağıdaki standartların takibi kritik önemdedir:

Veri Standartları (STIX/TAXII): Tehdit istihbaratının paylaşımı ve depolanması için STIX 2.1 (Structured Threat Information Expression) formatı kullanılmalıdır. Bu, verinin OpenCTI veya MISP gibi diğer platformlarla uyumlu olmasını sağlar.

Zafiyet Zenginleştirme (Vulnerability Enrichment): NVD API 2.0 kullanımı, zafiyetleri CPE (Common Platform Enumeration) verileriyle eşleştirerek hangi ürünlerin etkilendiğini otomatik belirlemek için endüstri standardıdır.   

Hibrit Puanlama Modeli: En iyi uygulama, zafiyet önceliklendirmesinde aşağıdaki mantıksal zinciri kullanmaktır:

(KEV∨(EPSS≥0.088))∧(CVSS≥7.0)
Bu yaklaşım, hem teknik olarak kritik hem de gerçekten istismar edilme olasılığı yüksek olan zafiyetlere odaklanılmasını sağlar.   

Otomatik Etiketleme: Haberlerin MITRE ATT&CK matrisindeki tekniklerle (TTP) eşleştirilmesi, savunma ekiplerinin saldırgan davranışlarını daha iyi anlamasına yardımcı olur.   

3. Benzer Açık Kaynak Projeler ve Rakipler
Proje / Platform	Tür	Öne Çıkan Özellikler
OpenCTI	Platform	
STIX 2.1 tabanlı, güçlü görselleştirme ve RSS konnektörleri.

MISP	Platform	Geniş topluluk desteği, 50+ varsayılan besleme (feed) ve IoC paylaşımı.
GlobalCVE	Araç	
KEV ve GitHub verileriyle zenginleştirilmiş hızlı CVE arama motoru.

Feedly for TI	Ticari	
1000'den fazla AI modeli ile haberleri otomatik IOC ve TTP'lere ayırma.

SOCFeed	Araç	
AI destekli siber güvenlik haber toplayıcısı.

  
4. Kritik Yapılandırma Dosyaları ve Parametreleri
Sistemin omurgasını oluşturan bileşenlerin yapılandırılmasında şu parametreler kritiktir:

NVD API Yapılandırması: resultsPerPage (maksimum 2000 önerilir) ve lastModStartDate/lastModEndDate parametreleri, API hız sınırlarına (rate limiting) takılmadan sadece güncel veriyi çekmek için kullanılır.   

MISP Besleme Ayarları (defaults.json): enabled ve caching_enabled parametreleri, verinin Redis üzerinde önbelleğe alınarak korelasyon analizinde kullanılmasını sağlar.   

OpenCTI Konnektör Parametreleri: IMPORT_FROM_DATE (geçmişe dönük veri sınırı), CONFIDENCE_LEVEL (varsayılan güven puanı) ve CONNECTOR_SCOPE (işlenecek veri türleri).   

NLP Model Parametreleri: Transformer modellerinde max_length (genellikle 512 token) ve sliding_window ayarları, uzun haber metinlerinin bağlam kaybı olmadan işlenmesini sağlar.   

5. Güvenlik Açısından Kritik Noktalar
Sistemin dış kaynaklardan veri alıyor olması, onu doğrudan saldırı hedefi haline getirir:

XML İşleme Riskleri (XXE): RSS beslemeleri XML tabanlıdır. Kötü niyetli bir kaynak, sistemin yerel dosyalarını (/etc/passwd vb.) okumasına neden olan XXE (XML External Entity) saldırısı gerçekleştirebilir.

Çözüm: XML parser yapılandırmasında DTD (Document Type Definition) işleme tamamen kapatılmalı veya defusedxml gibi güvenli kütüphaneler kullanılmalıdır.

Sunucu Tarafı İstek Sahteciliği (SSRF): Crawler, kullanıcıdan veya dış kaynaktan gelen bir URL'ye gitmek zorundadır. Saldırgan, sistemi iç ağdaki hassas servislere (bulut metadata servisleri gibi) istek atmaya zorlayabilir.

Çözüm: Sıkı bir "beyaz liste" (allowlist) uygulanmalı ve loopback (127.0.0.1) ile özel IP bloklarına erişim engellenmelidir.

Veri Zehirlenmesi ve Yanlış Pozitifler: Saldırganlar, sistemin önceliklendirme algoritmasını manipüle etmek için sahte haberler veya çok sayıda düşük kaliteli rapor üreterek "CVE farming" yapabilir.

Çözüm: Kaynakların itibar puanı (source reputation) tutulmalı ve güven skoru eşik değerleri (thresholds) uygulanmalıdır.   


