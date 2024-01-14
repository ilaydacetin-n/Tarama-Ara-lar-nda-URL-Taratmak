# risk_puanlama.py

from urlscan_kod import scan_url_urlscan
from virustotal_kod import scan_url_virustotal

def custom_scoring_algorithm(urlscan_result, virustotal_result):
    # Burada kendi puanlama algoritmanızı oluşturun
    urlscan_total_scans, urlscan_threats_detected = urlscan_result
    virustotal_total_scans, virustotal_threats_detected = virustotal_result

    # Örnek bir puanlama algoritması
    urlscan_score = urlscan_threats_detected / urlscan_total_scans * 100
    virustotal_score = virustotal_threats_detected / virustotal_total_scans * 100

    
    final_score = 0.3 * urlscan_score + 0.8 * virustotal_score

    # Örnek bir algoritma kullanıldığı için final_score doğrudan virustotal_score olarak atanıyor
   # final_score = irustotal_score

    return final_score

def calculate_risk_score(final_score):
    # Risk skorunu hesapla
    # Örnek bir hesaplama, final_score'un belirli bir eşik değerinden büyük olup olmadığını kontrol eder
    # ve buna göre bir risk düzeyi belirler.
    threshold = 50
    if final_score >= threshold:
        return "Yüksek Risk"
    else:
        return "Düşük Risk"

def main():
    # Kullanıcıdan URL al
    scan_url = input("Taramak istediğiniz URL'yi girin: ")

    # API anahtarlarınızı ayarlayın
    api_key_urlscan = '760d366a-6c97-4387-828e-391981dfa317'
    api_key_virustotal = '9e3482269ae4dccf9230ebf84a5571da222e846263dbb45b0ad0f50bcd5c58b9'

    # Tarama sonuçlarını alın
    urlscan_result = scan_url_urlscan(scan_url, api_key_urlscan)
    virustotal_result = scan_url_virustotal(api_key_virustotal, scan_url)

    # Puanlama algoritmasını kullanarak puanı al
    final_score = custom_scoring_algorithm(urlscan_result, virustotal_result)

    # Risk skorunu hesapla
    risk_score = calculate_risk_score(final_score)

    # Sonuçları yazdır
    if final_score is not None:
        print(f"Toplam Tarama Sayısı (URLScan.io): {urlscan_result[0]}, Tehdit Algılanan Tarama Sayısı: {urlscan_result[1]}")
        print(f"Toplam Tarama Sayısı (VirusTotal): {virustotal_result[0]}, Tehdit Algılanan Tarama Sayısı: {virustotal_result[1]}")
        print(f"Final Puan: {final_score}")
        print(f"Risk Skoru: {risk_score}")
    else:
        print("Tarama sonuçları alınamadı.")

if __name__ == "__main__":
    main()
