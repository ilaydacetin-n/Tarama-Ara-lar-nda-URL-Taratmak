# virustotal_kod.py

import requests

def scan_url_virustotal(api_key, scan_url):
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': api_key, 'resource': scan_url}
    response = requests.get(url, params=params)

    if response.status_code == 200:
        result = response.json()
        if result['response_code'] == 1:
            positives = result['positives']
            total = result['total']
            return total, positives
        else:
            return None
    else:
        return None
