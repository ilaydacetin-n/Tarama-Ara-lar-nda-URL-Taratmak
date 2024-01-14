# urlscan_kod.py

import requests
import time

def get_scan_results_urlscan(api_key, uuid):
    url = f'https://urlscan.io/api/v1/result/{uuid}/'
    headers = {'API-Key': api_key}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        result = response.json()
        engines = result.get('verdicts', {}).get('engines', [])
        threats_detected = 0
        for engine in engines:
            if isinstance(engine, dict) and engine.get('malicious', False):
                threats_detected += 1
        total_scans = len(engines)
        return total_scans, threats_detected
    else:
        return None

def scan_url_urlscan(scan_url, api_key):
    url = 'https://urlscan.io/api/v1/scan/'
    headers = {'API-Key': api_key}
    data = {'url': scan_url}
    response = requests.post(url, headers=headers, json=data)

    if response.status_code == 200:
        result = response.json()
        if 'message' in result and result['message'] == 'Submission successful':
            uuid = result['uuid']
            time.sleep(10)  
            return get_scan_results_urlscan(api_key, uuid)
        else:
            return None
    else:
        return None
