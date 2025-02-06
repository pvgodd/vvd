from flask import Flask, render_template, request, jsonify, send_file
import subprocess
from fpdf import FPDF
import os

app = Flask(__name__)

# index.html 페이지 렌더링
@app.route('/')
def index():
    return render_template('index.html')

# 공격 카테고리 선택 페이지
@app.route('/select-attack')
def select_attack():
    attacks = [
    	"ALL",
        "Atlassian Confluence",
        "Apache Struts2",
        "Apache OFBiz",
        "Cisco",
        "Citrix Bleed",
        "ProxyShell",
        "ProxyNotShell",
        "ShellShock",
        "VMware"
    ]
    return render_template('select_attack.html', attacks=attacks)

REQUIRED_CMD_ATTACKS = ["Command Injection", "Reverse Shell"]

# 공격 실행 API
@app.route('/run-attack/<attack_type>', methods=['POST'])
def run_attack(attack_type):
    data = request.get_json()
    url = data.get('url')
    cmd = data.get('cmd')

    if not url:
        return jsonify({"error": "URL is required"}), 400
    
    if attack_type in REQUIRED_CMD_ATTACKS and not cmd:
    	return jsonify({"error": f"Command is required for {attack_type}"}), 400
    	
    result = f"Executing attack: {attack_type} on {url} with command: {cmd or 'No Command'}"

    try:
        # 공격 종류에 따라 적합한 스크립트를 선택하여 명령어 실행
        if attack_type == "ALL":
            result = subprocess.run(['python3', 'tools/vvd.py', url], capture_output=True, text=True)
        elif attack_type == "Atlassian Confluence":
            result = subprocess.run(['python3', 'tools/confluence_attack.py', '--url', url, '--cmd', cmd], capture_output=True, text=True)
        elif attack_type == "Apache Struts2":
            result = subprocess.run(['python3', 'tools/struts2_attack.py', '--url', url, '--cmd', cmd], capture_output=True, text=True)
        elif attack_type == "Apache OFBiz":
            result = subprocess.run(['python3', 'tools/ofbiz_attack.py', '--url', url, '--cmd', cmd], capture_output=True, text=True)
        elif attack_type == "Cisco":
            result = subprocess.run(['python3', 'tools/cisco_attack.py', '--url', url, '--cmd', cmd], capture_output=True, text=True)
        elif attack_type == "Citrix Bleed":
            result = subprocess.run(['python3', 'tools/citrix_bleed_attack.py', '--url', url, '--cmd', cmd], capture_output=True, text=True)
        elif attack_type == "ProxyShell":
            result = subprocess.run(['python3', 'tools/proxyshell_attack.py', '--url', url, '--cmd', cmd], capture_output=True, text=True)
        elif attack_type == "ProxyNotShell":
            result = subprocess.run(['python3', 'tools/proxynotshell_attack.py', '--url', url, '--cmd', cmd], capture_output=True, text=True)
        elif attack_type == "ShellShock":
            result = subprocess.run(['python3', 'tools/shellshock_attack.py', '--url', url, '--cmd', cmd], capture_output=True, text=True)
        elif attack_type == "VMware":
            result = subprocess.run(['python3', 'tools/vmware_attack.py', '--url', url, '--cmd', cmd], capture_output=True, text=True)
        else:
            return jsonify({"error": "Invalid attack type"}), 400

        # 공격 결과를 JSON 응답으로 반환
        result_output = result.stdout if result.returncode == 0 else result.stderr
        return jsonify({"output": result_output})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# PDF 저장 및 다운로드 기능 추가
@app.route('/download-pdf', methods=['POST'])
def download_pdf():
    data = request.get_json()
    output_content = data.get('output')

    if not output_content:
        return jsonify({"error": "No content to save"}), 400

    # PDF 생성
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.multi_cell(0, 10, output_content)

    pdf_file = 'attack_result.pdf'
    pdf.output(pdf_file)

    # PDF 파일 다운로드 응답
    return send_file(pdf_file, as_attachment=True)

# 서버 실행
if __name__ == '__main__':
    app.run( port=80, debug= True, host = '0.0.0.0')
