"""
-----------------------------------------------------------------------------
FILE     : port_scanner_v1.py
VERSION  : Nosrat.Jahan.3.3.3 [Security Suite]
DEV      : Nosrat Jahan
ACADEMIC : BSc in Computer Science & Engineering
-----------------------------------------------------------------------------
"""

from flask import Flask, render_template_string, request, jsonify
import socket
import threading
import webbrowser

app = Flask(__name__)

# Core Scan Logic
open_ports = []
def scan_port(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        if s.connect_ex((target, port)) == 0:
            open_ports.append(port)
        s.close()
    except:
        pass

# UI Design with Dual Mode (Black & Light Gray)
UI_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Port-Scanner-Shield | Nosrat Jahan</title>
    <style>
        :root {
            --bg: #0a0a0c;
            --panel: #141417;
            --accent: #00ff41;
            --text: #e0e0e0;
            --terminal-bg: #000;
        }

        .gray-mode {
            --bg: #f1f2f6;
            --panel: #ffffff;
            --accent: #2ed573;
            --text: #2f3542;
            --terminal-bg: #f8f9fa;
        }

        body {
            background-color: var(--bg);
            color: var(--text);
            font-family: 'Courier New', monospace;
            margin: 0; padding: 0;
            display: flex; flex-direction: column; align-items: center;
            transition: 0.3s;
        }

        header {
            width: 100%;
            background: var(--panel);
            padding: 25px;
            text-align: center;
            border-bottom: 3px solid var(--accent);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }

        .container {
            width: 90%; max-width: 800px;
            margin-top: 40px;
            background: var(--panel);
            padding: 35px;
            border-radius: 12px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.3);
        }

        .controls {
            display: flex; gap: 10px; margin-bottom: 25px;
        }

        input {
            flex: 1;
            background: var(--terminal-bg);
            border: 1px solid var(--accent);
            padding: 12px;
            color: var(--accent);
            border-radius: 6px;
            outline: none;
        }

        button {
            background: var(--accent);
            color: #000;
            border: none;
            padding: 12px 25px;
            font-weight: bold;
            cursor: pointer;
            border-radius: 6px;
            transition: 0.2s;
        }

        button:hover { filter: brightness(1.2); transform: scale(1.02); }

        .terminal-box {
            background: var(--terminal-bg);
            border: 1px solid #333;
            padding: 20px;
            height: 250px;
            overflow-y: auto;
            border-radius: 8px;
            line-height: 1.6;
            font-size: 0.9rem;
        }

        .status-msg { color: var(--accent); }
        
        footer {
            width: 100%;
            text-align: center;
            padding: 25px;
            margin-top: 50px;
            background: var(--panel);
            border-top: 2px solid var(--accent);
            font-weight: bold;
        }
    </style>
</head>
<body onkeydown="handleGlobalEnter(event)">

    <header>
        <h1 style="margin:0; letter-spacing: 3px;">PORT-SCANNER-SHIELD</h1>
        <p style="font-size: 0.8rem; margin-top: 5px; opacity: 0.7;">Version Nosrat.Jahan.3.3.3</p>
        <div style="margin-top: 10px;">
            <button onclick="toggleTheme()" style="padding: 5px 15px; font-size: 0.8rem; background: #57606f; color: #fff;">Switch Black/Gray</button>
        </div>
    </header>

    <div class="container">
        <div class="controls">
            <input type="text" id="ip" placeholder="Target IP (e.g., 127.0.0.1)">
            <button onclick="startScan()">INITIATE SCAN</button>
        </div>

        <div id="status-label" style="margin-bottom: 10px; font-size: 0.8rem;">System Ready...</div>
        <div class="terminal-box" id="terminal">
            [#] Awaiting target IP for vulnerability assessment...
        </div>
    </div>

    <footer>
        Nosrat.Jahan.3.3.3 | Engineered by Nosrat Jahan | BSc in CSE | 2026
    </footer>

    <script>
        function toggleTheme() {
            document.body.classList.toggle('gray-mode');
        }

        function handleGlobalEnter(e) {
            if(e.key === 'Enter') {
                startScan();
            }
        }

        function startScan() {
            const ip = document.getElementById('ip').value;
            const terminal = document.getElementById('terminal');
            const status = document.getElementById('status-label');

            if(!ip) { alert("Please enter a target IP!"); return; }

            terminal.innerHTML = `<span class="status-msg">[!] Accessing target: ${ip}...</span><br>`;
            terminal.innerHTML += `[!] Initializing multi-threaded probe...<br>`;
            status.innerText = "Scanning in progress...";

            fetch('/scan', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({target: ip})
            })
            .then(res => res.json())
            .then(data => {
                if(data.error) {
                    terminal.innerHTML += `<span style="color:red;">[X] Error: ${data.error}</span>`;
                } else {
                    terminal.innerHTML += `[!] Scan completed.<br>`;
                    terminal.innerHTML += `------------------------------------------<br>`;
                    if(data.open_ports.length > 0) {
                        data.open_ports.forEach(port => {
                            terminal.innerHTML += `<span style="color:var(--accent); font-weight:bold;">[+] OPEN PORT FOUND: ${port}</span><br>`;
                        });
                    } else {
                        terminal.innerHTML += `[!] No open ports identified in common range.<br>`;
                    }
                    status.innerText = "Audit Finished.";
                }
            });
        }
    </script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(UI_HTML)

@app.route("/scan", methods=['POST'])
def handle_scan():
    target = request.json.get('target')
    global open_ports
    open_ports = []
    
    try:
        target_ip = socket.gethostbyname(target)
        threads = []
        # Top Cybersecurity Audit Ports
        common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 3306, 3389, 8080]
        
        for port in common_ports:
            t = threading.Thread(target=scan_port, args=(target_ip, port))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
            
        return jsonify({"open_ports": sorted(open_ports)})
    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == "__main__":
    url = "http://127.0.0.1:7070"
    print(f"\\n[!] PORT-SCANNER-SHIELD v3.3.3 ACTIVE")
    print(f"[!] ACCESS LINK: {url}\\n")
    webbrowser.open(url)
    app.run(port=7070, debug=False)
