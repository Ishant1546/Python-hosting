import subprocess
import psutil
import time
import json
import os
from threading import Thread

class DashboardManager:
    def __init__(self):
        self.dashboards = {}
        self.config_file = 'dashboard_config.json'
        self.load_config()
    
    def load_config(self):
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                self.dashboards = json.load(f)
    
    def save_config(self):
        with open(self.config_file, 'w') as f:
            json.dump(self.dashboards, f, indent=2)
    
    def start_dashboard(self, script_id, script_name, port, script_file):
        """Start an individual dashboard for a script"""
        dashboard_code = f'''
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import subprocess
import threading
import time
import os
import json
import sys

app = Flask(__name__)
app.config["SECRET_KEY"] = "dashboard-secret-{script_id}"
socketio = SocketIO(app, cors_allowed_origins="*")

SCRIPT_FILE = "{script_file}"
SCRIPT_NAME = "{script_name}"
SCRIPT_ID = "{script_id}"
LOG_FILE = "logs/{script_id}.log"

script_process = None
is_running = False
logs = []

def run_script():
    global script_process, is_running, logs
    is_running = True
    
    # Clear old log file
    open(LOG_FILE, 'w').close()
    
    script_process = subprocess.Popen(
        [sys.executable, SCRIPT_FILE],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        universal_newlines=True
    )
    
    # Stream output to log file and websocket
    for line in iter(script_process.stdout.readline, ''):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{{timestamp}}] {{line}}"
        
        # Save to log file
        with open(LOG_FILE, 'a') as f:
            f.write(log_entry)
        
        # Send to connected clients
        socketio.emit('log_update', {{'log': log_entry}})
        
        # Keep in memory (last 1000 lines)
        logs.append(log_entry)
        if len(logs) > 1000:
            logs.pop(0)
    
    is_running = False
    script_process = None

@app.route('/')
def dashboard():
    return render_template('script_dashboard.html', 
                         script_name=SCRIPT_NAME,
                         script_id=SCRIPT_ID,
                         port={port})

@app.route('/api/status')
def get_status():
    return jsonify({{
        'name': SCRIPT_NAME,
        'id': SCRIPT_ID,
        'is_running': is_running,
        'pid': script_process.pid if script_process else None
    }})

@app.route('/api/start', methods=['POST'])
def start_script():
    global script_process
    if not is_running:
        thread = threading.Thread(target=run_script)
        thread.daemon = True
        thread.start()
        return jsonify({{'status': 'starting'}})
    return jsonify({{'status': 'already_running'}})

@app.route('/api/stop', methods=['POST'])
def stop_script():
    global script_process, is_running
    if script_process and is_running:
        script_process.terminate()
        try:
            script_process.wait(timeout=5)
        except:
            script_process.kill()
        is_running = False
        script_process = None
        return jsonify({{'status': 'stopped'}})
    return jsonify({{'status': 'not_running'}})

@app.route('/api/logs')
def get_logs():
    # Return last 100 lines from memory
    return jsonify({{'logs': logs[-100:]}})

@app.route('/api/clear_logs', methods=['POST'])
def clear_logs():
    global logs
    logs = []
    open(LOG_FILE, 'w').close()
    return jsonify({{'status': 'cleared'}})

@socketio.on('connect')
def handle_connect():
    emit('connected', {{'script': SCRIPT_NAME}})

@socketio.on('get_logs')
def handle_get_logs():
    emit('logs_data', {{'logs': logs[-100:]}})

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port={port}, debug=False)
'''
        
        # Create dashboard file
        dashboard_file = f"script_dashboards/{script_id}_dashboard.py"
        with open(dashboard_file, 'w') as f:
            f.write(dashboard_code)
        
        # Start the dashboard
        process = subprocess.Popen(
            ['python', dashboard_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Store process info
        self.dashboards[script_id] = {
            'pid': process.pid,
            'port': port,
            'started': time.time(),
            'status': 'running'
        }
        
        self.save_config()
        return process.pid
    
    def stop_dashboard(self, script_id):
        """Stop a specific dashboard"""
        if script_id in self.dashboards:
            try:
                pid = self.dashboards[script_id]['pid']
                process = psutil.Process(pid)
                process.terminate()
                self.dashboards[script_id]['status'] = 'stopped'
                self.save_config()
                return True
            except:
                pass
        return False
    
    def get_status(self):
        """Get status of all dashboards"""
        status = {}
        for script_id, info in self.dashboards.items():
            try:
                process = psutil.Process(info['pid'])
                info['cpu'] = process.cpu_percent()
                info['memory_mb'] = process.memory_info().rss / 1024 / 1024
                info['alive'] = True
            except:
                info['alive'] = False
            status[script_id] = info
        return status