from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import subprocess
import threading
import time
import os
import sys

app = Flask(__name__)
app.config["SECRET_KEY"] = "dashboard-secret-script1"
socketio = SocketIO(app, cors_allowed_origins="*")

SCRIPT_FILE = "scripts/script1.py"
SCRIPT_NAME = "Data Processor"
SCRIPT_ID = "script1"
LOG_FILE = "logs/script1.log"

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
        log_entry = f"[{timestamp}] {line}"
        
        # Save to log file
        with open(LOG_FILE, 'a') as f:
            f.write(log_entry)
        
        # Send to connected clients
        socketio.emit('log_update', {'log': log_entry})
        
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
                         port=10001)

@app.route('/api/status')
def get_status():
    return jsonify({
        'name': SCRIPT_NAME,
        'id': SCRIPT_ID,
        'is_running': is_running,
        'pid': script_process.pid if script_process else None
    })

@app.route('/api/start', methods=['POST'])
def start_script():
    global script_process
    if not is_running:
        thread = threading.Thread(target=run_script)
        thread.daemon = True
        thread.start()
        return jsonify({'status': 'starting'})
    return jsonify({'status': 'already_running'})

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
        return jsonify({'status': 'stopped'})
    return jsonify({'status': 'not_running'})

@app.route('/api/logs')
def get_logs():
    # Return last 100 lines from memory
    return jsonify({'logs': logs[-100:]})

@app.route('/api/clear_logs', methods=['POST'])
def clear_logs():
    global logs
    logs = []
    open(LOG_FILE, 'w').close()
    return jsonify({'status': 'cleared'})

@socketio.on('connect')
def handle_connect():
    emit('connected', {'script': SCRIPT_NAME})

@socketio.on('get_logs')
def handle_get_logs():
    emit('logs_data', {'logs': logs[-100:]})

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=10001, debug=False)