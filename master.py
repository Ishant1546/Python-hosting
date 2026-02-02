#!/usr/bin/env python3
"""
MASTER SCRIPT - Runs everything:
1. Master Dashboard (Port 10000)
2. Auto-creates dashboards for all scripts
3. Manages all script processes
4. Handles dynamic script uploads
"""

import os
import sys
import json
import time
import shutil
import signal
import threading
import subprocess
import secrets
import hashlib
from datetime import datetime
from pathlib import Path

from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# =============== CONFIGURATION ===============
MASTER_PORT = 10000
BASE_SCRIPT_PORT = 10001
MAX_SCRIPTS = 50
SCRIPTS_DIR = "scripts"
DATA_DIR = "data"
LOGS_DIR = "data/logs"
TEMPLATES_DIR = "templates"
STATIC_DIR = "static"

# Create directories
os.makedirs(SCRIPTS_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(TEMPLATES_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(f"{STATIC_DIR}/css", exist_ok=True)
os.makedirs(f"{STATIC_DIR}/js", exist_ok=True)

# =============== FLASK APP ===============
app = Flask(__name__, template_folder=TEMPLATES_DIR, static_folder=STATIC_DIR)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# =============== DATABASE ===============
class ScriptDatabase:
    def __init__(self):
        self.db_file = f"{DATA_DIR}/scripts.json"
        self.load()
    
    def load(self):
        if os.path.exists(self.db_file):
            with open(self.db_file, 'r') as f:
                self.data = json.load(f)
        else:
            self.data = {
                'scripts': {},
                'next_id': 1,
                'users': {
                    'admin': {
                        'password': hashlib.sha256('admin123'.encode()).hexdigest(),
                        'role': 'admin'
                    }
                },
                'ports_used': {}
            }
            self.save()
    
    def save(self):
        with open(self.db_file, 'w') as f:
            json.dump(self.data, f, indent=2)
    
    def get_next_port(self):
        """Get next available port starting from BASE_SCRIPT_PORT"""
        for port in range(BASE_SCRIPT_PORT, BASE_SCRIPT_PORT + MAX_SCRIPTS):
            if str(port) not in self.data['ports_used']:
                return port
        raise Exception("No available ports")
    
    def add_script(self, script_name, script_filename, description="", author="", category=""):
        """Add a new script to database"""
        script_id = str(self.data['next_id'])
        self.data['next_id'] += 1
        
        port = self.get_next_port()
        
        script_data = {
            'id': script_id,
            'name': script_name,
            'filename': script_filename,
            'original_filename': script_filename,
            'description': description,
            'author': author,
            'category': category,
            'port': port,
            'status': 'stopped',
            'pid': None,
            'dashboard_pid': None,
            'created_at': datetime.now().isoformat(),
            'last_started': None,
            'last_stopped': None,
            'total_runs': 0,
            'total_errors': 0,
            'log_file': f"{LOGS_DIR}/script_{script_id}.log",
            'config_file': f"{SCRIPTS_DIR}/{script_name}/config.json",
            'dashboard_file': f"{SCRIPTS_DIR}/{script_name}/dashboard.py",
            'folder': f"{SCRIPTS_DIR}/{script_name}"
        }
        
        self.data['scripts'][script_id] = script_data
        self.data['ports_used'][str(port)] = script_id
        self.save()
        
        return script_data
    
    def update_script(self, script_id, updates):
        """Update script data"""
        if script_id in self.data['scripts']:
            self.data['scripts'][script_id].update(updates)
            self.save()
            return True
        return False
    
    def delete_script(self, script_id):
        """Delete a script"""
        if script_id in self.data['scripts']:
            script = self.data['scripts'][script_id]
            
            # Free the port
            port = script.get('port')
            if port and str(port) in self.data['ports_used']:
                del self.data['ports_used'][str(port)]
            
            # Remove script
            del self.data['scripts'][script_id]
            
            # Try to delete folder
            try:
                folder = script.get('folder')
                if folder and os.path.exists(folder):
                    shutil.rmtree(folder)
            except:
                pass
            
            self.save()
            return True
        return False
    
    def get_script(self, script_id):
        return self.data['scripts'].get(script_id)
    
    def get_all_scripts(self):
        return self.data['scripts']
    
    def get_script_by_port(self, port):
        for script in self.data['scripts'].values():
            if script.get('port') == port:
                return script
        return None

db = ScriptDatabase()

# =============== USER MANAGEMENT ===============
class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    user_data = db.data['users'].get(user_id)
    if user_data:
        return User(user_id, user_id, user_data['role'])
    return None

# =============== SCRIPT MANAGER ===============
class ScriptManager:
    def __init__(self):
        self.processes = {}  # script_id -> {'process': subprocess.Popen, 'type': 'script' or 'dashboard'}
        self.running_scripts = set()
        self.start_all_scripts()
    
    def start_all_scripts(self):
        """Start dashboards for all scripts on system start"""
        for script_id, script in db.get_all_scripts().items():
            if os.path.exists(script.get('dashboard_file', '')):
                self.start_dashboard(script_id)
    
    def create_script_environment(self, script_data):
        """Create folder and files for a new script"""
        script_name = script_data['name']
        script_folder = script_data['folder']
        
        # Create script folder
        os.makedirs(script_folder, exist_ok=True)
        
        # Create config file
        config = {
            'script_id': script_data['id'],
            'name': script_data['name'],
            'port': script_data['port'],
            'description': script_data['description'],
            'author': script_data['author'],
            'category': script_data['category'],
            'created': script_data['created_at'],
            'dependencies': [],
            'environment_vars': {},
            'timeout_seconds': 300,
            'max_memory_mb': 512,
            'auto_restart': False,
            'schedule': None
        }
        
        with open(f"{script_folder}/config.json", 'w') as f:
            json.dump(config, f, indent=2)
        
        # Create dashboard file
        self.generate_dashboard_file(script_data)
        
        # Create requirements.txt if doesn't exist
        if not os.path.exists(f"{script_folder}/requirements.txt"):
            with open(f"{script_folder}/requirements.txt", 'w') as f:
                f.write("# Add your script dependencies here\n")
        
        return True
    
    def generate_dashboard_file(self, script_data):
        """Generate a Flask dashboard for the script"""
        template = f'''#!/usr/bin/env python3
"""
Auto-generated Dashboard for: {script_data['name']}
Port: {script_data['port']}
"""

import os
import sys
import json
import time
import subprocess
import threading
from datetime import datetime
from pathlib import Path

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit

# Add parent directory to path to import shared modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dashboard-secret-{script_data["id"]}'
socketio = SocketIO(app, cors_allowed_origins="*")

# Configuration
SCRIPT_ID = "{script_data['id']}"
SCRIPT_NAME = "{script_data['name']}"
SCRIPT_PORT = {script_data['port']}
SCRIPT_FILE = "{script_data['folder']}/{script_data['filename']}"
CONFIG_FILE = "{script_data['folder']}/config.json"
LOG_FILE = "{script_data['log_file']}"

# Load config
with open(CONFIG_FILE, 'r') as f:
    CONFIG = json.load(f)

# Script state
script_process = None
is_running = False
logs = []
start_time = None

def run_script():
    """Run the script and capture output"""
    global script_process, is_running, start_time, logs
    
    is_running = True
    start_time = datetime.now()
    
    # Clear log file
    open(LOG_FILE, 'w').close()
    
    # Prepare environment
    env = os.environ.copy()
    env.update(CONFIG.get('environment_vars', {{}}))
    
    # Check for requirements.txt
    requirements_file = "{script_data['folder']}/requirements.txt"
    if os.path.exists(requirements_file):
        # In production, you'd install dependencies here
        pass
    
    # Run the script
    script_process = subprocess.Popen(
        [sys.executable, SCRIPT_FILE],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        universal_newlines=True,
        env=env,
        cwd="{script_data['folder']}"
    )
    
    # Stream output
    for line in iter(script_process.stdout.readline, ''):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        log_entry = f"[{{timestamp}}] {{line.rstrip()}}"
        
        # Save to log file
        with open(LOG_FILE, 'a') as f:
            f.write(log_entry + '\\n')
        
        # Send to connected clients
        socketio.emit('log_update', {{'log': log_entry}})
        
        # Keep in memory (last 1000 lines)
        logs.append(log_entry)
        if len(logs) > 1000:
            logs.pop(0)
    
    # Script finished
    is_running = False
    return_code = script_process.wait()
    script_process = None
    
    end_time = datetime.now()
    runtime = (end_time - start_time).total_seconds()
    
    finish_msg = f"Script {{'completed' if return_code == 0 else 'failed'}} with code {{return_code}} after {{runtime:.2f}}s"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    log_entry = f"[{{timestamp}}] {finish_msg}"
    
    socketio.emit('log_update', {{'log': log_entry}})
    with open(LOG_FILE, 'a') as f:
        f.write(log_entry + '\\n')

@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template('script_dashboard.html',
                         script_name=SCRIPT_NAME,
                         script_id=SCRIPT_ID,
                         port=SCRIPT_PORT,
                         config=CONFIG)

@app.route('/api/status')
def get_status():
    """Get script status"""
    status = {{
        'name': SCRIPT_NAME,
        'id': SCRIPT_ID,
        'is_running': is_running,
        'pid': script_process.pid if script_process else None,
        'start_time': start_time.isoformat() if start_time else None,
        'log_count': len(logs),
        'config': CONFIG
    }}
    return jsonify(status)

@app.route('/api/start', methods=['POST'])
def start_script():
    """Start the script"""
    global script_process, is_running
    
    if not is_running:
        thread = threading.Thread(target=run_script, daemon=True)
        thread.start()
        
        # Update master database
        try:
            import requests
            requests.post(f'http://localhost:{MASTER_PORT}/api/update_script_status', 
                         json={{'script_id': SCRIPT_ID, 'status': 'running'}})
        except:
            pass
        
        return jsonify({{'status': 'starting', 'message': 'Script is starting...'}})
    
    return jsonify({{'status': 'already_running', 'message': 'Script is already running'}})

@app.route('/api/stop', methods=['POST'])
def stop_script():
    """Stop the script"""
    global script_process, is_running
    
    if script_process and is_running:
        script_process.terminate()
        try:
            script_process.wait(timeout=5)
        except:
            script_process.kill()
        
        is_running = False
        script_process = None
        
        # Update master database
        try:
            import requests
            requests.post(f'http://localhost:{MASTER_PORT}/api/update_script_status', 
                         json={{'script_id': SCRIPT_ID, 'status': 'stopped'}})
        except:
            pass
        
        return jsonify({{'status': 'stopped', 'message': 'Script stopped'}})
    
    return jsonify({{'status': 'not_running', 'message': 'Script is not running'}})

@app.route('/api/logs')
def get_logs():
    """Get recent logs"""
    return jsonify({{'logs': logs[-100:]}})

@app.route('/api/logs/download')
def download_logs():
    """Download complete log file"""
    if os.path.exists(LOG_FILE):
        return send_file(LOG_FILE, as_attachment=True)
    return jsonify({{'error': 'Log file not found'}}), 404

@app.route('/api/config', methods=['GET', 'POST'])
def handle_config():
    """Get or update configuration"""
    if request.method == 'POST':
        new_config = request.json
        CONFIG.update(new_config)
        with open(CONFIG_FILE, 'w') as f:
            json.dump(CONFIG, f, indent=2)
        return jsonify({{'status': 'updated', 'config': CONFIG}})
    
    return jsonify(CONFIG)

@app.route('/api/restart', methods=['POST'])
def restart_script():
    """Restart the script"""
    stop_script()
    time.sleep(1)
    start_script()
    return jsonify({{'status': 'restarting', 'message': 'Script is restarting...'}})

@socketio.on('connect')
def handle_connect():
    emit('connected', {{'script': SCRIPT_NAME, 'port': SCRIPT_PORT}})

@socketio.on('get_status')
def handle_get_status():
    emit('status_update', {{
        'is_running': is_running,
        'start_time': start_time.isoformat() if start_time else None,
        'log_count': len(logs)
    }})

@socketio.on('get_logs')
def handle_get_logs():
    emit('logs_data', {{'logs': logs[-50:]}})

if __name__ == '__main__':
    print(f"Starting dashboard for {{SCRIPT_NAME}} on port {{SCRIPT_PORT}}...")
    socketio.run(app, host='0.0.0.0', port=SCRIPT_PORT, debug=False, allow_unsafe_werkzeug=True)
'''
        
        with open(script_data['dashboard_file'], 'w') as f:
            f.write(template)
        
        # Make it executable
        os.chmod(script_data['dashboard_file'], 0o755)
    
    def start_dashboard(self, script_id):
        """Start the dashboard for a script"""
        script = db.get_script(script_id)
        if not script or not os.path.exists(script['dashboard_file']):
            return False
        
        try:
            # Kill existing dashboard if running
            if script.get('dashboard_pid'):
                try:
                    os.kill(script['dashboard_pid'], signal.SIGTERM)
                except:
                    pass
            
            # Start new dashboard
            process = subprocess.Popen(
                [sys.executable, script['dashboard_file']],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            db.update_script(script_id, {
                'dashboard_pid': process.pid,
                'status': 'dashboard_running'
            })
            
            self.processes[script_id] = {'process': process, 'type': 'dashboard'}
            print(f"Started dashboard for {script['name']} on port {script['port']} (PID: {process.pid})")
            
            # Wait a bit for dashboard to start
            time.sleep(2)
            return True
        except Exception as e:
            print(f"Error starting dashboard for {script_id}: {e}")
            return False
    
    def stop_dashboard(self, script_id):
        """Stop the dashboard for a script"""
        if script_id in self.processes:
            try:
                self.processes[script_id]['process'].terminate()
                self.processes[script_id]['process'].wait(timeout=5)
            except:
                try:
                    self.processes[script_id]['process'].kill()
                except:
                    pass
            
            del self.processes[script_id]
        
        db.update_script(script_id, {
            'dashboard_pid': None,
            'status': 'stopped'
        })
        return True
    
    def start_script_execution(self, script_id):
        """Start the actual script execution (via dashboard API)"""
        script = db.get_script(script_id)
        if not script:
            return False
        
        try:
            import requests
            response = requests.post(f"http://localhost:{script['port']}/api/start", timeout=5)
            if response.status_code == 200:
                db.update_script(script_id, {'status': 'running'})
                return True
        except:
            pass
        return False
    
    def stop_script_execution(self, script_id):
        """Stop the script execution"""
        script = db.get_script(script_id)
        if not script:
            return False
        
        try:
            import requests
            response = requests.post(f"http://localhost:{script['port']}/api/stop", timeout=5)
            if response.status_code == 200:
                db.update_script(script_id, {'status': 'dashboard_running'})
                return True
        except:
            pass
        
        # Fallback: kill process directly
        if script.get('pid'):
            try:
                os.kill(script['pid'], signal.SIGTERM)
            except:
                pass
        
        db.update_script(script_id, {'status': 'stopped', 'pid': None})
        return True
    
    def get_script_status(self, script_id):
        """Get detailed status of a script"""
        script = db.get_script(script_id)
        if not script:
            return None
        
        status = script.copy()
        
        # Check if dashboard is running
        if script.get('dashboard_pid'):
            try:
                process = psutil.Process(script['dashboard_pid'])
                status['dashboard_alive'] = True
                status['dashboard_cpu'] = process.cpu_percent()
                status['dashboard_memory_mb'] = process.memory_info().rss / 1024 / 1024
            except:
                status['dashboard_alive'] = False
                status['dashboard_cpu'] = 0
                status['dashboard_memory_mb'] = 0
        
        # Try to get script execution status from dashboard
        try:
            import requests
            response = requests.get(f"http://localhost:{script['port']}/api/status", timeout=2)
            if response.status_code == 200:
                dashboard_status = response.json()
                status.update(dashboard_status)
        except:
            pass
        
        return status

script_manager = ScriptManager()

# =============== ROUTES ===============
@app.route('/')
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    return redirect(url_for('master_dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('master_dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user_data = db.data['users'].get(username)
        if user_data and user_data['password'] == hashlib.sha256(password.encode()).hexdigest():
            user = User(username, username, user_data['role'])
            login_user(user)
            return redirect(url_for('master_dashboard'))
        
        flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/master')
@login_required
def master_dashboard():
    """Main master dashboard"""
    scripts = db.get_all_scripts()
    script_list = []
    
    for script_id, script in scripts.items():
        status = script_manager.get_script_status(script_id) or script
        script_list.append(status)
    
    # System stats
    cpu_percent = psutil.cpu_percent()
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    return render_template('master.html',
                         scripts=script_list,
                         cpu=cpu_percent,
                         memory=memory.percent,
                         disk=disk.percent,
                         total_scripts=len(scripts),
                         username=current_user.username)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_script():
    """Upload a new script"""
    if request.method == 'POST':
        if 'script_file' not in request.files:
            flash('No file uploaded')
            return redirect(request.url)
        
        file = request.files['script_file']
        if file.filename == '':
            flash('No file selected')
            return redirect(request.url)
        
        if not file.filename.endswith('.py'):
            flash('Only Python files (.py) are allowed')
            return redirect(request.url)
        
        # Get form data
        script_name = request.form.get('script_name', '').strip() or Path(file.filename).stem
        description = request.form.get('description', '')
        author = request.form.get('author', current_user.username)
        category = request.form.get('category', 'uncategorized')
        
        # Sanitize script name
        script_name = ''.join(c for c in script_name if c.isalnum() or c in '_- ').strip()
        script_name = script_name.replace(' ', '_')
        
        if not script_name:
            flash('Invalid script name')
            return redirect(request.url)
        
        # Check if script name already exists
        for existing_script in db.get_all_scripts().values():
            if existing_script['name'] == script_name:
                flash('Script name already exists')
                return redirect(request.url)
        
        # Add script to database
        script_data = db.add_script(
            script_name=script_name,
            script_filename=file.filename,
            description=description,
            author=author,
            category=category
        )
        
        # Create script environment
        script_manager.create_script_environment(script_data)
        
        # Save the uploaded script
        script_folder = script_data['folder']
        file.save(f"{script_folder}/{file.filename}")
        
        # Start the dashboard
        if script_manager.start_dashboard(script_data['id']):
            flash(f'Script uploaded successfully! Dashboard available at port {script_data["port"]}')
        else:
            flash('Script uploaded but dashboard failed to start')
        
        return redirect(url_for('master_dashboard'))
    
    return render_template('upload.html')

@app.route('/script/<script_id>')
@login_required
def script_dashboard(script_id):
    """Redirect to script's individual dashboard"""
    script = db.get_script(script_id)
    if not script:
        flash('Script not found')
        return redirect(url_for('master_dashboard'))
    
    dashboard_url = f"http://localhost:{script['port']}"
    return redirect(dashboard_url)

@app.route('/api/scripts')
@login_required
def api_get_scripts():
    """API: Get all scripts"""
    scripts = []
    for script_id, script in db.get_all_scripts().items():
        status = script_manager.get_script_status(script_id) or script
        scripts.append(status)
    
    return jsonify({'scripts': scripts})

@app.route('/api/script/<script_id>')
@login_required
def api_get_script(script_id):
    """API: Get specific script"""
    script = script_manager.get_script_status(script_id)
    if not script:
        return jsonify({'error': 'Script not found'}), 404
    return jsonify(script)

@app.route('/api/start/<script_id>', methods=['POST'])
@login_required
def api_start_script(script_id):
    """API: Start a script"""
    if script_manager.start_script_execution(script_id):
        return jsonify({'status': 'success', 'message': 'Script started'})
    return jsonify({'status': 'error', 'message': 'Failed to start script'}), 500

@app.route('/api/stop/<script_id>', methods=['POST'])
@login_required
def api_stop_script(script_id):
    """API: Stop a script"""
    if script_manager.stop_script_execution(script_id):
        return jsonify({'status': 'success', 'message': 'Script stopped'})
    return jsonify({'status': 'error', 'message': 'Failed to stop script'}), 500

@app.route('/api/restart/<script_id>', methods=['POST'])
@login_required
def api_restart_script(script_id):
    """API: Restart a script"""
    script_manager.stop_script_execution(script_id)
    time.sleep(2)
    if script_manager.start_script_execution(script_id):
        return jsonify({'status': 'success', 'message': 'Script restarted'})
    return jsonify({'status': 'error', 'message': 'Failed to restart script'}), 500

@app.route('/api/start_dashboard/<script_id>', methods=['POST'])
@login_required
def api_start_dashboard(script_id):
    """API: Start script dashboard"""
    if script_manager.start_dashboard(script_id):
        return jsonify({'status': 'success', 'message': 'Dashboard started'})
    return jsonify({'status': 'error', 'message': 'Failed to start dashboard'}), 500

@app.route('/api/stop_dashboard/<script_id>', methods=['POST'])
@login_required
def api_stop_dashboard(script_id):
    """API: Stop script dashboard"""
    if script_manager.stop_dashboard(script_id):
        return jsonify({'status': 'success', 'message': 'Dashboard stopped'})
    return jsonify({'status': 'error', 'message': 'Failed to stop dashboard'}), 500

@app.route('/api/delete/<script_id>', methods=['DELETE'])
@login_required
def api_delete_script(script_id):
    """API: Delete a script"""
    if current_user.role != 'admin':
        return jsonify({'error': 'Admin required'}), 403
    
    script_manager.stop_dashboard(script_id)
    script_manager.stop_script_execution(script_id)
    
    if db.delete_script(script_id):
        return jsonify({'status': 'success', 'message': 'Script deleted'})
    return jsonify({'status': 'error', 'message': 'Failed to delete script'}), 500

@app.route('/api/update_script_status', methods=['POST'])
def api_update_script_status():
    """Internal API: Update script status from dashboard"""
    data = request.json
    script_id = data.get('script_id')
    status = data.get('status')
    
    if script_id and status:
        db.update_script(script_id, {'status': status})
        return jsonify({'status': 'success'})
    
    return jsonify({'error': 'Invalid data'}), 400

@app.route('/api/system_stats')
@login_required
def api_system_stats():
    """API: Get system statistics"""
    cpu_percent = psutil.cpu_percent()
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    # Get network info
    net_io = psutil.net_io_counters()
    
    return jsonify({
        'cpu': cpu_percent,
        'memory': {
            'total': memory.total / (1024**3),
            'used': memory.used / (1024**3),
            'free': memory.free / (1024**3),
            'percent': memory.percent
        },
        'disk': {
            'total': disk.total / (1024**3),
            'used': disk.used / (1024**3),
            'free': disk.free / (1024**3),
            'percent': disk.percent
        },
        'network': {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv
        },
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/script_logs/<script_id>')
@login_required
def api_script_logs(script_id):
    """API: Get script logs"""
    script = db.get_script(script_id)
    if not script:
        return jsonify({'error': 'Script not found'}), 404
    
    log_file = script.get('log_file')
    if not log_file or not os.path.exists(log_file):
        return jsonify({'logs': []})
    
    try:
        with open(log_file, 'r') as f:
            logs = f.readlines()[-100:]  # Last 100 lines
    except:
        logs = []
    
    return jsonify({'logs': logs})

@socketio.on('connect')
def handle_connect():
    emit('connected', {'message': 'Connected to master dashboard'})

@socketio.on('request_update')
def handle_update_request():
    """Send real-time updates to master dashboard"""
    scripts = []
    for script_id in db.get_all_scripts():
        status = script_manager.get_script_status(script_id) or db.get_script(script_id)
        if status:
            scripts.append(status)
    
    emit('scripts_update', {'scripts': scripts})

# =============== START ALL SERVICES ===============
def start_all_services():
    """Start all script dashboards"""
    print("Starting all script dashboards...")
    for script_id in db.get_all_scripts():
        script_manager.start_dashboard(script_id)
    print(f"All dashboards started. Master dashboard on port {MASTER_PORT}")

# =============== SHUTDOWN HANDLER ===============
def shutdown_handler(signum, frame):
    """Clean shutdown of all processes"""
    print("\nShutting down all services...")
    
    # Stop all dashboards
    for script_id in list(script_manager.processes.keys()):
        script_manager.stop_dashboard(script_id)
    
    print("All services stopped. Goodbye!")
    sys.exit(0)

# =============== MAIN ===============
if __name__ == '__main__':
    # Register shutdown handler
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    
    print("=" * 60)
    print("PYTHON SCRIPT HOSTING MASTER")
    print("=" * 60)
    print(f"Master Dashboard: http://localhost:{MASTER_PORT}")
    print("Default login: admin / admin123")
    print("=" * 60)
    
    # Start all script dashboards
    start_all_services()
    
    # Start master dashboard
    print(f"\nStarting master dashboard on port {MASTER_PORT}...")
    socketio.run(app, host='0.0.0.0', port=MASTER_PORT, debug=False, allow_unsafe_werkzeug=True)