from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import os
import subprocess
import uuid
from database import DatabaseManager 

app = Flask(__name__)
# Secret key is required by Flask to encrypt the session cookies securely
app.secret_key = 'super_secret_scanner_key_change_in_production' 

def get_db_connection():
    # This automatically creates scanner.db and its tables if it doesn't exist
    DatabaseManager()
    
    # Connect to the SQLite database
    conn = sqlite3.connect('scanner.db')
    conn.row_factory = sqlite3.Row  # This allows us to access columns by name (e.g., row['name'])
    return conn

@app.route('/')
def index():
    # Automatically assign an anonymous, private session ID if the user doesn't have one
    if 'uid' not in session:
        session['uid'] = str(uuid.uuid4())

    conn = get_db_connection()
    
    
    active_scans = conn.execute('''
        SELECT t.domain, s.start_time 
        FROM Scans s
        JOIN Targets t ON s.target_id = t.id
        WHERE s.session_id = ? AND s.status = 'RUNNING'
        ORDER BY s.start_time DESC
    ''', (session['uid'],)).fetchall()
    
    # Fetch ONLY vulnerabilities that belong that specific user 
    vulns = conn.execute('''
        SELECT v.severity, v.name, v.url, v.discovered_at, t.domain
        FROM Vulnerabilities v
        JOIN Scans s ON v.scan_id = s.id
        JOIN Targets t ON s.target_id = t.id
        WHERE s.session_id = ?
        ORDER BY 
            CASE v.severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                WHEN 'INFO' THEN 5
                ELSE 6
            END, v.discovered_at DESC
    ''', (session['uid'],)).fetchall()

    # Calculate statistics for the dashboard cards based on ONLY their private findings
    stats = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for v in vulns:
        sev = v['severity'].upper()
        if sev in stats:
            stats[sev] += 1

    conn.close()
    
    # Render the HTML template and pass the active_scans so the UI can auto-refresh
    return render_template('index.html', vulns=vulns, stats=stats, active_scans=active_scans)

@app.route('/scan', methods=['POST'])
def start_scan():
    # Ensure they have a session ID before scanning
    if 'uid' not in session:
        session['uid'] = str(uuid.uuid4())

    target = request.form.get('target')
    if target:
        # Launch the orchestrator script in the background, passing BOTH the target and their secret session ID
        print(f"[*] UI Triggered Scan for: {target} by User {session['uid'][:8]}")
        subprocess.Popen(['python', 'orchestrator.py', target, session['uid']])
        
    return redirect(url_for('index'))

if __name__ == '__main__':

    port = int(os.environ.get("PORT", 5000))
    print(f"[+] Starting Web Dashboard on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)