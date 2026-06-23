from flask import Flask, render_template
import sqlite3
import os

app = Flask(__name__)


def get_db_connection():
    
    conn = sqlite3.connect('scanner.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():

    # Check if DB exists
    if not os.path.exists('scanner.db'):
        return "Database 'scanner.db' not found. Please run orchestrator.py first!"
    
        conn = get_db_connection()

        vulns = conn.execute('''
        SELECT v.severity, v.name, v.url, v.discovered_at, t.domain
        FROM Vulnerabilities v
        JOIN Scans s ON v.scan_id = s.id
        JOIN Targets t ON s.target_id = t.id
        ORDER BY 
            CASE v.severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                WHEN 'INFO' THEN 5
                ELSE 6
            END, v.discovered_at DESC
    ''').fetchall()

    # Calculate statistics for the dashboard cards
    stats = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for v in vulns:
        sev = v['severity'].upper()
        if sev in stats:
            stats[sev] += 1

    conn.close()
    
    # Render the HTML template and pass the data to it
    return render_template('index.html', vulns=vulns, stats=stats)

if __name__ == '__main__':
    print("[+] Starting Web Dashboard on http://127.0.0.1:5000")
    app.run(debug=True, port=5000)


    

