import sqlite3
from datetime import datetime

class DatabaseManager:
    def __init__(self, db_name="scanner.db"):
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self.init_db()

    def init_db(self):
        """Creates the necessary tables if they don't exist."""
        self.cursor.executescript("""
            CREATE TABLE IF NOT EXISTS Targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE,
                created_at TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS Scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                session_id TEXT,
                start_time TIMESTAMP,
                status TEXT,
                FOREIGN KEY(target_id) REFERENCES Targets(id)
            );
            
            CREATE TABLE IF NOT EXISTS Vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                template_id TEXT,
                name TEXT,
                severity TEXT,
                url TEXT,
                discovered_at TIMESTAMP,
                FOREIGN KEY(scan_id) REFERENCES Scans(id)
            );
        """)
        self.conn.commit()

    def start_scan(self, domain, session_id):
        """Registers a new target and starts a new scan session linked to the anonymous user."""
        now = datetime.now()
        
        
        self.cursor.execute("INSERT OR IGNORE INTO Targets (domain, created_at) VALUES (?, ?)", (domain, now))
        self.cursor.execute("SELECT id FROM Targets WHERE domain = ?", (domain,))
        target_id = self.cursor.fetchone()[0]

        # Create a new scan session attached to their private session_id
        self.cursor.execute("INSERT INTO Scans (target_id, session_id, start_time, status) VALUES (?, ?, ?, ?)", (target_id, session_id, now, "RUNNING"))
        self.conn.commit()
        
        return self.cursor.lastrowid

    def save_vulnerability(self, scan_id, template_id, name, severity, url):
        """Saves a discovered vulnerability to the database."""
        now = datetime.now()
        self.cursor.execute("""
            INSERT INTO Vulnerabilities (scan_id, template_id, name, severity, url, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (scan_id, template_id, name, severity, url, now))
        self.conn.commit()

    def complete_scan(self, scan_id):
        """Marks the scan as completed."""
        self.cursor.execute("UPDATE Scans SET status = 'COMPLETED' WHERE id = ?", (scan_id,))
        self.conn.commit()