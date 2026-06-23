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
                start_time TIMESTAMP,
                status TEXT,
                FOREIGN KEY(target_id) REFERENCES Targets(id) 
            );
                                  
            CREATE TABLE IF NOT EXISTS Vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                templates_id TEXT,
                name TEXT,
                severity TEXT,
                url TEXT,
                discovered_at TIMESTAMP,
                FOREIGN KEY(scan_id) REFERENCES Scans(id)
            );
        """)

        self.conn.commit()

def start_scan()


