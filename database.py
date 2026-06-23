import sqlite3
from datetime import datetime

class DatabaseManager:
    def __init__(self, db_name="scanner.db"):
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self.init_db()
        