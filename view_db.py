## making this to verify workflow working fine(checker Script)

import sqlite3

def check_db():
    print("\n[+] connecting to scanner.db...\n")

    try:
        conn= sqlite3.connect("scanner.db")
        cursor = conn.cursor()

        # 1 check the target table 

        print("--- TARGETS TABLE ---")
        print("--- TARGETS TABLE ---")
        cursor.execute("SELECT * FROM Targets")
        targets = cursor.fetchall()
        for t in targets:
            print(f"ID: {t[0]} | Domain: {t[1]} | Scanned At: {t[2]}")

    
#2 scan the table 
        print("\n--- SCANS TABLE ---")
        cursor.execute("SELECT * FROM Scans")
        scans = cursor.fetchall()
        for s in scans:
            print(f"Scan ID: {s[0]} | Tagret ID: {s[1]} | Status: {s[3]} | Start: {s[2]}")

            # check the vuln Table
