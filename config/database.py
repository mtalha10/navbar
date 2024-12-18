import sqlite3

def create_db():
    conn = sqlite3.connect("zap_scanner.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY,
        name TEXT,
        risk TEXT,
        url TEXT
    )''')
    conn.commit()
    conn.close()

def insert_scan_results(alerts):
    conn = sqlite3.connect("zap_scanner.db")
    cursor = conn.cursor()
    for alert in alerts:
        cursor.execute("INSERT INTO alerts (name, risk, url) VALUES (?, ?, ?)",
                       (alert['name'], alert['risk'], alert['url']))
    conn.commit()
    conn.close()
