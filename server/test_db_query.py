import psycopg2

# ============================
# HARDCODED DATABASE SETTINGS
# ============================

PG_HOST = "192.168.50.12"
PG_PORT = 5432
PG_DB = "DBNAME"
PG_USER = "DBUSER"
PG_PASSWORD = "DBPASS"



print("[*] Testing PostgreSQL connection...")

try:
    conn = psycopg2.connect(
        host=PG_HOST,
        port=PG_PORT,
        dbname=PG_DB,
        user=PG_USER,
        password=PG_PASSWORD,
        connect_timeout=5
    )

    cur = conn.cursor()
    cur.execute("SELECT * from fim.fim_events;")
    result = cur.fetchone()

    print("[✓] Connection successful!")
    print("    Result of SELECT:", result)

    cur.close()
    conn.close()

except Exception as e:
    print("[✗] Connection failed!")
    print("Error:", e)

