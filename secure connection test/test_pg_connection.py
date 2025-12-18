import psycopg2

# ============================
# HARDCODED DATABASE SETTINGS
# ============================

PG_HOST = "192.168.50.12"
PG_PORT = 5432
PG_DB = "fim_db"
PG_USER = "refer_user"
PG_PASSWORD = "PanoptesSeesAll"

# Table name (if you need it later)
FIM_EVENTS_TABLE = "fim_events"


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
    cur.execute("SELECT * from fim.fim_current_state;")
    result = cur.fetchone()

    print("[✓] Connection successful!")
    print("    Result of SELECT:\n", result)

    cur.close()
    conn.close()

except Exception as e:
    print("[✗] Connection failed!")
    print("Error:", e)
