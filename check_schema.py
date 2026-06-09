import MySQLdb

config = {
    'host': 'localhost',
    'user': 'root',
    'passwd': 'password@2532',
    'db': 'drone_db'
}

def check_schema():
    try:
        db = MySQLdb.connect(**config)
        cur = db.cursor()
        cur.execute("DESCRIBE notices")
        for row in cur.fetchall():
            print(row)
        db.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    check_schema()
