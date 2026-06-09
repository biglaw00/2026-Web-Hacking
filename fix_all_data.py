import MySQLdb

config = {
    'host': 'localhost',
    'user': 'root',
    'passwd': 'password@2532',
    'db': 'drone_db'
}

def fix_all_data():
    try:
        db = MySQLdb.connect(**config)
        cur = db.cursor()
        
        # 1. Update Market items to use the generated drone image
        cur.execute("UPDATE marketplace_items SET image_path = 'drone_main.png' WHERE id > 0")
        
        # 2. Add an Admin user if not exists (for tests)
        cur.execute("SELECT id FROM users WHERE username = 'admin'")
        if not cur.fetchone():
            cur.execute("INSERT INTO users (username, password, name, ssn, phone, address, email, role) VALUES ('admin', 'admin1234', 'Admin Manager', '000000-0000000', '010-0000-0000', 'UAV Lab', 'admin@dronegard.com', 'admin')")
            print("Admin user created (admin / admin1234)")

        db.commit()
        print("Data fixed and images updated.")
        db.close()
    except Exception as e:
        print(f"Error fixing data: {e}")

if __name__ == "__main__":
    fix_all_data()
