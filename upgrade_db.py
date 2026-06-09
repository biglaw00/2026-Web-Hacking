import MySQLdb

config = {
    'host': 'localhost',
    'user': 'root',
    'passwd': 'password@2532',
    'db': 'drone_db'
}

def upgrade_schema_and_fix():
    try:
        db = MySQLdb.connect(**config)
        cur = db.cursor()
        
        # 1. Add job and company columns to users table
        try:
            cur.execute("ALTER TABLE users ADD COLUMN job VARCHAR(100) AFTER email")
            cur.execute("ALTER TABLE users ADD COLUMN company VARCHAR(100) AFTER job")
            print("Columns 'job' and 'company' added to users table.")
        except MySQLdb.OperationalError as e:
            if 'duplicate column' in str(e).lower():
                print("Columns 'job'/'company' already exist.")
            else:
                raise e

        # 2. Add login_attempts and lock_time columns to users table
        try:
            cur.execute("ALTER TABLE users ADD COLUMN login_attempts INT DEFAULT 0 AFTER role")
            cur.execute("ALTER TABLE users ADD COLUMN lock_time TIMESTAMP NULL DEFAULT NULL AFTER login_attempts")
            print("Columns 'login_attempts' and 'lock_time' added to users table.")
        except MySQLdb.OperationalError as e:
            if 'duplicate column' in str(e).lower() or 'already exists' in str(e).lower():
                print("Columns 'login_attempts'/'lock_time' already exist.")
            else:
                raise e

        # 2. Fix marketplace items images once more just in case
        cur.execute("UPDATE marketplace_items SET image_path = 'drone_main.png' WHERE image_path IS NULL OR image_path = ''")
        
        db.commit()
        db.close()
        print("Schema upgrade and data fix completed.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    upgrade_schema_and_fix()
