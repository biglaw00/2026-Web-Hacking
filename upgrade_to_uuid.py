import MySQLdb
import uuid

config = {
    'host': 'localhost',
    'user': 'root',
    'passwd': 'password@2532',
    'db': 'drone_db'
}

def migrate():
    try:
        db = MySQLdb.connect(**config)
        cur = db.cursor()
        
        # 1. Add uuid columns to tables if they don't exist
        tables = ['notices', 'free_board', 'marketplace_items', 'project_recruitment', 'lab_vault']
        for t in tables:
            try:
                cur.execute(f"ALTER TABLE {t} ADD COLUMN uuid VARCHAR(36) NULL")
                db.commit()
                print(f"Added uuid column to {t}")
            except Exception as e:
                if 'duplicate column' in str(e).lower() or 'already exists' in str(e).lower():
                    print(f"uuid column already exists in {t}")
                else:
                    raise e
                    
        # 2. Populate UUIDs for existing rows that have NULL uuid
        for t in tables:
            cur.execute(f"SELECT id FROM {t} WHERE uuid IS NULL")
            rows = cur.fetchall()
            for row in rows:
                rid = row[0]
                new_uuid = str(uuid.uuid4())
                cur.execute(f"UPDATE {t} SET uuid = %s WHERE id = %s", (new_uuid, rid))
            db.commit()
            if rows:
                print(f"Populated {len(rows)} UUIDs in {t}")
                
        # 3. Set uuid column as NOT NULL and add UNIQUE constraint
        for t in tables:
            try:
                cur.execute(f"ALTER TABLE {t} MODIFY COLUMN uuid VARCHAR(36) NOT NULL")
                cur.execute(f"ALTER TABLE {t} ADD UNIQUE INDEX idx_uuid (uuid)")
                db.commit()
                print(f"Set uuid column in {t} as NOT NULL UNIQUE")
            except Exception as e:
                if 'duplicate' in str(e).lower() or 'already exists' in str(e).lower():
                    print(f"Unique constraint/index already exists on {t}.uuid")
                else:
                    print(f"Warning setting constraints on {t}: {e}")
                    
        # 4. Add login_attempts and lock_time to users table
        try:
            cur.execute("ALTER TABLE users ADD COLUMN login_attempts INT DEFAULT 0 AFTER role")
            db.commit()
            print("Added login_attempts column to users")
        except Exception as e:
            if 'duplicate column' in str(e).lower() or 'already exists' in str(e).lower():
                print("login_attempts column already exists in users")
            else:
                raise e
                
        try:
            cur.execute("ALTER TABLE users ADD COLUMN lock_time TIMESTAMP NULL DEFAULT NULL AFTER login_attempts")
            db.commit()
            print("Added lock_time column to users")
        except Exception as e:
            if 'duplicate column' in str(e).lower() or 'already exists' in str(e).lower():
                print("lock_time column already exists in users")
            else:
                raise e
                
        db.close()
        print("Migration completed successfully!")
    except Exception as e:
        print(f"Error during migration: {e}")

if __name__ == '__main__':
    migrate()
