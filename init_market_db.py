import MySQLdb

config = {
    'host': 'localhost',
    'user': 'root',
    'passwd': 'password@2532',
    'db': 'drone_db'
}

def init_db():
    try:
        db = MySQLdb.connect(**config)
        cur = db.cursor()
        
        # Marketplace table
        cur.execute("""
        CREATE TABLE IF NOT EXISTS marketplace_items (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) NOT NULL,
            title VARCHAR(255) NOT NULL,
            description TEXT NOT NULL,
            price INT NOT NULL,
            image_path VARCHAR(255),
            status ENUM('판매중', '예약중', '판매완료') DEFAULT '판매중',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        db.commit()
        print("Marketplace table verified/created.")
        db.close()
    except Exception as e:
        print(f"Error initializing DB: {e}")

if __name__ == "__main__":
    init_db()
