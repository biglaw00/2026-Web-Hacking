import MySQLdb

config = {
    'host': 'localhost',
    'user': 'root',
    'passwd': 'password@2532',
    'db': 'drone_db'
}

def setup_vault_and_sync_market():
    try:
        db = MySQLdb.connect(**config)
        cur = db.cursor()
        
        # 1. Create Lab Vault table
        cur.execute("""
        CREATE TABLE IF NOT EXISTS lab_vault (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) NOT NULL,
            filename VARCHAR(255) NOT NULL,
            filepath VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        print("Table 'lab_vault' initialized.")

        # 2. Update Marketplace Items with REAL generated photos
        # We'll replace the old dummy data with these 3 new ones
        cur.execute("DELETE FROM marketplace_items WHERE id > 0")
        items = [
            ('admin', 'High-End Flight Controller (H743)', 'DroneGard Lab 공식 인증 고성능 FC입니다. 듀얼 IMU 및 정밀 제어를 지원합니다.', 450000, 'fc_pro.png', '판매중'),
            ('admin', 'UAV 고출력 브러시리스 모터', '산업용 드론에 최적화된 고출력 모터입니다. 저방향 소음 및 고효율 설계.', 120000, 'motor_pro.png', '판매중'),
            ('admin', '카본 파이버 폴딩 프로펠러', '고강도 카본 소재의 폴딩형 프로펠러입니다. 비행 안정성 및 보관 편의성 극대화.', 85000, 'props_pro.png', '판매중')
        ]
        cur.executemany("INSERT INTO marketplace_items (username, title, description, price, image_path, status) VALUES (%s, %s, %s, %s, %s, %s)", items)
        
        db.commit()
        db.close()
        print("Marketplace assets synced and Lab Vault ready.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    setup_vault_and_sync_market()
