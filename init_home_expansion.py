import MySQLdb

config = {
    'host': 'localhost',
    'user': 'root',
    'passwd': 'password@2532',
    'db': 'drone_db'
}

def init_expansion():
    try:
        db = MySQLdb.connect(**config)
        cur = db.cursor()
        
        # 0. Fix notices table
        try:
            cur.execute("ALTER TABLE notices ADD COLUMN file_name VARCHAR(255)")
            cur.execute("ALTER TABLE notices ADD COLUMN file_path VARCHAR(255)")
            print("Added file columns to notices table.")
        except:
            print("Columns might already exist.")

        # 1. Chat table
        cur.execute("""
        CREATE TABLE IF NOT EXISTS chat_messages (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) NOT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        # 2. Insert Security News (Notices)
        cur.execute("DELETE FROM notices")
        notices = [
            ("[긴급] 드론 GPS 스푸핑 취약점 발견 및 조치권고", "최근 도심지에서 드론의 GPS 신호를 가로채 위치 정보를 왜곡하는 스푸핑 공격이 포착되었습니다. 펌웨어 2.1.2 버전 이상으로 즉시 업데이트 하시기 바랍니다.", "admin_notice_1.pdf", "uploads/admin_notice_1.pdf"),
            ("RF 재밍 차단을 위한 안티-잼 기술 세미나", "주파수 도약(FHSS) 기술을 활용한 재밍 방어 방안에 대한 온라인 기술 세미나를 개최합니다. 4월 15일 오후 3시 채널A에서 참여 가능합니다.", None, None),
            ("MAVLink 프로토콜 하이재킹 소스코드 분석 사례", "원격 제어 신호 탈취를 통한 하이재킹 취약점의 상세 기술 분석 문서가 업데이트 되었습니다. 커뮤니티 Lab 섹션에서 확인하세요.", "mavlink_analysis.txt", "uploads/mavlink_analysis.txt")
        ]
        for title, content, fname, fpath in notices:
            cur.execute("INSERT INTO notices (title, content, file_name, file_path) VALUES (%s, %s, %s, %s)", (title, content, fname, fpath))
            
        # 3. Insert Marketplace Dummy Items
        cur.execute("DELETE FROM marketplace_items")
        items = [
            ("seller1", "DJI Mavic 3 Pro (신품급)", "작년 구매 후 실비행 3회 미만입니다. 배터리 3개, 가방 포함 풀세트 판매합니다.", 2200000, None),
            ("seller2", "Pixhawk 6C 비행 컨트롤러", "보안 테스트용으로 구매했던 제품입니다. 상태 아주 깨끗합니다.", 350000, None),
            ("seller3", "Herelink Blue 그라운드 스테이션", "보안 인증된 블루투스 전송 계열입니다. 박스 포함.", 1100000, None)
        ]
        for user, title, desc, price, img in items:
            cur.execute("INSERT INTO marketplace_items (username, title, description, price, image_path) VALUES (%s, %s, %s, %s, %s)", (user, title, desc, price, img))

        db.commit()
        print("Expansion tables and data initialized.")
        db.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    init_expansion()
