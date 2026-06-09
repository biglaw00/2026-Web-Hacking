import MySQLdb

config = {
    'host': 'localhost',
    'user': 'root',
    'passwd': 'password@2532',
    'db': 'drone_db'
}

def init_expansion_v2():
    try:
        db = MySQLdb.connect(**config)
        cur = db.cursor()
        
        # 1. Project Recruitment Table
        cur.execute("""
        CREATE TABLE IF NOT EXISTS project_recruitment (
            id INT AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(255) NOT NULL,
            category VARCHAR(100) NOT NULL, -- 'Study', 'Project', 'Research'
            author VARCHAR(50) NOT NULL,
            content TEXT,
            status VARCHAR(20) DEFAULT 'Recruiting', -- 'Recruiting', 'Closed'
            current_members INT DEFAULT 1,
            target_members INT DEFAULT 4,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        # 2. Support Inquiries Table
        cur.execute("""
        CREATE TABLE IF NOT EXISTS support_inquiries (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) NOT NULL,
            title VARCHAR(255) NOT NULL,
            message TEXT,
            response TEXT,
            status VARCHAR(20) DEFAULT 'Pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        # 3. Sample Projects
        cur.execute("DELETE FROM project_recruitment")
        projects = [
            ("MAVLink 프로토콜 보안 분석 스터디원 모집", "Study", "admin", "MAVLink 2.0 프로토콜의 취약점을 함께 분석하고 익스플로잇 코드를 작성해볼 스터디원을 모집합니다.", "Recruiting", 1, 5),
            ("안티 드론 시스템 H/W 설계 팀 합류하실 분", "Project", "user1", "라즈베리 파이와 RF 탐지 모듈을 이용한 소형 안티 드론 시스템을 제작 중입니다. 하드웨어 설계 경험자 환영합니다.", "Recruiting", 2, 4),
            ("실시간 드론 위치 추적 알고리즘 연구", "Research", "admin", "OpenCV 기반의 드론 객체 인식 및 위치 추적 알고리즘 고도화 연구팀입니다.", "Closed", 4, 4)
        ]
        for title, cat, author, content, status, cur_m, tar_m in projects:
            cur.execute("INSERT INTO project_recruitment (title, category, author, content, status, current_members, target_members) VALUES (%s, %s, %s, %s, %s, %s, %s)", 
                        (title, cat, author, content, status, cur_m, tar_m))

        db.commit()
        print("Expansion V2 tables initialized.")
        db.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    init_expansion_v2()
