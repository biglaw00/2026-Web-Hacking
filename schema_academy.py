import MySQLdb

config = {
    'host': 'localhost',
    'user': 'root',
    'passwd': 'password@2532',
    'db': 'drone_db'
}

def init_academy():
    try:
        db = MySQLdb.connect(**config)
        cur = db.cursor()
        
        # 1. Academy Courses Table
        cur.execute("""
        CREATE TABLE IF NOT EXISTS academy_courses (
            id INT AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(255) NOT NULL,
            category VARCHAR(100) NOT NULL,
            description TEXT,
            thumbnail_path VARCHAR(255),
            instructor VARCHAR(100) DEFAULT 'DroneGard Labs',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        # 2. Academy Lessons Table
        cur.execute("""
        CREATE TABLE IF NOT EXISTS academy_lessons (
            id INT AUTO_INCREMENT PRIMARY KEY,
            course_id INT NOT NULL,
            title VARCHAR(255) NOT NULL,
            video_url VARCHAR(255),
            content TEXT,
            material_path VARCHAR(255),
            duration VARCHAR(50),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (course_id) REFERENCES academy_courses(id) ON DELETE CASCADE
        )
        """)
        
        # 3. Insert Initial Data
        cur.execute("DELETE FROM academy_lessons")
        cur.execute("DELETE FROM academy_courses")
        
        courses = [
            ("드론 기초 항공역학 (Aerodynamics)", "항공역학", "드론의 비행 원리와 기체 구조에 대한 물리적 기초 지식을 학습합니다.", "course_aero.jpg"),
            ("PX4 비행 제어 및 MAVLink 통신", "항공제어", "오픈소스 FC인 PX4 사용법과 MAVLink 프로토콜을 이용한 제어 통신을 분석합니다.", "course_control.jpg"),
            ("드론 RF 사이버 보안 및 취약점 분석", "드론보안", "드론 통신 주파수에 대한 가로채기(Sniffing)와 하이재킹(Hijacking) 실습 자료입니다.", "course_security.jpg")
        ]
        
        for title, cat, desc, img in courses:
            cur.execute("INSERT INTO academy_courses (title, category, description, thumbnail_path) VALUES (%s, %s, %s, %s)", (title, cat, desc, img))
            course_id = cur.lastrowid
            
            # Add some lessons for each course
            lessons = [
                (course_id, "Section 1: 드론 비행의 4가지 힘", "https://www.youtube.com/embed/8-SSTGoV8O4", "비행에 작용하는 양력, 중력, 추력, 항력의 상호작용 이해.", None, "15:00"),
                (course_id, "Section 2: 주파수 도약(FHSS) 기초 이론", "https://www.youtube.com/embed/example", "보안 통신의 핵심인 FHSS 기술 분석.", "fhss_theory.pdf", "22:30")
            ]
            for cid, ltitle, vurl, lcontent, lmat, ldur in lessons:
                cur.execute("INSERT INTO academy_lessons (course_id, title, video_url, content, material_path, duration) VALUES (%s, %s, %s, %s, %s, %s)", (cid, ltitle, vurl, lcontent, lmat, ldur))

        db.commit()
        print("Academy tables and initial data initialized.")
        db.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    init_academy()
