import MySQLdb

# Database connection details
db_config = {
    'host': 'localhost',
    'user': 'root',
    'passwd': 'password@2532',
    'db': 'drone_db',
    'charset': 'utf8mb4'
}

def init_db():
    try:
        db = MySQLdb.connect(**db_config)
        cur = db.cursor()

        # 1. Users Table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                name VARCHAR(100),
                ssn VARCHAR(20),
                phone VARCHAR(20),
                address TEXT,
                email VARCHAR(100),
                job VARCHAR(100),
                company VARCHAR(100),
                role VARCHAR(20) DEFAULT 'user',
                login_attempts INT DEFAULT 0,
                lock_time TIMESTAMP NULL DEFAULT NULL,
                sec_question TEXT,
                sec_answer TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 2. Notices Table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS notices (
                id INT AUTO_INCREMENT PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                content TEXT,
                file_name VARCHAR(255),
                file_path VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                uuid VARCHAR(36) UNIQUE NOT NULL
            )
        """)

        # 3. Free Board Table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS free_board (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50),
                title VARCHAR(255) NOT NULL,
                content TEXT,
                file_name VARCHAR(255),
                file_path VARCHAR(255),
                views INT DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                uuid VARCHAR(36) UNIQUE NOT NULL
            )
        """)

        # 4. Marketplace Table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS marketplace_items (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50),
                title VARCHAR(255) NOT NULL,
                description TEXT,
                price VARCHAR(50),
                image_path VARCHAR(255),
                status VARCHAR(20) DEFAULT '판매',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                uuid VARCHAR(36) UNIQUE NOT NULL
            )
        """)

        # 5. Academy Courses & Lessons
        cur.execute("""
            CREATE TABLE IF NOT EXISTS academy_courses (
                id INT AUTO_INCREMENT PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                description TEXT,
                category VARCHAR(50)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS academy_lessons (
                id INT AUTO_INCREMENT PRIMARY KEY,
                course_id INT,
                title VARCHAR(255) NOT NULL,
                video_url VARCHAR(255),
                content TEXT,
                FOREIGN KEY (course_id) REFERENCES academy_courses(id) ON DELETE CASCADE
            )
        """)

        # 6. Audit Logs
        cur.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50),
                action VARCHAR(255),
                ip_address VARCHAR(50),
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 7. Notifications
        cur.execute("""
            CREATE TABLE IF NOT EXISTS notifications (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50),
                message TEXT,
                link VARCHAR(255),
                is_read TINYINT(1) DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 8. Project Recruitment
        cur.execute("""
            CREATE TABLE IF NOT EXISTS project_recruitment (
                id INT AUTO_INCREMENT PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                category VARCHAR(100) NOT NULL,
                author VARCHAR(50) NOT NULL,
                content TEXT,
                status VARCHAR(20) DEFAULT 'Recruiting',
                current_members INT DEFAULT 1,
                target_members INT DEFAULT 4,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                uuid VARCHAR(36) UNIQUE NOT NULL
            )
        """)

        # 9. Comments (Notice & Board)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS notice_comments (
                id INT AUTO_INCREMENT PRIMARY KEY,
                notice_id INT,
                username VARCHAR(50),
                content TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS free_board_comments (
                id INT AUTO_INCREMENT PRIMARY KEY,
                board_id INT,
                username VARCHAR(50),
                content TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 10. Lab Vault (Cloud Storage)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS lab_vault (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50),
                filename VARCHAR(255),
                filepath VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                uuid VARCHAR(36) UNIQUE NOT NULL
            )
        """)

        # 11. Chat Messages
        cur.execute("""
            CREATE TABLE IF NOT EXISTS chat_messages (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50),
                message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Admin User Check & Insert
        cur.execute("SELECT * FROM users WHERE username = 'admin'")
        if not cur.fetchone():
            cur.execute("""
                INSERT INTO users (username, password, name, role, email) 
                VALUES ('admin', 'admin1234', 'Administrator', 'admin', 'admin@dronegard.lab')
            """)
            print("Admin account created (admin / admin1234)")

        db.commit()
        print("All tables created successfully!")
        cur.close()
        db.close()

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    init_db()
