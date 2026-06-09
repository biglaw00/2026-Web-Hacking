import os
from flask import Flask, render_template, request, session, redirect, url_for, flash, send_from_directory
from flask_mysqldb import MySQL
import MySQLdb.cursors
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'dronegard_enterprise_secret_key'
# 🛡️ Secure Cookie Settings for HTTPS/SSL Environment
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'password@2532'
app.config['MYSQL_DB'] = 'drone_db'
# app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
app.config['MYSQL_CHARSET'] = 'utf8mb4' # ✨ Encoding Fix

mysql = MySQL(app)

# 🛡️ Auto-reset Admin account on startup (Self-healing DB configuration)
def auto_init_admin():
    import MySQLdb
    try:
        db = MySQLdb.connect(
            host=app.config['MYSQL_HOST'],
            user=app.config['MYSQL_USER'],
            passwd=app.config['MYSQL_PASSWORD'],
            db=app.config['MYSQL_DB']
        )
        cur = db.cursor()
        cur.execute("SELECT id FROM users WHERE username = 'admin'")
        if not cur.fetchone():
            cur.execute("""
                INSERT INTO users (username, password, name, role, email, ssn, phone, address, company, login_attempts, lock_time)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 0, NULL)
            """, ('admin', 'admin', 'Administrator', 'admin', 'admin@dronegard.lab', '000000-0000000', '010-0000-0000', 'Seoul, Korea', 'DroneGard UAV Lab'))
            db.commit()
            print("Auto-Init: Admin user created.")
        else:
            cur.execute("""
                UPDATE users 
                SET password = %s, login_attempts = 0, lock_time = NULL, role = 'admin'
                WHERE username = 'admin'
            """, ('admin',))
            db.commit()
            print("Auto-Init: Admin user verified/reset.")
        cur.close()
        db.close()
    except Exception as e:
        print(f"Auto-Init Admin Error: {e}")

auto_init_admin()

# 🛠️ Helper: Exception Logger
import traceback
@app.errorhandler(Exception)
def handle_exception(e):
    try:
        log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'error.log')
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(f"--- ERROR AT {datetime.now()} ---\n")
            traceback.print_exc(file=f)
            f.write("\n")
    except Exception as log_err:
        print(f"Failed to log error: {log_err}")
    return f"Internal Server Error: {str(e)}", 500


@app.route('/error_log_view')
def error_log_view():
    try:
        log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'error.log')
        if os.path.exists(log_path):
            with open(log_path, 'r', encoding='utf-8') as f:
                content = f.read()
            return f"<pre>{content}</pre>"
        return "No error log found."
    except Exception as e:
        return f"Error reading log: {str(e)}"
# 🛠️ Helper: Audit Logger
def log_action(action, details=None):
    username = session.get('username', 'Anonymous')
    ip = request.remote_addr
    try:
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO audit_logs (username, action, ip_address, details) VALUES (%s, %s, %s, %s)", (username, action, ip, details))
        mysql.connection.commit()
        cur.close()
    except Exception as e:
        print(f"Log Error: {e}")

# 🛡️ Security Headers: Defense against Clickjacking (Iframe insertion) and other attacks
@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Content-Security-Policy'] = "frame-ancestors 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # 🛡️ Prevent Browser Caching of Sensitive Pages (Back-Button vulnerability fix)
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    return response

# 🛡️ WAF: SQL Injection Attack Detection & Prevention Filter
import re
SQL_INJECTION_PATTERN = re.compile(
    r"(?i)(UNION\s+SELECT|UNION\s+ALL\s+SELECT|SELECT\s+.*\s+FROM|INSERT\s+INTO|UPDATE\s+.*\s+SET|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE|OR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|OR\s+\d+\s*=\s*\d+|\'\s*OR\s*|\"\s*OR\s*|--|#|\/\*|\*\/|SLEEP\(|BENCHMARK\()"
)

@app.before_request
def waf_sql_filter():
    # Only scan form POST inputs, query string arguments, and JSON payloads
    inputs_to_check = []
    
    # 1. Query String parameters
    for k, v in request.args.items():
        inputs_to_check.append((f"QueryParam '{k}'", v))
        
    # 2. Form POST fields
    for k, v in request.form.items():
        # Relax SQL Injection checks for rich text fields to prevent false positives,
        # but keep scanning for high-severity patterns.
        if k in ['content', 'description']:
            if any(p in v.lower() for p in ['union select', 'union all select', 'drop table', 'alter table', 'delete from']):
                inputs_to_check.append((f"RichTextField '{k}'", v))
        else:
            inputs_to_check.append((f"FormField '{k}'", v))
            
    # 3. JSON payloads
    if request.is_json:
        try:
            json_data = request.get_json(silent=True)
            if isinstance(json_data, dict):
                for k, v in json_data.items():
                    if isinstance(v, str):
                        inputs_to_check.append((f"JSONField '{k}'", v))
        except:
            pass

    for label, val in inputs_to_check:
        if val and isinstance(val, str) and SQL_INJECTION_PATTERN.search(val):
            log_action("[SECURITY] SQL Injection Blocked by WAF", f"Source: {label}, Value: {val[:100]}")
            return """
            <div style="font-family: sans-serif; text-align: center; padding: 5rem; color: #334155; background: #f8fafc; min-height: 100vh;">
                <div style="max-width: 600px; margin: 0 auto; background: white; padding: 3rem; border-radius: 20px; box-shadow: 0 10px 30px rgba(0,0,0,0.05); border-top: 4px solid #ef4444;">
                    <span style="font-size: 4rem; color: #ef4444;"><i class="fas fa-shield-halved"></i> 🛡️</span>
                    <h1 style="font-size: 1.75rem; font-weight: 800; color: #1e293b; margin-top: 1.5rem; margin-bottom: 1rem;">보안 인가 위반 및 차단 조치</h1>
                    <p style="font-size: 0.95rem; line-height: 1.6; color: #64748b; margin-bottom: 2rem;">
                        귀하의 요청에서 보안 필터(WAF)에 의해 잠재적인 SQL Injection 인젝션 공격 징후가 감지되어 시스템 보호를 위해 해당 요청이 즉시 차단되었습니다.
                    </p>
                    <div style="background: #f1f5f9; padding: 1rem; border-radius: 8px; font-family: monospace; font-size: 0.8rem; color: #475569; text-align: left; word-break: break-all; margin-bottom: 2rem;">
                        <strong>[검출 정보]</strong>: {label} 에 대한 비정상 패턴 차단
                    </div>
                    <button onclick="window.history.back()" style="background: #0f172a; color: white; border: none; padding: 0.75rem 1.5rem; font-size: 0.9rem; font-weight: 700; border-radius: 8px; cursor: pointer;">이전 페이지로 돌아가기</button>
                </div>
            </div>
            """.format(label=label), 400

# 🛡️ Helper: Render Custom Security Error (Authorization Denied)
def render_security_error(reason, details=None):
    log_action("[SECURITY] Unauthorized Access Attempt", f"Reason: {reason}, Details: {details}")
    return """
    <div style="font-family: sans-serif; text-align: center; padding: 5rem; color: #334155; background: #f8fafc; min-height: 100vh;">
        <div style="max-width: 600px; margin: 0 auto; background: white; padding: 3rem; border-radius: 20px; box-shadow: 0 10px 30px rgba(0,0,0,0.05); border-top: 4px solid #f59e0b;">
            <span style="font-size: 4rem; color: #f59e0b;">⚠️</span>
            <h1 style="font-size: 1.75rem; font-weight: 800; color: #1e293b; margin-top: 1.5rem; margin-bottom: 1rem;">비인가 접근 차단 (403 Forbidden)</h1>
            <p style="font-size: 0.95rem; line-height: 1.6; color: #64748b; margin-bottom: 2rem;">
                요청하신 기능에 대한 서버 측 인가 검증을 진행한 결과, 필요한 권한이 없거나 다른 사용자의 리소스에 대한 접근 권한 변조 시도가 확인되어 접근이 차단되었습니다.
            </p>
            <div style="background: #fef3c7; border: 1px solid #fde68a; padding: 1rem; border-radius: 8px; font-family: monospace; font-size: 0.8rem; color: #b45309; text-align: left; word-break: break-all; margin-bottom: 2rem;">
                <strong>[보안 경고]</strong>: {reason}
            </div>
            <button onclick="window.history.back()" style="background: #0f172a; color: white; border: none; padding: 0.75rem 1.5rem; font-size: 0.9rem; font-weight: 700; border-radius: 8px; cursor: pointer;">이전 페이지로 돌아가기</button>
        </div>
    </div>
    """.format(reason=reason), 403

# 🛡️ Helper: Verify File Content & MIME Signature Integrity
def validate_file_integrity(file_stream, filename):
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    header = file_stream.read(2048)
    file_stream.seek(0) # Reset stream
    
    signatures = {
        'png': b'\x89PNG\r\n\x1a\n',
        'jpg': b'\xff\xd8\xff',
        'jpeg': b'\xff\xd8\xff',
        'gif': b'GIF8',
        'pdf': b'%PDF-',
        'zip': b'PK\x03\x04',
        'docx': b'PK\x03\x04',
    }
    
    if ext in signatures:
        sig = signatures[ext]
        if not header.startswith(sig):
            return False, f"실제 파일 내용이 {ext.upper()} 파일 형식(Magic Bytes)과 일치하지 않습니다."
            
    script_patterns = [
        b'import os', b'import subprocess', b'import sys', b'import socket', b'import pty',
        b'__import__', b'eval(', b'exec(', b'system(', b'popen(', b'subprocess.call',
        b'subprocess.run', b'os.system', b'os.popen', b'#\!/bin/bash', b'#\!/bin/sh',
        b'#\!/usr/bin/env', b'<?php', b'exec_shell', b'shell_exec', b'Invoke-Expression',
        b'iex ', b'powershell'
    ]
    
    header_lower = header.lower()
    for pat in script_patterns:
        if pat in header_lower:
            return False, f"허용되지 않는 실행 스크립트 유형의 문자열('{pat.decode(errors='ignore')}')이 파일에서 탐지되었습니다."
            
    return True, "Success"

# 🛡️ Helper: Render Custom Security Upload Error Page
def render_upload_error(reason, filename):
    log_action("[SECURITY] Malicious File Upload Attempt", f"Filename: {filename}, Reason: {reason}")
    return """
    <div style="font-family: sans-serif; text-align: center; padding: 5rem; color: #334155; background: #f8fafc; min-height: 100vh;">
        <div style="max-width: 600px; margin: 0 auto; background: white; padding: 3rem; border-radius: 20px; box-shadow: 0 10px 30px rgba(0,0,0,0.05); border-top: 4px solid #ef4444;">
            <span style="font-size: 4rem; color: #ef4444;">⚠️</span>
            <h1 style="font-size: 1.75rem; font-weight: 800; color: #1e293b; margin-top: 1.5rem; margin-bottom: 1rem;">악성 파일 탐지 및 가로채기 차단</h1>
            <p style="font-size: 0.95rem; line-height: 1.6; color: #64748b; margin-bottom: 2rem;">
                업로드하신 파일 [{filename}]에 대한 무결성 정밀 검증 결과, 파일의 헤더 시그니처 위변조 또는 잠재적인 시스템 웹쉘/스크립트 실행 코드 삽입 정황이 감지되어 시스템 보호를 위해 파일 영구 격리 및 차단 조치되었습니다.
            </p>
            <div style="background: #fef2f2; border: 1px solid #fee2e2; padding: 1rem; border-radius: 8px; font-family: monospace; font-size: 0.8rem; color: #991b1b; text-align: left; word-break: break-all; margin-bottom: 2rem;">
                <strong>[무결성 오류]</strong>: {reason}
            </div>
            <button onclick="window.history.back()" style="background: #0f172a; color: white; border: none; padding: 0.75rem 1.5rem; font-size: 0.9rem; font-weight: 700; border-radius: 8px; cursor: pointer;">이전 페이지로 돌아가기</button>
        </div>
    </div>
    """.format(filename=filename, reason=reason), 400


# 🛠️ Helper: Add Notification (Alarm)
def add_notification(username, message, link=None):
    try:
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO notifications (username, message, link) VALUES (%s, %s, %s)", (username, message, link))
        mysql.connection.commit()
        cur.close()
    except Exception as e:
        print(f"Notification Error: {e}")

# 🛠️ Helper: Mention Parser
def notify_mentions(content, link):
    import re
    mentions = re.findall(r'@(\w+)', content)
    for username in mentions:
        cur = mysql.connection.cursor()
        cur.execute("SELECT username FROM users WHERE username = %s", [username])
        user = cur.fetchone()
        if user:
            add_notification(username, f"[{session.get('username')}]님이 당신을 언급했습니다: {content[:50]}...", link)
        cur.close()

# 🛠️ Helper: YouTube Embed Fix
def get_youtube_embed(url):
    if not url: return None
    if 'embed' in url: return url
    video_id = None
    if 'youtu.be/' in url: video_id = url.split('/')[-1].split('?')[0]
    elif 'v=' in url: video_id = url.split('v=')[1].split('&')[0]
    return f"https://www.youtube.com/embed/{video_id}" if video_id else url

UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'hwp', 'docx'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ----------------------------------------
# 🏠 1. 메인 홈 (대시보드) - SYNC FIXED
# ----------------------------------------
@app.route('/')
def index():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM notices ORDER BY created_at DESC")
    notices = cur.fetchall()
    cur.execute("SELECT * FROM free_board ORDER BY created_at DESC LIMIT 5")
    posts = cur.fetchall()
    
    # 💎 Marketplace Sync Fix: Pass 'items' to index
    cur.execute("SELECT * FROM marketplace_items ORDER BY created_at DESC")
    items = cur.fetchall()
    
    cur.execute("SELECT COUNT(*) FROM marketplace_items")
    market_count = cur.fetchone()[0]
    
    cur.execute("SELECT COUNT(*) FROM academy_courses")
    academy_count = cur.fetchone()[0]
    
    cur.close()
    return render_template('index.html', notices=notices, posts=posts, items=items, market_count=market_count, academy_count=academy_count)

# ----------------------------------------
# 👤 2. 프로필 & 개인정보 관리
# ----------------------------------------
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    cur = mysql.connection.cursor()
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        job = request.form.get('job', '')
        company = request.form.get('company', '')
        
        sec_question = request.form.get('sec_question', '')
        sec_answer = request.form.get('sec_answer', '')
        
        cur.execute("UPDATE users SET name=%s, email=%s, job=%s, company=%s, sec_question=%s, sec_answer=%s WHERE username=%s", 
                    (name, email, job, company, sec_question, sec_answer, session.get('username')))
        mysql.connection.commit()
        flash("프로필 정보가 업데이트되었습니다.", "success")
        return redirect(url_for('profile'))
    
    cur.execute("SELECT * FROM users WHERE username = %s", [session.get('username')])
    user = cur.fetchone()
    cur.close()
    return render_template('profile.html', user=user)

# ----------------------------------------
# 🔐 3. Lab Vault (개인 클라우드 시스템)
# ----------------------------------------
@app.route('/vault')
def vault_list():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM lab_vault WHERE username = %s ORDER BY created_at DESC", [session.get('username')])
    files = cur.fetchall()
    cur.close()
    return render_template('vault.html', files=files)

@app.route('/vault/upload', methods=['POST'])
def vault_upload():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    if 'file' not in request.files:
        return redirect(request.url)
    
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    
    if file:
        # File Integrity Check
        is_valid, reason = validate_file_integrity(file, file.filename)
        if not is_valid:
            return render_upload_error(reason, file.filename)

        filename = secure_filename(file.filename)
        # Store in user-specific folder for extra safety
        user_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'vault', session.get('username'))
        if not os.path.exists(user_dir):
            os.makedirs(user_dir)
            
        filepath = os.path.join(user_dir, filename)
        file.save(filepath)
        
        import uuid
        file_uuid = str(uuid.uuid4())
        
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO lab_vault (username, filename, filepath, uuid) VALUES (%s, %s, %s, %s)", 
                    (session.get('username'), filename, filepath, file_uuid))
        mysql.connection.commit()
        cur.close()
        flash("파일이 Lab Vault에 안전하게 저장되었습니다.", "success")
        
    return redirect(url_for('vault_list'))

@app.route('/vault/delete/<string:uuid>', methods=['POST'])
def vault_delete(uuid):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    cur = mysql.connection.cursor()
    cur.execute("SELECT username, filepath FROM lab_vault WHERE uuid = %s", [uuid])
    file_data = cur.fetchone()
    
    if not file_data:
        cur.close()
        flash("파일을 찾을 수 없습니다.", "danger")
        return redirect(url_for('vault_list'))
        
    # Server-side Authorization Check
    if file_data[0] != session.get('username') and session.get('role') != 'admin':
        cur.close()
        return render_security_error("타인의 Lab Vault 파일에 대한 삭제 권한이 없습니다.", f"User: {session.get('username')}, Owner: {file_data[0]}")
    
    try:
        if os.path.exists(file_data[1]):
            os.remove(file_data[1])
    except Exception as e:
        print(f"File Delete Error: {e}")
        
    cur.execute("DELETE FROM lab_vault WHERE uuid = %s", [uuid])
    mysql.connection.commit()
    cur.close()
    flash("파일이 삭제되었습니다.", "success")
    return redirect(url_for('vault_list'))

# ----------------------------------------
# 📢 4. 공지사항 (드론보안)
# ----------------------------------------
@app.route('/notice')
def notice_list():
    if not session.get('logged_in'):
        flash("로그인이 필요한 서비스입니다.", "danger")
        return redirect(url_for('index'))
    
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM notices ORDER BY created_at DESC")
    notices = cur.fetchall()
    cur.close()
    return render_template('notice_list.html', notices=notices)

@app.route('/notice/<string:uuid>')
def notice_detail(uuid):
    if not session.get('logged_in'): return redirect(url_for('login'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM notices WHERE uuid = %s", [uuid])
    notice = cur.fetchone()
    if not notice:
        cur.close()
        flash("공지글을 찾을 수 없습니다.", "danger")
        return redirect(url_for('notice_list'))
        
    cur.execute("SELECT * FROM notice_comments WHERE notice_id = %s ORDER BY created_at ASC", [notice[0]])
    comments = cur.fetchall()
    cur.close()
    log_action(f"Viewed Notice: {notice[0]}")
    return render_template('notice_detail.html', notice=notice, comments=comments)

@app.route('/notice/comment/<string:uuid>', methods=['POST'])
def add_comment(uuid):
    if not session.get('logged_in'): return redirect(url_for('login'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT id FROM notices WHERE uuid = %s", [uuid])
    notice = cur.fetchone()
    if not notice:
        cur.close()
        flash("공지글을 찾을 수 없습니다.", "danger")
        return redirect(url_for('notice_list'))
        
    content = request.form.get('content')
    cur.execute("INSERT INTO notice_comments (notice_id, username, content) VALUES (%s, %s, %s)", 
                (notice[0], session['username'], content))
    mysql.connection.commit()
    cur.close()
    link = url_for('notice_detail', uuid=uuid)
    notify_mentions(content, link)
    log_action("[NOTICE] Add Comment", f"Notice UUID: {uuid}, Content: {content[:100]}")
    return redirect(url_for('notice_detail', uuid=uuid))

@app.route('/notice/comment/delete/<int:cid>', methods=['POST'])
def notice_comment_delete(cid):
    if not session.get('logged_in'): return redirect(url_for('login'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT c.username, n.uuid FROM notice_comments c JOIN notices n ON c.notice_id = n.id WHERE c.id = %s", [cid])
    comment = cur.fetchone()
    
    if not comment:
        cur.close()
        flash("댓글을 찾을 수 없습니다.", "danger")
        return redirect(url_for('notice_list'))
        
    # Server-side Authorization Check
    if comment[0] != session.get('username') and session.get('role') != 'admin':
        cur.close()
        return render_security_error("타인의 공지사항 댓글에 대한 삭제 권한이 없습니다.", f"User: {session.get('username')}, Owner: {comment[0]}")
        
    cur.execute("DELETE FROM notice_comments WHERE id = %s", [cid])
    mysql.connection.commit()
    cur.close()
    log_action("Deleted Notice Comment", f"Comment ID: {cid}")
    return redirect(url_for('notice_detail', uuid=comment[1]))

@app.route('/notice/comment/edit/<int:cid>', methods=['POST'])
def notice_comment_edit(cid):
    if not session.get('logged_in'): return redirect(url_for('login'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT c.username, n.uuid FROM notice_comments c JOIN notices n ON c.notice_id = n.id WHERE c.id = %s", [cid])
    comment = cur.fetchone()
    
    if not comment:
        cur.close()
        flash("댓글을 찾을 수 없습니다.", "danger")
        return redirect(url_for('notice_list'))
        
    # Server-side Authorization Check
    if comment[0] != session.get('username') and session.get('role') != 'admin':
        cur.close()
        return render_security_error("타인의 공지사항 댓글에 대한 수정 권한이 없습니다.", f"User: {session.get('username')}, Owner: {comment[0]}")
        
    content = request.form.get('content')
    cur.execute("UPDATE notice_comments SET content = %s WHERE id = %s", (content, cid))
    mysql.connection.commit()
    cur.close()
    log_action("Edited Notice Comment", f"Comment ID: {cid}")
    return redirect(url_for('notice_detail', uuid=comment[1]))

@app.route('/notice/add', methods=['GET', 'POST'])
def notice_add():
    if session.get('role') != 'admin':
        return render_security_error("공지사항 등록 권한이 없습니다.", "Admin role required")
    
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        
        # 🛡️ Input length validation to prevent DB errors and server crash
        if len(title) > 255:
            flash("제목이 너무 깁니다. (최대 255자)", "danger")
            return redirect(url_for('notice_add'))
        if len(content) > 65535:
            flash("내용이 너무 깁니다. (최대 65,535자)", "danger")
            return redirect(url_for('notice_add'))
            
        file = request.files.get('file')
        file_name, file_path = None, None
        
        if file and file.filename != '':
            # File Integrity Check
            is_valid, reason = validate_file_integrity(file, file.filename)
            if not is_valid:
                return render_upload_error(reason, file.filename)
            file_name = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_name)
            file.save(file_path)
            
        import uuid
        notice_uuid = str(uuid.uuid4())
        
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO notices (title, content, file_name, file_path, uuid) VALUES (%s, %s, %s, %s, %s)", 
                    (title, content, file_name, file_name, notice_uuid))
        mysql.connection.commit()
        cur.close()
        log_action("[NOTICE] Created", f"Title: {title}")
        return redirect(url_for('notice_list'))
    return render_template('notice_form.html')

@app.route('/notice/delete/<string:uuid>', methods=['POST'])
def notice_delete(uuid):
    if session.get('role') != 'admin':
        return render_security_error("공지사항 삭제 권한이 없습니다.", "Admin role required")
        
    cur = mysql.connection.cursor()
    cur.execute("SELECT id FROM notices WHERE uuid = %s", [uuid])
    notice = cur.fetchone()
    if not notice:
        cur.close()
        flash("공지글을 찾을 수 없습니다.", "danger")
        return redirect(url_for('notice_list'))
        
    cur.execute("DELETE FROM notices WHERE uuid = %s", [uuid])
    mysql.connection.commit()
    cur.close()
    log_action(f"Deleted Notice UUID: {uuid}")
    flash("공지사항이 삭제되었습니다.", "success")
    return redirect(url_for('notice_list'))

@app.route('/notice/edit/<string:uuid>', methods=['GET', 'POST'])
def notice_edit(uuid):
    if session.get('role') != 'admin':
        return render_security_error("공지사항 수정 권한이 없습니다.", "Admin role required")
        
    cur = mysql.connection.cursor()
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        cur.execute("UPDATE notices SET title=%s, content=%s WHERE uuid=%s", (title, content, uuid))
        mysql.connection.commit()
        cur.close()
        log_action(f"Edited Notice UUID: {uuid}")
        return redirect(url_for('notice_detail', uuid=uuid))
    
    cur.execute("SELECT * FROM notices WHERE uuid = %s", [uuid])
    notice = cur.fetchone()
    cur.close()
    if not notice:
        flash("공지글을 찾을 수 없습니다.", "danger")
        return redirect(url_for('notice_list'))
    return render_template('notice_form.html', notice=notice)

# ----------------------------------------
# 📋 5. 게시판 (포럼)
# ----------------------------------------
@app.route('/board')
def board_list():
    if not session.get('logged_in'): return redirect(url_for('index'))
    cur = mysql.connection.cursor()
    # ⚠️ VULNERABILITY: SQL Injection possible via raw string if params were used
    cur.execute("SELECT * FROM free_board ORDER BY created_at DESC")
    posts = cur.fetchall()
    cur.close()
    return render_template('board_list.html', posts=posts)

@app.route('/board/<string:uuid>')
def board_detail(uuid):
    if not session.get('logged_in'): return redirect(url_for('login'))
    cur = mysql.connection.cursor()
    
    # Check if post exists
    cur.execute("SELECT * FROM free_board WHERE uuid = %s", [uuid])
    post = cur.fetchone()
    if not post:
        cur.close()
        flash("게시글을 찾을 수 없습니다.", "danger")
        return redirect(url_for('board_list'))

    # Record View Count
    cur.execute("UPDATE free_board SET views = views + 1 WHERE uuid = %s", [uuid])
    mysql.connection.commit()
    
    cur.execute("SELECT * FROM free_board_comments WHERE board_id = %s ORDER BY created_at ASC", [post[0]])
    comments = cur.fetchall()
    cur.close()
    log_action("[BOARD] View Post", f"Post UUID: {uuid}")
    return render_template('board_detail.html', post=post, comments=comments)

@app.route('/board/comment/<string:uuid>', methods=['POST'])
def board_comment(uuid):
    if not session.get('logged_in'): return redirect(url_for('login'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT id FROM free_board WHERE uuid = %s", [uuid])
    post = cur.fetchone()
    if not post:
        cur.close()
        flash("게시글을 찾을 수 없습니다.", "danger")
        return redirect(url_for('board_list'))
        
    content = request.form.get('content')
    cur.execute("INSERT INTO free_board_comments (board_id, username, content) VALUES (%s, %s, %s)", 
                (post[0], session['username'], content))
    mysql.connection.commit()
    cur.close()
    link = url_for('board_detail', uuid=uuid)
    notify_mentions(content, link)
    log_action("[BOARD] Add Comment", f"Post UUID: {uuid}, Content: {content[:100]}")
    return redirect(url_for('board_detail', uuid=uuid))

@app.route('/board/comment/delete/<int:cid>', methods=['POST'])
def board_comment_delete(cid):
    if not session.get('logged_in'): return redirect(url_for('login'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT c.username, b.uuid FROM free_board_comments c JOIN free_board b ON c.board_id = b.id WHERE c.id = %s", [cid])
    comment = cur.fetchone()
    
    if not comment:
        cur.close()
        flash("댓글을 찾을 수 없습니다.", "danger")
        return redirect(url_for('board_list'))
        
    # Server-side Authorization Check
    if comment[0] != session.get('username') and session.get('role') != 'admin':
        cur.close()
        return render_security_error("타인의 게시판 댓글에 대한 삭제 권한이 없습니다.", f"User: {session.get('username')}, Owner: {comment[0]}")
        
    cur.execute("DELETE FROM free_board_comments WHERE id = %s", [cid])
    mysql.connection.commit()
    cur.close()
    log_action("Deleted Comment", f"Comment ID: {cid}")
    return redirect(url_for('board_detail', uuid=comment[1]))

@app.route('/board/comment/edit/<int:cid>', methods=['POST'])
def board_comment_edit(cid):
    if not session.get('logged_in'): return redirect(url_for('login'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT c.username, b.uuid FROM free_board_comments c JOIN free_board b ON c.board_id = b.id WHERE c.id = %s", [cid])
    comment = cur.fetchone()
    
    if not comment:
        cur.close()
        flash("댓글을 찾을 수 없습니다.", "danger")
        return redirect(url_for('board_list'))
        
    # Server-side Authorization Check
    if comment[0] != session.get('username') and session.get('role') != 'admin':
        cur.close()
        return render_security_error("타인의 게시판 댓글에 대한 수정 권한이 없습니다.", f"User: {session.get('username')}, Owner: {comment[0]}")
        
    content = request.form.get('content')
    cur.execute("UPDATE free_board_comments SET content = %s WHERE id = %s", (content, cid))
    mysql.connection.commit()
    cur.close()
    log_action("Edited Comment", f"Comment ID: {cid}")
    return redirect(url_for('board_detail', uuid=comment[1]))

@app.route('/board/add', methods=['GET', 'POST'])
def board_add():
    if not session.get('logged_in'): return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        
        # 🛡️ Input length validation to prevent DB errors and server crash
        if len(title) > 255:
            flash("제목이 너무 깁니다. (최대 255자)", "danger")
            return redirect(url_for('board_add'))
        if len(content) > 65535:
            flash("내용이 너무 깁니다. (최대 65,535자)", "danger")
            return redirect(url_for('board_add'))
            
        file = request.files.get('file')
        file_name, file_path = None, None
        if file and file.filename != '':
            if allowed_file(file.filename):
                # File Integrity Check
                is_valid, reason = validate_file_integrity(file, file.filename)
                if not is_valid:
                    return render_upload_error(reason, file.filename)
                file_name = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], file_name))
            else:
                flash("허용되지 않은 파일 형식입니다. (txt, pdf, png, jpg, zip 등만 가능)", "danger")
                log_action("Blocked Malicious Board Upload", f"Filename: {file.filename}")
                return redirect(url_for('board_add'))
            
        import uuid
        post_uuid = str(uuid.uuid4())
        
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO free_board (username, title, content, file_name, file_path, uuid) VALUES (%s, %s, %s, %s, %s, %s)", 
                    (session['username'], title, content, file_name, file_name, post_uuid))
        mysql.connection.commit()
        cur.close()
        log_action("[BOARD] Created", f"Title: {title}")
        return redirect(url_for('board_list'))
    return render_template('board_form.html')

@app.route('/board/delete/<string:uuid>', methods=['POST'])
def board_delete(uuid):
    if not session.get('logged_in'): return redirect(url_for('login'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT username FROM free_board WHERE uuid = %s", [uuid])
    post = cur.fetchone()
    if not post:
        cur.close()
        flash("게시글을 찾을 수 없습니다.", "danger")
        return redirect(url_for('board_list'))
        
    # Server-side Authorization Check
    if post[0] != session.get('username') and session.get('role') != 'admin':
        cur.close()
        return render_security_error("타인의 자유게시판 게시글에 대한 삭제 권한이 없습니다.", f"User: {session.get('username')}, Owner: {post[0]}")
        
    cur.execute("DELETE FROM free_board WHERE uuid = %s", [uuid])
    mysql.connection.commit()
    cur.close()
    log_action(f"Deleted Board Post UUID: {uuid}")
    flash("게시글이 삭제되었습니다.", "success")
    return redirect(url_for('board_list'))

@app.route('/board/edit/<string:uuid>', methods=['GET', 'POST'])
def board_edit(uuid):
    if not session.get('logged_in'): return redirect(url_for('login'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM free_board WHERE uuid = %s", [uuid])
    post = cur.fetchone()
    
    if not post:
        cur.close()
        flash("게시글을 찾을 수 없습니다.", "danger")
        return redirect(url_for('board_list'))
        
    # Server-side Authorization Check
    if post[1] != session.get('username') and session.get('role') != 'admin':
        cur.close()
        return render_security_error("타인의 자유게시판 게시글에 대한 수정 권한이 없습니다.", f"User: {session.get('username')}, Owner: {post[1]}")

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        cur.execute("UPDATE free_board SET title=%s, content=%s WHERE uuid=%s", (title, content, uuid))
        mysql.connection.commit()
        cur.close()
        log_action(f"Edited Board Post UUID: {uuid}")
        return redirect(url_for('board_detail', uuid=uuid))
    
    cur.close()
    return render_template('board_form.html', post=post)

# ----------------------------------------
# 🛒 6. 중고시장
# ----------------------------------------
@app.route('/market')
def market_list():
    if not session.get('logged_in'): return redirect(url_for('index'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM marketplace_items ORDER BY created_at DESC")
    items = cur.fetchall()
    cur.close()
    log_action("Viewed Marketplace")
    return render_template('market_list.html', items=items)

@app.route('/market/<string:uuid>')
def market_detail(uuid):
    if not session.get('logged_in'): return redirect(url_for('login'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM marketplace_items WHERE uuid = %s", [uuid])
    item = cur.fetchone()
    cur.close()
    if not item:
        flash("상품을 찾을 수 없습니다.", "danger")
        return redirect(url_for('market_list'))
    return render_template('market_detail.html', item=item)

@app.route('/market/add', methods=['GET', 'POST'])
def market_add():
    if not session.get('logged_in'): return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        
        # 🛡️ Input length validation to prevent DB errors and server crash
        if len(title) > 255:
            flash("상품명이 너무 깁니다. (최대 255자)", "danger")
            return redirect(url_for('market_add'))
        if len(description) > 65535:
            flash("설명이 너무 깁니다. (최대 65,535자)", "danger")
            return redirect(url_for('market_add'))
        if len(price) > 50:
            flash("가격 입력값이 너무 깁니다. (최대 50자)", "danger")
            return redirect(url_for('market_add'))
            
        file = request.files.get('file')
        image_path = None
        if file and file.filename != '':
            if allowed_file(file.filename):
                # File Integrity Check
                is_valid, reason = validate_file_integrity(file, file.filename)
                if not is_valid:
                    return render_upload_error(reason, file.filename)
                image_path = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], image_path))
            else:
                flash("허용되지 않은 파일 형식입니다. 보안 정책에 의해 차단되었습니다.", "danger")
                log_action("Malicious File Upload Blocked", f"Filename: {file.filename}")
                return redirect(url_for('market_add'))
        
        import uuid
        item_uuid = str(uuid.uuid4())
        
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO marketplace_items (username, title, description, price, image_path, uuid) VALUES (%s, %s, %s, %s, %s, %s)",
                    (session['username'], title, description, price, image_path, item_uuid))
        mysql.connection.commit()
        cur.close()
        log_action("Created Market Item")
        return redirect(url_for('market_list'))
    return render_template('market_form.html')

@app.route('/market/delete/<string:uuid>', methods=['POST'])
def market_delete(uuid):
    if not session.get('logged_in'): return redirect(url_for('login'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT username FROM marketplace_items WHERE uuid = %s", [uuid])
    item = cur.fetchone()
    if not item:
        cur.close()
        flash("상품을 찾을 수 없습니다.", "danger")
        return redirect(url_for('market_list'))
        
    # Server-side Authorization Check
    if item[0] != session.get('username') and session.get('role') != 'admin':
        cur.close()
        return render_security_error("타인의 중고 거래 게시글에 대한 삭제 권한이 없습니다.", f"User: {session.get('username')}, Owner: {item[0]}")
        
    cur.execute("DELETE FROM marketplace_items WHERE uuid = %s", [uuid])
    mysql.connection.commit()
    cur.close()
    log_action(f"Deleted Market Item UUID: {uuid}")
    flash("매물이 삭제되었습니다.", "success")
    return redirect(url_for('market_list'))

@app.route('/market/edit/<string:uuid>', methods=['GET', 'POST'])
def market_edit(uuid):
    if not session.get('logged_in'): return redirect(url_for('login'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM marketplace_items WHERE uuid = %s", [uuid])
    item = cur.fetchone()
    
    if not item:
        cur.close()
        flash("상품을 찾을 수 없습니다.", "danger")
        return redirect(url_for('market_list'))
        
    # Server-side Authorization Check
    if item[1] != session.get('username') and session.get('role') != 'admin':
        cur.close()
        return render_security_error("타인의 중고 거래 게시글에 대한 수정 권한이 없습니다.", f"User: {session.get('username')}, Owner: {item[1]}")

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        cur.execute("UPDATE marketplace_items SET title=%s, description=%s, price=%s WHERE uuid=%s", (title, description, price, uuid))
        mysql.connection.commit()
        cur.close()
        log_action(f"Edited Market Item UUID: {uuid}")
        return redirect(url_for('market_detail', uuid=uuid))
    
    cur.close()
    return render_template('market_form.html', item=item)

# ----------------------------------------
# 🎓 7. Aero Academy (학습 센터)
# ----------------------------------------
@app.route('/academy')
def academy_list():
    if not session.get('logged_in'): return redirect(url_for('index'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM academy_courses ORDER BY id ASC")
    courses = cur.fetchall()
    cur.close()
    return render_template('academy_list.html', courses=courses)

@app.route('/academy/course/<int:id>')
def academy_course(id):
    if not session.get('logged_in'): return redirect(url_for('login'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM academy_courses WHERE id = %s", [id])
    course = cur.fetchone()
    cur.execute("SELECT * FROM academy_lessons WHERE course_id = %s ORDER BY id ASC", [id])
    lessons = cur.fetchall()
    cur.close()
    return render_template('academy_detail.html', course=course, lessons=lessons)

@app.route('/academy/lesson/<int:id>')
def academy_lesson(id):
    if not session.get('logged_in'): return redirect(url_for('login'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM academy_lessons WHERE id = %s", [id])
    lesson = cur.fetchone()
    if not lesson:
        cur.close()
        flash("유효하지 않은 강의입니다.", "danger")
        return redirect(url_for('academy_list'))
        
    # ✨ YouTube Embed Fix
    processed_url = get_youtube_embed(lesson[3])
    # Convert tuple to list to modify
    lesson_list = list(lesson)
    lesson_list[3] = processed_url
    lesson = tuple(lesson_list)

    # Get course info for breadcrumbs/sidebar
    cur.execute("SELECT * FROM academy_courses WHERE id = %s", [lesson[1]])
    course = cur.fetchone()
    cur.execute("SELECT id, title FROM academy_lessons WHERE course_id = %s ORDER BY id ASC", [lesson[1]])
    all_lessons = cur.fetchall()
    cur.close()
    log_action(f"Viewed Lesson: {lesson[2]}")
    return render_template('academy_viewer.html', lesson=lesson, course=course, all_lessons=all_lessons)

# ----------------------------------------
# 💬 8. 실시간 채팅 & GARD-AI
# ----------------------------------------
@app.route('/chat/get')
def get_chat():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM chat_messages ORDER BY created_at ASC LIMIT 50")
    msgs = cur.fetchall()
    cur.close()
    return {'messages': [{'username': m[1], 'message': m[2], 'time': m[3].strftime('%H:%M:%S')} for m in msgs]}

@app.route('/chat/send', methods=['POST'])
def send_chat():
    if not session.get('logged_in'): return {'status': 'error'}
    msg = request.form.get('message')
    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO chat_messages (username, message) VALUES (%s, %s)", (session['username'], msg))
    mysql.connection.commit()
    cur.close()
    return {'status': 'success'}

@app.route('/ai_chatbot', methods=['POST'])
def ai_chatbot():
    if not session.get('logged_in'): return {'status': 'error'}, 403
    user_msg = request.json.get('message', '').lower()
    response = "DroneGard Lab 데이터베이스에서 해당 쿼리를 찾지 못했습니다. 보안 기술 위협에 대해 질문해 주십시오."
    if '안녕' in user_msg or 'hello' in user_msg:
        response = "반갑습니다. DroneGard UAV Lab의 지능형 보안 엔진 **GARD-AI**입니다. 무엇을 도와드릴까요?"
    elif '재밍' in user_msg: response = "재밍방어 기술인 FHSS와 빔포밍을 연구 중입니다."
    elif '스푸핑' in user_msg: response = "GPS 위조 신호를 탐지하는 알고리즘이 가동 중입니다."
    log_action("[AI_CHAT] Query", f"User: {user_msg[:100]}, Bot: {response[:50]}...")
    return {'status': 'success', 'response': response}

# ----------------------------------------
# 🚀 9. Project Lab (팀 빌딩 & 스터디 모집)
# ----------------------------------------
@app.route('/projects')
def project_list():
    if not session.get('logged_in'): return redirect(url_for('index'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM project_recruitment ORDER BY created_at DESC")
    projects = cur.fetchall()
    cur.close()
    return render_template('project_list.html', projects=projects)

@app.route('/projects/add', methods=['GET', 'POST'])
def project_add():
    if not session.get('logged_in'): return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        category = request.form['category']
        target_members = request.form['target_members']
        content = request.form['content']
        
        import uuid
        project_uuid = str(uuid.uuid4())
        
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO project_recruitment (title, category, author, content, target_members, uuid) VALUES (%s, %s, %s, %s, %s, %s)",
                    (title, category, session['username'], content, target_members, project_uuid))
        mysql.connection.commit()
        cur.close()
        log_action("Created Project", f"Title: {title}")
        return redirect(url_for('project_list'))
    return render_template('project_form.html')

@app.route('/projects/<string:uuid>')
def project_detail(uuid):
    if not session.get('logged_in'): return redirect(url_for('index'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT p.*, u.email FROM project_recruitment p JOIN users u ON p.author = u.username WHERE p.uuid = %s", [uuid])
    project = cur.fetchone()
    if not project:
        cur.close()
        flash("프로젝트를 찾을 수 없습니다.", "danger")
        return redirect(url_for('project_list'))
        
    cur.execute("SELECT * FROM project_room_comments WHERE project_id = %s ORDER BY created_at ASC", [project[0]])
    comments = cur.fetchall()
    cur.execute("SELECT applicant_username, status, id FROM project_applications WHERE project_id = %s", [project[0]])
    apps = cur.fetchall()
    cur.close()
    return render_template('project_detail.html', project=project, comments=comments, apps=apps)

@app.route('/projects/comment/<string:uuid>', methods=['POST'])
def project_comment(uuid):
    if not session.get('logged_in'): return redirect(url_for('login'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT id FROM project_recruitment WHERE uuid = %s", [uuid])
    project = cur.fetchone()
    if not project:
        cur.close()
        flash("프로젝트를 찾을 수 없습니다.", "danger")
        return redirect(url_for('project_list'))
        
    content = request.form.get('content')
    cur.execute("INSERT INTO project_room_comments (project_id, username, content) VALUES (%s, %s, %s)", 
                (project[0], session['username'], content))
    mysql.connection.commit()
    cur.close()
    link = url_for('project_detail', uuid=uuid)
    notify_mentions(content, link)
    return redirect(url_for('project_detail', uuid=uuid))

@app.route('/projects/apply/<string:uuid>', methods=['POST'])
def project_apply(uuid):
    if not session.get('logged_in'): return redirect(url_for('login'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, author, title FROM project_recruitment WHERE uuid = %s", [uuid])
    project = cur.fetchone()
    if project:
        cur.execute("INSERT INTO project_applications (project_id, applicant_username) VALUES (%s, %s)", (project[0], session['username']))
        mysql.connection.commit()
        add_notification(project[1], f"[{session['username']}]님이 '{project[2]}' 프로젝트에 참여를 신청했습니다.", url_for('project_detail', uuid=uuid))
        flash("참여 신청이 완료되었습니다.", "success")
        cur.close()
        return redirect(url_for('project_detail', uuid=uuid))
    else:
        cur.close()
        flash("프로젝트를 찾을 수 없습니다.", "danger")
        return redirect(url_for('project_list'))

@app.route('/projects/approve/<int:aid>', methods=['POST'])
def project_approve(aid):
    if not session.get('logged_in'): return redirect(url_for('login'))
    cur = mysql.connection.cursor()
    # Check if session user is the owner of the project
    cur.execute("SELECT p.author, a.applicant_username, p.title, p.uuid, p.id FROM project_applications a JOIN project_recruitment p ON a.project_id = p.id WHERE a.id = %s", [aid])
    data = cur.fetchone()
    if data and data[0] == session['username']:
        cur.execute("UPDATE project_applications SET status='accepted' WHERE id = %s", [aid])
        cur.execute("INSERT INTO project_members (project_id, username) VALUES (%s, %s)", (data[4], data[1]))
        mysql.connection.commit()
        add_notification(data[1], f"축하합니다! '{data[2]}' 프로젝트 참여 신청이 승인되었습니다.", url_for('project_detail', uuid=data[3]))
        log_action("Approved Project Member", f"Project: {data[2]}, Member: {data[1]}")
        cur.close()
        return redirect(url_for('project_detail', uuid=data[3]))
    cur.close()
    flash("유효하지 않은 요청이거나 승인 권한이 없습니다.", "danger")
    return redirect(url_for('project_list'))

@app.route('/projects/reject/<int:aid>', methods=['POST'])
def project_reject(aid):
    if not session.get('logged_in'): return redirect(url_for('login'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT p.author, a.applicant_username, p.title, p.uuid FROM project_applications a JOIN project_recruitment p ON a.project_id = p.id WHERE a.id = %s", [aid])
    data = cur.fetchone()
    if data and data[0] == session['username']:
        cur.execute("UPDATE project_applications SET status='rejected' WHERE id = %s", [aid])
        mysql.connection.commit()
        add_notification(data[1], f"안타깝게도 '{data[2]}' 프로젝트 참여 신청이 거절되었습니다.")
        cur.close()
        return redirect(url_for('project_detail', uuid=data[3]))
    cur.close()
    flash("유효하지 않은 요청이거나 거절 권한이 없습니다.", "danger")
    return redirect(url_for('project_list'))
@app.route('/notifications')
def notifications():
    if not session.get('logged_in'): return redirect(url_for('index'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM notifications WHERE username=%s ORDER BY created_at DESC", [session['username']])
    notifs = cur.fetchall()
    cur.execute("UPDATE notifications SET is_read=1 WHERE username=%s", [session['username']])
    mysql.connection.commit()
    cur.close()
    return render_template('notifications.html', notifications=notifs)

@app.route('/notifications/delete/<int:nid>', methods=['POST'])
def delete_notification(nid):
    if not session.get('logged_in'): return redirect(url_for('login'))
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM notifications WHERE id = %s AND username = %s", (nid, session['username']))
    mysql.connection.commit()
    cur.close()
    return redirect(url_for('notifications'))

# ----------------------------------------
# 📞 10. Support Center (고객 지원)
# ----------------------------------------
@app.route('/support')
def support_center():
    if not session.get('logged_in'): return redirect(url_for('index'))
    return render_template('support.html')

@app.route('/support/contact', methods=['POST'])
def support_contact():
    if not session.get('logged_in'): return redirect(url_for('login'))
    name = request.form.get('name')
    email = request.form.get('email')
    subject = request.form.get('subject')
    message = request.form.get('message')
    
    # Notify admin
    admin_msg = f"[Support] '{name}'님으로부터 새로운 문의: {subject}"
    add_notification('admin', admin_msg, url_for('admin_logs')) # Or a specific ticket view if it existed
    
    flash("문의가 성공적으로 접수되었습니다. 관리자가 검토 후 연락드리겠습니다.", "success")
    log_action("[SUPPORT] New Inquiry", f"From: {name}, Subject: {subject}")
    return redirect(url_for('support_center'))

@app.route('/privacy')
def privacy_policy():
    return render_template('privacy.html')

# ----------------------------------------
# 🔑 11. 회원가입 & 로그인
# ----------------------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        u, p = request.form['username'], request.form['password']
        n, ph = request.form['name'], request.form['phone']
        e, j, c = request.form['email'], request.form.get('job',''), request.form.get('company','')
        sq, sa = request.form.get('sec_question'), request.form.get('sec_answer')
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users (username, password, name, ssn, phone, address, email, job, company, role, sec_question, sec_answer) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'user', %s, %s)",
                    (u, p, n, '000000-0000000', ph, request.form['address'], e, j, c, sq, sa))
        mysql.connection.commit()
        cur.close()
        return "<script>alert('등록되었습니다.'); if (window.opener && !window.opener.closed) { window.close(); } else { window.location.href = '/login'; }</script>"
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u, p = request.form['username'], request.form['password']
        cur = mysql.connection.cursor()
        
        # Parameterized query to prevent SQL Injection
        cur.execute("SELECT * FROM users WHERE username = %s", [u])
        user = cur.fetchone()
        
        if user:
            user_id = user[0]
            username = user[1]
            db_password = user[2]
            role = user[10]
            login_attempts = user[11] or 0
            lock_time = user[12]
            
            # Check Account Lockout State (Locked for 5 minutes)
            if lock_time:
                from datetime import datetime, timedelta
                if isinstance(lock_time, str):
                    try:
                        lock_time = datetime.strptime(lock_time, '%Y-%m-%d %H:%M:%S')
                    except ValueError:
                        pass
                if isinstance(lock_time, datetime):
                    if lock_time.tzinfo is not None:
                        lock_time = lock_time.replace(tzinfo=None)
                    now = datetime.now()
                    if now < lock_time + timedelta(minutes=5):
                        log_action("[SECURITY] Locked Account Login Attempt", f"Username: {u}")
                        flash("연속된 로그인 실패로 인해 계정이 잠겼습니다. 5분 후에 다시 시도해 주십시오.", "danger")
                        cur.close()
                        return render_template('login.html')
            
            # Verify Password
            if db_password == p:
                # Reset login attempts & lock time on success
                cur.execute("UPDATE users SET login_attempts = 0, lock_time = NULL WHERE id = %s", [user_id])
                mysql.connection.commit()
                session.permanent = True
                session.update({'logged_in': True, 'username': username, 'role': role})
                log_action("[AUTH] Login Success")
                cur.close()
                return "<script>if (window.opener && !window.opener.closed) { try { window.opener.location.reload(); } catch(e) {} window.close(); } else { window.location.href = '/'; }</script>"
            else:
                # Increment failed login attempts
                new_attempts = login_attempts + 1
                if new_attempts >= 5:
                    cur.execute("UPDATE users SET login_attempts = %s, lock_time = CURRENT_TIMESTAMP WHERE id = %s", (new_attempts, user_id))
                    mysql.connection.commit()
                    log_action("[SECURITY] Account Locked", f"Username: {u} (5 failed attempts)")
                    flash("로그인에 실패하였습니다. 5회 연속 실패하여 계정이 5분간 잠깁니다.", "danger")
                else:
                    cur.execute("UPDATE users SET login_attempts = %s WHERE id = %s", (new_attempts, user_id))
                    mysql.connection.commit()
                    log_action("[AUTH] Login Failed", f"Attempted Username: {u} (Failure count: {new_attempts}/5)")
                    flash(f"로그인 정보가 올바르지 않습니다. (실패 횟수: {new_attempts}/5)", "danger")
        else:
            log_action("[AUTH] Login Failed", f"Attempted Username: {u} (User not found)")
            flash("로그인 정보가 올바르지 않습니다.", "danger")
            
        cur.close()
    return render_template('login.html')

@app.route('/notifications/count')
def notif_count():
    if not session.get('logged_in'): return {'count': 0}
    cur = mysql.connection.cursor()
    cur.execute("SELECT COUNT(*) FROM notifications WHERE username=%s AND is_read=0", [session['username']])
    count = cur.fetchone()[0]
    cur.close()
    return {'count': count}

@app.route('/admin/logs')
def admin_logs():
    if session.get('role') != 'admin':
        flash("관리자만 접근 가능합니다.", "danger")
        return redirect(url_for('index'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 200")
    logs = cur.fetchall()
    cur.close()
    return render_template('admin_logs.html', logs=logs)

@app.route('/admin/logs/delete/<int:log_id>', methods=['POST'])
def admin_delete_log(log_id):
    if session.get('role') != 'admin':
        flash("관리자만 접근 가능합니다.", "danger")
        return redirect(url_for('index'))
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM audit_logs WHERE id = %s", [log_id])
    mysql.connection.commit()
    cur.close()
    flash("선택한 감사 로그가 삭제되었습니다.", "success")
    return redirect(url_for('admin_logs'))

@app.route('/admin/logs/clear', methods=['POST'])
def admin_clear_logs():
    if session.get('role') != 'admin':
        flash("관리자만 접근 가능합니다.", "danger")
        return redirect(url_for('index'))
    cur = mysql.connection.cursor()
    cur.execute("TRUNCATE TABLE audit_logs")
    mysql.connection.commit()
    cur.close()
    flash("모든 감사 로그가 초기화되었습니다.", "success")
    return redirect(url_for('admin_logs'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# ----------------------------------------
# 🔑 12. 계정 찾기 (ID/PW)
# ----------------------------------------
@app.route('/find_account', methods=['GET', 'POST'])
def find_account():
    if request.method == 'POST':
        action = request.form.get('action')
        cur = mysql.connection.cursor()
        
        if action == 'find_id':
            email = request.form.get('email')
            name = request.form.get('name')
            # Parameterized Query to prevent SQL Injection
            cur.execute("SELECT username FROM users WHERE email = %s AND name = %s", (email, name))
            user = cur.fetchone()
            if user: flash(f"찾으시는 아이디는 [{user[0]}] 입니다.", "success")
            else: flash("일치하는 계정 정보가 없습니다. (이름/이메일 확인 요망)", "danger")
            
        elif action == 'get_question':
            username = request.form.get('username')
            email = request.form.get('email')
            cur.execute("SELECT sec_question FROM users WHERE username=%s AND email=%s", (username, email))
            user = cur.fetchone()
            if user:
                return render_template('find_account.html', question=user[0], username=username, email=email)
            else:
                flash("계정 정보를 찾을 수 없습니다.", "danger")
                
        elif action == 'reset_pw':
            username = request.form.get('username')
            email = request.form.get('email')
            answer = request.form.get('sec_answer')
            new_pw = request.form.get('new_password')
            
            cur.execute("SELECT id FROM users WHERE username=%s AND email=%s AND sec_answer=%s", (username, email, answer))
            if cur.fetchone():
                cur.execute("UPDATE users SET password=%s WHERE username=%s", (new_pw, username))
                mysql.connection.commit()
                flash("비밀번호가 성공적으로 재설정되었습니다.", "success")
            else:
                flash("보안 질문의 답변이 일치하지 않습니다.", "danger")
                
        cur.close()
        return render_template('find_account.html')
    return render_template('find_account.html')

@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(debug=True, port=5000)