from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from datetime import datetime
import bcrypt
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your_very_strong_secret_key_here'

# تنظیمات مدیر سیستم + 5 کاربر دیگر (مجموعاً 6 کاربر)
PREDEFINED_USERS = {
    'admin': 'admin123',  # مدیر سیستم
    'ahmad_abbasi': 'ahmad.reza',
    'aria_faghih': 'password2',
    'sina_salary': 'password3',
    'sina_faraji': 'password4',
    'arash_taghie': 'password5',
    'arash_ebrahimy': 'passwprd6',
    'mohrez': 'password7',
}

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    
    # ایجاد جداول
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS login_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        login_time TEXT
    )''')
    
    # اضافه کردن کاربران از پیش تعریف شده به دیتابیس
    for username, password in PREDEFINED_USERS.items():
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        try:
            c.execute('INSERT INTO users (username, password) VALUES (?, ?)', 
                    (username, hashed_password))
        except sqlite3.IntegrityError:
            pass  # اگر کاربر از قبل وجود داشت، خطا نده
    
    conn.commit()
    conn.close()

# دکوراتور برای بررسی دسترسی مدیر
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or session['username'] != 'admin':
            flash('دسترسی غیرمجاز! فقط مدیر سیستم می‌تواند این صفحه را مشاهده کند.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            session['username'] = user['username']
            
            # ثبت زمان ورود در دیتابیس
            conn = get_db_connection()
            conn.execute('INSERT INTO login_logs (username, login_time) VALUES (?, ?)',
                        (user['username'], datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
            conn.close()
            
            if user['username'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('user_dashboard'))
        else:
            flash('نام کاربری یا رمز عبور اشتباه است', 'error')
    
    return render_template('login.html')

@app.route('/user/dashboard')
def user_dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    return render_template('user_dashboard.html', username=session['username'])

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    logs = conn.execute('SELECT * FROM login_logs ORDER BY login_time DESC').fetchall()
    conn.close()
    return render_template('admin_dashboard.html', logs=logs, username='admin')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)