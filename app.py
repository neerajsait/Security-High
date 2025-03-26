from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import create_engine, Column, String, Integer, LargeBinary
from sqlalchemy.orm import declarative_base, sessionmaker
from dotenv import load_dotenv
import os
import random
import hashlib
import base64
import re
import logging
import secrets
from cryptography.fernet import Fernet
from datetime import datetime  # Added for timestamp tracking

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(filename='data_operations.log', level=logging.INFO)

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(16))

# MySQL Configuration with SQLAlchemy
try:
    engine = create_engine(f"mysql+pymysql://{os.getenv('MYSQL_USER')}:{os.getenv('MYSQL_PASSWORD')}@{os.getenv('MYSQL_HOST')}/{os.getenv('MYSQL_DB')}")
    Base = declarative_base()
    Session = sessionmaker(bind=engine)
except Exception as e:
    print(f"Error connecting to MySQL: {e}")
    raise

# Email Configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')
mail = Mail(app)

# Flask-Limiter Configuration
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per day", "10 per hour"]
)

# In-memory OTP and activity storage
otp_storage = {}
activity_log = {}  # Added to track user activities

# SQLAlchemy Models
class Signup(Base):
    __tablename__ = 'signup'
    id = Column(Integer, primary_key=True)
    encrypted_fname = Column(String(500))
    encrypted_lname = Column(String(500))
    encrypted_dob = Column(String(500))
    encrypted_phno = Column(String(500))
    encrypted_email = Column(String(500), unique=True)
    encrypted_password = Column(String(500))

class UserData(Base):
    __tablename__ = 'user_data'
    id = Column(Integer, primary_key=True)
    user_email = Column(String(120))
    encrypted_name = Column(String(500))
    encrypted_dob = Column(String(500))
    encrypted_phone = Column(String(500))
    encrypted_notes = Column(String(1000), nullable=True)
    encrypted_image = Column(LargeBinary, nullable=True)
    encrypted_video = Column(LargeBinary, nullable=True)

# Create tables
try:
    Base.metadata.create_all(engine)
except Exception as e:
    print(f"Error creating tables: {e}")
    raise

# Helper function to log activities
def log_activity(email, action, details=""):
    if email not in activity_log:
        activity_log[email] = []
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    activity_log[email].append(f"{timestamp} - {action}: {details}")

# Encryption/Decryption Helper Functions
def validate_name(name):
    if not re.match("^[A-Za-z]+$", name):
        raise ValueError("Name should only contain alphabetic characters.")

def validate_dob(dob):
    if not re.match(r"\d{2}-\d{2}-\d{4}", dob):
        raise ValueError("Date of Birth must be in DD-MM-YYYY format.")

def validate_phone(phone):
    if not re.match(r"^\d{10}$", phone):
        raise ValueError("Phone number must be exactly 10 digits.")

def generate_output(first_name, last_name, dob, phone):
    last_part = last_name[1] + last_name[3] if len(last_name) > 3 else last_name[1] + "_"
    first_part = first_name[1] + first_name[3] if len(first_name) > 3 else first_name[1] + "_"
    dob_sum = sum(int(digit) for digit in dob if digit.isdigit())
    dob_sum = str(dob_sum)[-2:].zfill(2)
    phone_middle = phone[3:7]
    return last_part + dob_sum + first_part + phone_middle

def generate_key_from_user_data(email, value, password):
    combined = f"{email}{value}{password}".encode()
    hash_digest = hashlib.sha256(combined).digest()
    return base64.urlsafe_b64encode(hash_digest[:32])

def encrypt_data(data, key):
    cipher = Fernet(key)
    if isinstance(data, str):
        encrypted = cipher.encrypt(data.encode())
    else:
        encrypted = cipher.encrypt(data)
    print(f"Encrypted data size: {len(encrypted)} bytes")
    return encrypted.decode('utf-8') if isinstance(data, str) else encrypted

def decrypt_data(encrypted_data, key):
    cipher = Fernet(key)
    decrypted = cipher.decrypt(encrypted_data.encode('utf-8') if isinstance(encrypted_data, str) else encrypted_data)
    print(f"Decrypted data size: {len(decrypted)} bytes")
    return decrypted.decode('utf-8') if isinstance(encrypted_data, str) else decrypted

# Routes
@app.route('/')
def index():
    print("GET request to /index")
    return render_template('login.html')

@app.route('/send_login_otp', methods=['POST'])
@limiter.limit("5 per minute")
def send_login_otp():
    email = request.form['email']
    password = request.form['password']
    print(f"POST request received with email: {email}")
    
    db_session = Session()
    users = db_session.query(Signup).all()
    db_session.close()

    encryption_key = generate_key_from_user_data(email, "signup", password)
    user = None
    
    for u in users:
        try:
            decrypted_email = decrypt_data(u.encrypted_email, encryption_key)
            if decrypted_email == email:
                decrypted_password = decrypt_data(u.encrypted_password, encryption_key)
                if decrypted_password == password:
                    user = u
                    break
        except Exception:
            continue

    if not user:
        flash("Invalid email or password! Please try again or <a href='/signup' class='alert-link'>Sign Up</a>.", "danger")
        print(f"Login failed for {email}: No matching user or incorrect credentials.")
        return redirect(url_for('index'))

    otp = random.randint(100000, 999999)
    otp_storage[email] = otp

    msg = Message('Login OTP', recipients=[email])
    msg.body = f'Your OTP for login is: {otp}'
    mail.send(msg)

    flash("OTP sent successfully! Check your email.", "success")
    print(f"Login OTP sent for {email}: {otp}")
    session['pending_login_email'] = email
    log_activity(email, "Login attempt", "OTP sent")
    return render_template('verify_login.html', email=email)

@app.route('/verify_login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def verify_login():
    if request.method == 'POST':
        try:
            email = request.form['email']
            user_otp = request.form['otp']
            print(f"POST to /verify_login - Verifying OTP for {email}: {user_otp}, stored OTP: {otp_storage.get(email)}")

            if email in otp_storage and otp_storage[email] == int(user_otp):
                session['user'] = email
                session['decrypted_records'] = {}
                otp_storage.pop(email)
                session.pop('login_password', None)
                flash("Login successful!", "success")
                print("Login OTP verified, redirecting to home.")
                log_activity(email, "Login", "Successful")
                return redirect(url_for('home'))
            else:
                flash("Invalid OTP! Try again.", "danger")
                print("Login OTP verification failed.")
                log_activity(email, "Login attempt", "Invalid OTP")
                return render_template('verify_login.html', email=email)
        except KeyError as e:
            print(f"POST to /verify_login - KeyError: {e}")
            flash("Form submission error. Please try again.", "danger")
            return render_template('verify_login.html', email=request.form.get('email', ''))

    email = request.args.get('email')
    if email and email in otp_storage:
        print(f"GET request to /verify_login with email: {email}")
        return render_template('verify_login.html', email=email)
    print("GET request to /verify_login without valid email, redirecting to index.")
    flash("Please enter your email first.", "warning")
    return redirect(url_for('index'))

@app.route('/home', methods=['GET', 'POST'])
@limiter.limit("50 per day")
def home():
    if 'user' not in session:
        flash("Please log in first.", "warning")
        print("No user in session, redirecting to index.")
        return redirect(url_for('index'))

    email = session['user']
    stack_data = []
    db_session = Session()

    if request.method == 'GET':
        session['decrypted_records'] = {}
        print("Page refreshed, decrypted records reset.")
        log_activity(email, "Home page access", "Page refreshed")

    decrypted_records = session.get('decrypted_records', {})

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'encrypt':
            try:
                first_name = request.form['first_name']
                last_name = request.form['last_name']
                dob = request.form['dob']
                phone = request.form['phone']
                notes = request.form.get('notes', '')
                image = request.files.get('image')
                video = request.files.get('video')
                password = request.form.get('password')

                if not password:
                    raise ValueError("Password required for encryption")

                validate_name(first_name)
                validate_name(last_name)
                validate_dob(dob)
                validate_phone(phone)

                generated_value = generate_output(first_name, last_name, dob, phone)
                encryption_key = generate_key_from_user_data(email, generated_value, password)

                encrypted_name = encrypt_data(f"{first_name} {last_name}", encryption_key)
                encrypted_dob = encrypt_data(dob, encryption_key)
                encrypted_phone = encrypt_data(phone, encryption_key)
                encrypted_notes = encrypt_data(notes, encryption_key) if notes else None

                encrypted_image = None
                if image and image.filename:
                    image_data = image.read()
                    if image_data:
                        encrypted_image = encrypt_data(image_data, encryption_key)

                encrypted_video = None
                if video and video.filename:
                    video_data = video.read()
                    if video_data:
                        encrypted_video = encrypt_data(video_data, encryption_key)

                new_record = UserData(
                    user_email=email,
                    encrypted_name=encrypted_name,
                    encrypted_dob=encrypted_dob,
                    encrypted_phone=encrypted_phone,
                    encrypted_notes=encrypted_notes,
                    encrypted_image=encrypted_image,
                    encrypted_video=encrypted_video
                )
                db_session.add(new_record)
                db_session.commit()

                decrypted_records[str(new_record.id)] = {
                    'name': f"{first_name} {last_name}",
                    'dob': dob,
                    'phone': phone,
                    'notes': notes,
                    'image': base64.b64encode(image_data).decode('utf-8') if image and image_data else None,
                    'video': base64.b64encode(video_data).decode('utf-8') if video and video_data else None
                }
                session['decrypted_records'] = decrypted_records

                flash("Data encrypted and stored successfully!", "success")
                logging.info(f"Data stored for {email}: {first_name} {last_name}")
                print(f"Encryption successful for {email}")
                log_activity(email, "Data encryption", f"Record ID {new_record.id} created")

            except Exception as e:
                db_session.rollback()
                flash(f"Error: {str(e)}", "danger")
                logging.error(f"Error while storing data: {e}")
                print(f"Encryption error for {email}: {e}")
                log_activity(email, "Data encryption failed", str(e))

        # Add logging to other actions as needed

    records = db_session.query(UserData).filter_by(user_email=email).order_by(UserData.id.desc()).all()
    for record in records:
        id_str = str(record.id)
        if id_str in decrypted_records:
            stack_data.append({
                'id': record.id,
                'name': decrypted_records[id_str]['name'],
                'dob': decrypted_records[id_str]['dob'],
                'phone': decrypted_records[id_str]['phone'],
                'notes': decrypted_records[id_str]['notes'],
                'image': decrypted_records[id_str]['image'],
                'video': decrypted_records[id_str]['video'],
                'decrypted': True
            })
        else:
            stack_data.append({
                'id': record.id,
                'name': record.encrypted_name,
                'dob': record.encrypted_dob,
                'phone': record.encrypted_phone,
                'notes': record.encrypted_notes if record.encrypted_notes else "",
                'image': base64.b64encode(record.encrypted_image).decode('utf-8') if record.encrypted_image else None,
                'video': base64.b64encode(record.encrypted_video).decode('utf-8') if record.encrypted_video else None,
                'decrypted': False
            })

    total_entries = len(records)
    decrypted_count = sum(1 for entry in stack_data if entry['decrypted'])
    print(f"User {email} accessed home page with {decrypted_count} decrypted items out of {total_entries} total.")
    db_session.close()
    return render_template('home.html', email=email, stack_data=stack_data, total_entries=total_entries)

@app.route('/logout')
def logout():
    email = session.get('user')
    if email and email in activity_log:
        # Prepare and send activity report
        report = "Your Session Activity Report:\n\n"
        report += "\n".join(activity_log[email])
        msg = Message('Your Session Activity Report', recipients=[email])
        msg.body = report
        try:
            mail.send(msg)
            print(f"Activity report sent to {email}")
        except Exception as e:
            print(f"Failed to send activity report to {email}: {e}")

        # Clean up activity log for this user
        del activity_log[email]

    session.clear()
    flash("Logged out successfully!", "info")
    print("User logged out, session fully cleared.")
    return redirect(url_for('index'))

@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def signup():
    if request.method == 'POST':
        fname = request.form['fname']
        lname = request.form['lname']
        dob = request.form['dob']
        phno = request.form['phno']
        email = request.form['email']
        password = request.form['password']
        cpassword = request.form['cpassword']

        if password != cpassword:
            flash("Passwords do not match!", "danger")
            return redirect(url_for('signup'))

        try:
            validate_name(fname)
            validate_name(lname)
            validate_dob(dob)
            validate_phone(phno)

            encryption_key = generate_key_from_user_data(email, "signup", password)

            encrypted_fname = encrypt_data(fname, encryption_key)
            encrypted_lname = encrypt_data(lname, encryption_key)
            encrypted_dob = encrypt_data(dob, encryption_key)
            encrypted_phno = encrypt_data(phno, encryption_key)
            encrypted_email = encrypt_data(email, encryption_key)
            encrypted_password = encrypt_data(password, encryption_key)

            db_session = Session()
            new_user = Signup(
                encrypted_fname=encrypted_fname,
                encrypted_lname=encrypted_lname,
                encrypted_dob=encrypted_dob,
                encrypted_phno=encrypted_phno,
                encrypted_email=encrypted_email,
                encrypted_password=encrypted_password
            )
            db_session.add(new_user)
            db_session.commit()
            db_session.close()

            otp = random.randint(100000, 999999)
            otp_storage[email] = otp

            msg = Message('Signup OTP', recipients=[email])
            msg.body = f'Your OTP for signup verification is: {otp}'
            mail.send(msg)

            flash("Signup successful! OTP sent to your email.", "success")
            print(f"Signup OTP sent for {email}: {otp}")
            log_activity(email, "Signup", "Successful")
            return render_template('verify.html', email=email)

        except Exception as e:
            flash(f"Error: {str(e)}", "danger")
            print(f"Signup error: {e}")
            log_activity(email, "Signup failed", str(e))
            return redirect(url_for('signup'))

    return render_template('signup.html')

@app.route('/verify', methods=['POST'])
@limiter.limit("10 per minute")
def verify():
    email = request.form['email']
    user_otp = request.form['otp']
    print(f"POST to /verify - Verifying signup OTP for {email}: {user_otp}")

    if email in otp_storage and otp_storage[email] == int(user_otp):
        otp_storage.pop(email)
        login_otp = random.randint(100000, 999999)
        otp_storage[email] = login_otp

        msg = Message('Login OTP', recipients=[email])
        msg.body = f'Your OTP for login is: {login_otp}'
        mail.send(msg)

        flash("Signup verified! Now enter your login OTP.", "success")
        print(f"Signup verified, login OTP sent for {email}: {login_otp}")
        log_activity(email, "Signup verification", "Successful")
        return render_template('verify_login.html', email=email)
    else:
        flash("Invalid OTP! Try again.", "danger")
        print(f"Signup OTP verification failed. Entered: {user_otp}, Stored: {otp_storage.get(email)}")
        log_activity(email, "Signup verification", "Invalid OTP")
        return render_template('verify.html', email=email)

if __name__ == '__main__':
    try:
        print("Starting Flask server on http://127.0.0.1:5000")
        app.run(host='127.0.0.1', port=5000, debug=True)
    except Exception as e:
        print(f"Error starting server: {e}")