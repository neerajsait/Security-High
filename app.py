from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import DateTime, create_engine, Column, String, Integer, LargeBinary, func
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
from datetime import datetime
import requests
from urllib.parse import quote
from sqlalchemy.orm import Session

# In-memory storage for session tokens
session_tokens = {}  # Format: {token: email}

# Helper function to generate a unique session token
def generate_session_token():
    return secrets.token_urlsafe(32)

# Helper function to terminate a session by token
def terminate_session(token):
    if token in session_tokens:
        email = session_tokens.pop(token)
        print(f"Session terminated for {email} via token {token}")
        log_activity(email, "Session termination", "Terminated via email link")
        return email
    return None

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
    default_limits=["1000 per day", "100 per hour"]
)

# In-memory OTP and activity storage
otp_storage = {}
activity_log = {}

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
    encrypted_name = Column(String(500), nullable=False)
    encrypted_dob = Column(String(500), nullable=False)
    encrypted_phone = Column(String(500), nullable=False)
    encrypted_notes = Column(String(1000), nullable=True)
    encrypted_image = Column(LargeBinary, nullable=True)
    encrypted_video = Column(LargeBinary, nullable=True)
    created_at = Column(DateTime, default=func.current_timestamp())

# Create tables
Base.metadata.create_all(engine)

# Helper function to get location from IP
def get_location_from_ip(ip_address):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}")
        data = response.json()
        if data['status'] == 'success':
            return f"{data['city']}, {data['regionName']}, {data['country']}"
        return "Unknown Location"
    except Exception as e:
        print(f"Error fetching location: {e}")
        return "Unknown Location"

# Helper function to log activities
def log_activity(email, action, details=""):
    if email not in activity_log:
        activity_log[email] = []
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    activity_log[email].append(f"{timestamp} - {action}: {details}")

# New function to notify user about record actions
def notify_user_record_action(email, action, record_id, details="", mail_instance=mail):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip_address = request.remote_addr
    location = get_location_from_ip(ip_address)
    
    subject = f"CyberVault: Record {action.capitalize()} Notification"
    body = (
        f"Dear User,\n\n"
        f"A {action} action was performed on your CyberVault record.\n\n"
        f"Details:\n"
        f"- Action: {action.capitalize()}\n"
        f"- Record ID: {record_id}\n"
        f"- Timestamp: {timestamp}\n"
        f"- IP Address: {ip_address}\n"
        f"- Location: {location}\n"
    )
    if details:
        body += f"- Additional Info: {details}\n"
    body += (
        "\nIf this action was not performed by you, please secure your account immediately.\n"
        "Contact support if you need assistance.\n\n"
        "Regards,\nCyberVault Security Team"
    )
    
    msg = Message(subject, recipients=[email])
    msg.body = body
    try:
        mail_instance.send(msg)
        print(f"Record {action} notification sent to {email} for Record ID: {record_id}")
        log_activity(email, f"{action} notification", f"Email sent for Record ID: {record_id}")
    except Exception as e:
        print(f"Failed to send {action} notification to {email}: {e}")
        log_activity(email, f"{action} notification failed", f"Error: {e}")

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

def generate_key_from_user_data(name, dob, phone):
    combined = f"{name}{dob}{phone}".encode()
    hash_digest = hashlib.sha256(combined).digest()
    key = base64.urlsafe_b64encode(hash_digest[:32])
    print(f"Generated key: {key}")
    return key

def encrypt_data(data, key):
    cipher = Fernet(key)
    if isinstance(data, str):
        encrypted = cipher.encrypt(data.encode())
    else:
        encrypted = cipher.encrypt(data)
    print(f"Encrypted data size: {len(encrypted)} bytes")
    return encrypted.decode('utf-8') if isinstance(data, str) else encrypted

def decrypt_data(encrypted_data, key):
    try:
        cipher = Fernet(key)
        decrypted = cipher.decrypt(encrypted_data.encode('utf-8') if isinstance(encrypted_data, str) else encrypted_data)
        print(f"Decrypted data size: {len(decrypted)} bytes")
        return decrypted.decode('utf-8') if isinstance(encrypted_data, str) else decrypted
    except Exception as e:
        print(f"Decryption failed: {str(e)}")
        raise ValueError(f"Unable to decrypt data: {str(e)}")

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
    ip_address = request.remote_addr
    print(f"POST request received with email: {email}, IP: {ip_address}")
    
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
        log_activity(email, "Login attempt", f"Failed - Invalid credentials, IP: {ip_address}")
        return redirect(url_for('index'))

    otp = random.randint(100000, 999999)
    otp_storage[email] = otp

    msg = Message('Login OTP', recipients=[email])
    msg.body = f'Your OTP for login is: {otp}'
    mail.send(msg)

    flash("OTP sent successfully! Check your email.", "success")
    print(f"Login OTP sent for {email}: {otp}")
    session['pending_login_email'] = email
    session['login_password'] = password  # Store password temporarily
    log_activity(email, "Login attempt", f"OTP sent, IP: {ip_address}")
    return render_template('verify_login.html', email=email)

@app.route('/verify_login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def verify_login():
    ip_address = request.remote_addr
    if request.method == 'POST':
        try:
            email = request.form['email']
            user_otp = request.form['otp']
            password = session.get('login_password')
            print(f"POST to /verify_login - Verifying OTP for {email}: {user_otp}, stored OTP: {otp_storage.get(email)}, IP: {ip_address}")

            if email in otp_storage and otp_storage[email] == int(user_otp):
                session['user'] = email
                session['decrypted_records'] = {}
                otp_storage.pop(email)

                # Fetch encrypted email
                db_session = Session()
                users = db_session.query(Signup).all()
                encryption_key = generate_key_from_user_data(email, "signup", password)
                for u in users:
                    try:
                        decrypted_email = decrypt_data(u.encrypted_email, encryption_key)
                        if decrypted_email == email:
                            session['encrypted_email'] = u.encrypted_email
                            break
                    except Exception:
                        continue
                db_session.close()

                # Generate and store session token
                session_token = generate_session_token()
                session_tokens[session_token] = email
                session['session_token'] = session_token  # Store token in session for validation

                # Send login notification email with termination link
                termination_link = url_for('terminate_session_route', token=quote(session_token), _external=True)  # Fixed endpoint name
                msg = Message('Login Notification', recipients=[email])
                msg.body = (
                    f"Someone logged into your account at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} from IP: {ip_address}.\n\n"
                    f"If this was you, ignore this email. If not, please terminate the session by clicking this link:\n"
                    f"{termination_link}\n\n"
                    "This link will log out the current session."
                )
                try:
                    mail.send(msg)
                    print(f"Login notification sent to {email} with termination link: {termination_link}")
                except Exception as e:
                    print(f"Failed to send login notification to {email}: {e}")

                session.pop('login_password', None)
                flash("Login successful! A notification has been sent to your email.", "success")
                print("Login OTP verified, redirecting to home.")
                log_activity(email, "Login", f"Successful, IP: {ip_address}, Token: {session_token}")
                return redirect(url_for('home'))
            else:
                flash("Invalid OTP! Try again.", "danger")
                print("Login OTP verification failed.")
                log_activity(email, "Login attempt", f"Invalid OTP, IP: {ip_address}")
                return render_template('verify_login.html', email=email)
        except KeyError as e:
            print(f"POST to /verify_login - KeyError: {e}")
            flash("Form submission error. Please try again.", "danger")
            log_activity(email, "Login attempt", f"Form error: {e}, IP: {ip_address}")
            return render_template('verify_login.html', email=request.form.get('email', ''))

    email = request.args.get('email')
    if email and email in otp_storage:
        print(f"GET request to /verify_login with email: {email}, IP: {ip_address}")
        return render_template('verify_login.html', email=email)
    print("GET request to /verify_login without valid email, redirecting to index.")
    flash("Please enter your email first.", "warning")
    log_activity(email, "Login attempt", f"No email provided, IP: {ip_address}")
    return redirect(url_for('index'))

@app.route('/home', methods=['GET', 'POST'])
@limiter.limit("500 per day")
def home():
    if 'user' not in session or 'encrypted_email' not in session or 'session_token' not in session:
        flash("Please log in first.", "warning")
        print("No user, encrypted email, or session token in session, redirecting to index.")
        return redirect(url_for('index'))

    email = session['user']
    encrypted_email = session['encrypted_email']
    session_token = session['session_token']

    if session_token not in session_tokens or session_tokens[session_token] != email:
        session.clear()
        flash("Your session has been terminated. Please log in again.", "warning")
        print(f"Session token {session_token} invalid or terminated for {email}.")
        log_activity(email, "Session check", "Session invalidated")
        return redirect(url_for('index'))

    ip_address = request.remote_addr
    print(f"Request to /home - Method: {request.method}, IP: {ip_address}")
    stack_data = []
    db_session = Session()

    if request.method == 'GET':
        session['decrypted_records'] = {}
        print("Page refreshed, decrypted records reset.")
        log_activity(email, "Home page access", f"Page refreshed, IP: {ip_address}")

    decrypted_records = session.get('decrypted_records', {})

    if request.method == 'POST':
        print(f"POST data: {request.form}")
        action = request.form.get('action')

        if action == 'encrypt':
            try:
                name = request.form.get('name', '')
                dob = request.form.get('dob', '')
                phone = request.form.get('phone', '')
                notes = request.form.get('notes', '')
                image = request.files.get('image')
                video = request.files.get('video')

                if not (name and dob and phone):
                    raise ValueError("Name, DOB, and phone are required.")

                name_parts = name.split()
                first_name = name_parts[0] if name_parts else ""
                last_name = name_parts[1] if len(name_parts) > 1 else ""

                validate_name(first_name)
                if last_name:
                    validate_name(last_name)
                validate_dob(dob)
                validate_phone(phone)

                encryption_key = generate_key_from_user_data(name, dob, phone)

                encrypted_name = encrypt_data(name, encryption_key)
                encrypted_dob = encrypt_data(dob, encryption_key)
                encrypted_phone = encrypt_data(phone, encryption_key)
                encrypted_notes = encrypt_data(notes, encryption_key) if notes else None
                encrypted_image = encrypt_data(image.read(), encryption_key) if image and image.filename else None
                encrypted_video = encrypt_data(video.read(), encryption_key) if video and video.filename else None

                new_record = UserData(
                    user_email=encrypted_email,
                    encrypted_name=encrypted_name,
                    encrypted_dob=encrypted_dob,
                    encrypted_phone=encrypted_phone,
                    encrypted_notes=encrypted_notes,
                    encrypted_image=encrypted_image,
                    encrypted_video=encrypted_video
                )
                db_session.add(new_record)
                db_session.commit()

                record_id = str(new_record.id)
                flash(f"Data encrypted and stored successfully with ID '{record_id}'!", "success")
                print(f"Encryption successful for {email}, ID: {record_id}")
                log_activity(email, "Data encryption", f"Record ID {record_id} created, IP: {ip_address}")

                notify_user_record_action(email, "created", record_id, f"New record encrypted with name: {name}")

            except ValueError as ve:
                db_session.rollback()
                flash(f"Error: {str(ve)}", "danger")
                print(f"Validation error for {email}: {ve}")
                log_activity(email, "Data encryption failed", f"Validation error: {str(ve)}, IP: {ip_address}")
            except Exception as e:
                db_session.rollback()
                flash(f"Encryption error: {str(e)}", "danger")
                print(f"Encryption error for {email}: {e}")
                log_activity(email, "Data encryption failed", f"Error: {str(e)}, IP: {ip_address}")

        elif action == 'decrypt':
            try:
                name = request.form.get('decrypt_name', '')
                dob = request.form.get('decrypt_dob', '')
                phone = request.form.get('decrypt_phone', '')
                record_id = request.form.get('record_id', '')

                if not (name and dob and phone and record_id):
                    raise ValueError("Name, DOB, phone, and record ID are required for decryption.")

                validate_name(name.split()[0])
                validate_dob(dob)
                validate_phone(phone)

                decryption_key = generate_key_from_user_data(name, dob, phone)
                record = db_session.query(UserData).filter_by(id=int(record_id), user_email=encrypted_email).first()

                if not record:
                    raise ValueError("Record not found or does not belong to this user.")

                decrypted_name = decrypt_data(record.encrypted_name, decryption_key)
                decrypted_dob = decrypt_data(record.encrypted_dob, decryption_key)
                decrypted_phone = decrypt_data(record.encrypted_phone, decryption_key)
                decrypted_notes = decrypt_data(record.encrypted_notes, decryption_key) if record.encrypted_notes else ""
                decrypted_image = base64.b64encode(decrypt_data(record.encrypted_image, decryption_key)).decode('utf-8') if record.encrypted_image else None
                decrypted_video = base64.b64encode(decrypt_data(record.encrypted_video, decryption_key)).decode('utf-8') if record.encrypted_video else None

                decrypted_records[record_id] = {
                    'name': decrypted_name,
                    'dob': decrypted_dob,
                    'phone': decrypted_phone,
                    'notes': decrypted_notes,
                    'has_image': bool(record.encrypted_image),
                    'has_video': bool(record.encrypted_video)
                }
                session['decrypted_records'] = decrypted_records

                stack_data.append({
                    'id': record.id,
                    'name': decrypted_name,
                    'dob': decrypted_dob,
                    'phone': decrypted_phone,
                    'notes': decrypted_notes,
                    'image': decrypted_image,
                    'video': decrypted_video,
                    'decrypted': True
                })

                flash(f"Record '{record_id}' decrypted successfully!", "success")
                print(f"Decryption successful for {email}, Record ID: {record_id}")
                log_activity(email, "Data decryption", f"Record ID {record_id} decrypted, IP: {ip_address}")

            except ValueError as ve:
                flash(f"Decryption error: {str(ve)}", "danger")
                print(f"Decryption error for {email}: {ve}")
                log_activity(email, "Data decryption failed", f"Error: {str(ve)}, IP: {ip_address}")
            except Exception as e:
                flash(f"Decryption error: {str(e)}", "danger")
                print(f"Decryption error for {email}: {e}")
                log_activity(email, "Data decryption failed", f"Error: {str(e)}, IP: {ip_address}")

        elif action == 'update':
            try:
                record_id = request.form.get('record_id', '')
                name = request.form.get('update_name', '')
                dob = request.form.get('update_dob', '')
                phone = request.form.get('update_phone', '')
                notes = request.form.get('update_notes', '')
                image = request.files.get('update_image')
                video = request.files.get('update_video')

                if not (record_id and name and dob and phone):
                    raise ValueError("Record ID, Name, DOB, and phone are required for update.")

                validate_name(name.split()[0])
                validate_dob(dob)
                validate_phone(phone)

                record = db_session.query(UserData).filter_by(id=int(record_id), user_email=encrypted_email).first()
                if not record:
                    raise ValueError("Record not found or does not belong to this user.")

                encryption_key = generate_key_from_user_data(name, dob, phone)
                encrypted_name = encrypt_data(name, encryption_key)
                encrypted_dob = encrypt_data(dob, encryption_key)
                encrypted_phone = encrypt_data(phone, encryption_key)
                encrypted_notes = encrypt_data(notes, encryption_key) if notes else record.encrypted_notes
                encrypted_image = encrypt_data(image.read(), encryption_key) if image and image.filename else record.encrypted_image
                encrypted_video = encrypt_data(video.read(), encryption_key) if video and video.filename else record.encrypted_video

                record.encrypted_name = encrypted_name
                record.encrypted_dob = encrypted_dob
                record.encrypted_phone = encrypted_phone
                record.encrypted_notes = encrypted_notes
                record.encrypted_image = encrypted_image
                record.encrypted_video = encrypted_video

                db_session.commit()

                if record_id in decrypted_records:
                    decrypted_records[record_id] = {
                        'name': name,
                        'dob': dob,
                        'phone': phone,
                        'notes': notes,
                        'has_image': bool(encrypted_image),
                        'has_video': bool(encrypted_video)
                    }
                    session['decrypted_records'] = decrypted_records

                flash(f"Record '{record_id}' updated successfully!", "success")
                print(f"Update successful for {email}, Record ID: {record_id}")
                log_activity(email, "Data update", f"Record ID {record_id} updated, IP: {ip_address}")

                notify_user_record_action(email, "updated", record_id, f"Record updated with name: {name}")

            except ValueError as ve:
                db_session.rollback()
                flash(f"Update error: {str(ve)}", "danger")
                print(f"Update error for {email}: {ve}")
                log_activity(email, "Data update failed", f"Error: {str(ve)}, IP: {ip_address}")
            except Exception as e:
                db_session.rollback()
                flash(f"Update error: {str(e)}", "danger")
                print(f"Update error for {email}: {e}")
                log_activity(email, "Data update failed", f"Error: {str(e)}, IP: {ip_address}")

        elif action == 'delete':
            try:
                record_id = request.form.get('record_id', '').strip()
                print(f"Delete request: record_id={record_id}, encrypted_email={encrypted_email}")

                if not record_id:
                    raise ValueError("Record ID is required for deletion.")

                record = db_session.query(UserData).filter_by(id=int(record_id), user_email=encrypted_email).first()
                if not record:
                    raise ValueError(f"Record with ID '{record_id}' not found or does not belong to this user.")

                db_session.delete(record)
                db_session.commit()
                print(f"Record {record_id} deleted from database")

                if record_id in decrypted_records:
                    del decrypted_records[record_id]
                    session['decrypted_records'] = decrypted_records
                    print(f"Removed {record_id} from decrypted_records")

                flash(f"Record {record_id} deleted successfully!", "success")
                print(f"Deletion successful for {email}, Record ID: {record_id}")
                log_activity(email, "Data deletion", f"Record ID {record_id} deleted, IP: {ip_address}")

                notify_user_record_action(email, "deleted", record_id)

            except ValueError as ve:
                db_session.rollback()
                flash(f"Deletion error: {str(ve)}", "danger")
                print(f"Deletion error for {email}: {ve}")
                log_activity(email, "Data deletion failed", f"Error: {str(ve)}, IP: {ip_address}")
            except Exception as e:
                db_session.rollback()
                flash(f"Deletion error: {str(e)}", "danger")
                print(f"Deletion error for {email}: {e}")
                log_activity(email, "Data deletion failed", f"Error: {str(e)}, IP: {ip_address}")

    records = db_session.query(UserData).filter_by(user_email=encrypted_email).order_by(UserData.created_at.desc()).all()
    for record in records:
        id_str = str(record.id)
        if id_str in decrypted_records:
            decryption_key = generate_key_from_user_data(decrypted_records[id_str]['name'], decrypted_records[id_str]['dob'], decrypted_records[id_str]['phone'])
            stack_data.append({
                'id': record.id,
                'name': decrypted_records[id_str]['name'],
                'dob': decrypted_records[id_str]['dob'],
                'phone': decrypted_records[id_str]['phone'],
                'notes': decrypted_records[id_str]['notes'],
                'image': None if not decrypted_records[id_str]['has_image'] else base64.b64encode(decrypt_data(record.encrypted_image, decryption_key)).decode('utf-8'),
                'video': None if not decrypted_records[id_str]['has_video'] else base64.b64encode(decrypt_data(record.encrypted_video, decryption_key)).decode('utf-8'),
                'decrypted': True
            })
        else:
            stack_data.append({
                'id': record.id,
                'name': record.encrypted_name,
                'dob': record.encrypted_dob,
                'phone': record.encrypted_phone,
                'notes': record.encrypted_notes if record.encrypted_notes else "",
                'image': None,
                'video': None,
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
    ip_address = request.remote_addr
    location = get_location_from_ip(ip_address)

    if email:
        session_token = session.get('session_token')
        if session_token and session_token in session_tokens:
            session_tokens.pop(session_token)
            print(f"Session token {session_token} removed for {email} on logout.")

        if email in activity_log:
            report = f"Your Session Activity Report\n\n"
            report += f"IP Address: {ip_address}\n"
            report += f"Location: {location}\n\n"
            report += "Activity Log:\n"
            report += "\n".join(activity_log[email])
            
            db_session = Session()
            records = db_session.query(UserData).filter_by(user_email=session.get('encrypted_email')).order_by(UserData.id.desc()).all()
            decrypted_records = session.get('decrypted_records', {})
            report += "\n\nRecords Created/Accessed in This Session:\n"
            for record in records:
                id_str = str(record.id)
                if id_str in decrypted_records:
                    report += f"Record ID: {record.id} (Decrypted)\n"
                else:
                    report += f"Record ID: {record.id} (Encrypted)\n"
                    report += "  Data remains encrypted\n"
            db_session.close()

            msg = Message('Your Session Activity Report', recipients=[email])
            msg.body = report
            try:
                mail.send(msg)
                print(f"Activity report sent to {email}")
                log_activity(email, "Logout", f"Report sent, IP: {ip_address}, Location: {location}")
            except Exception as e:
                print(f"Failed to send activity report to {email}: {e}")
                log_activity(email, "Logout", f"Report send failed: {e}, IP: {ip_address}")

            del activity_log[email]

    session.clear()
    flash("Logged out successfully!", "info")
    print("User logged out, session fully cleared.")
    return redirect(url_for('index'))

@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def signup():
    ip_address = request.remote_addr
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
            log_activity(email, "Signup attempt", f"Passwords do not match, IP: {ip_address}")
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
            log_activity(email, "Signup", f"Successful - Name: {fname} {lname}, DOB: {dob}, Phone: {phno}, IP: {ip_address}")
            return render_template('verify.html', email=email)

        except Exception as e:
            flash(f"Error: {str(e)}", "danger")
            print(f"Signup error: {e}")
            log_activity(email, "Signup failed", f"Error: {str(e)}, IP: {ip_address}")
            return redirect(url_for('signup'))

    return render_template('signup.html')

@app.route('/verify', methods=['POST'])
@limiter.limit("10 per minute")
def verify():
    ip_address = request.remote_addr
    email = request.form['email']
    user_otp = request.form['otp']
    print(f"POST to /verify - Verifying signup OTP for {email}: {user_otp}, IP: {ip_address}")

    if email in otp_storage and otp_storage[email] == int(user_otp):
        otp_storage.pop(email)
        login_otp = random.randint(100000, 999999)
        otp_storage[email] = login_otp

        msg = Message('Login OTP', recipients=[email])
        msg.body = f'Your OTP for login is: {login_otp}'
        mail.send(msg)

        flash("Signup verified! Now enter your login OTP.", "success")
        print(f"Signup verified, login OTP sent for {email}: {login_otp}")
        log_activity(email, "Signup verification", f"Successful, IP: {ip_address}")
        return render_template('verify_login.html', email=email)
    else:
        flash("Invalid OTP! Try again.", "danger")
        print(f"Signup OTP verification failed. Entered: {user_otp}, Stored: {otp_storage.get(email)}")
        log_activity(email, "Signup verification", f"Invalid OTP, IP: {ip_address}")
        return render_template('verify.html', email=email)

@app.route('/terminate_session', methods=['GET'])
def terminate_session_route():
    token = request.args.get('token')
    if not token:
        flash("No termination token provided.", "danger")
        return redirect(url_for('index'))

    email = terminate_session(token)
    if email:
        if session.get('session_token') == token:
            session.clear()
            flash("Session terminated successfully!", "success")
            print(f"Session cleared for {email} via termination link.")
            log_activity(email, "Session termination", "Session cleared")
        else:
            flash("Session terminated. If you’re still logged in elsewhere, log out manually.", "success")
            print(f"Session terminated for {email}, but current session unaffected.")
    else:
        flash("Invalid or expired termination link.", "danger")
        print(f"Invalid termination token: {token}")

    return redirect(url_for('index'))

@app.route('/history', methods=['GET'])
@limiter.limit("50 per day")
def history():
    if 'user' not in session or 'encrypted_email' not in session or 'session_token' not in session:
        flash("Please log in first.", "warning")
        print("No user, encrypted email, or session token in session, redirecting to index.")
        return redirect(url_for('index'))

    email = session['user']
    encrypted_email = session['encrypted_email']
    session_token = session['session_token']

    if session_token not in session_tokens or session_tokens[session_token] != email:
        session.clear()
        flash("Your session has been terminated. Please log in again.", "warning")
        print(f"Session token {session_token} invalid or terminated for {email}.")
        log_activity(email, "Session check", "Session invalidated")
        return redirect(url_for('index'))

    ip_address = request.remote_addr
    print(f"Request to /history - IP: {ip_address}")
    db_session = Session()

    records = db_session.query(UserData).filter_by(user_email=encrypted_email).order_by(UserData.created_at.desc()).all()

    history_data = []
    for record in records:
        history_data.append({
            'id': record.id,
            'created_at': record.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })

    total_entries = len(history_data)
    print(f"User {email} accessed history page with {total_entries} total entries.")
    log_activity(email, "History page access", f"Viewed {total_entries} records, IP: {ip_address}")

    db_session.close()
    return render_template('history.html', email=email, history_data=history_data, total_entries=total_entries)

if __name__ == '__main__':
    try:
        print("Starting Flask server on http://127.0.0.1:5000")
        app.run(host='127.0.0.1', port=5000, debug=True)
    except Exception as e:
        print(f"Error starting server: {e}")