from flask import Flask, render_template, request, session, redirect, url_for, flash, jsonify
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
from cryptography.fernet import Fernet

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(filename='data_operations.log', level=logging.INFO)

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB limit for uploads

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

# In-memory OTP storage
otp_storage = {}

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

Base.metadata.create_all(engine)

# Encryption/Decryption Helper Functions
def validate_name(name):
    if not name or not re.match("^[A-Za-z ]+$", name):
        raise ValueError("Name should only contain alphabetic characters and spaces.")

def validate_dob(dob):
    if not dob or not re.match(r"\d{2}-\d{2}-\d{4}", dob):
        raise ValueError("Date of Birth must be in DD-MM-YYYY format.")

def validate_phone(phone):
    if not phone or not re.match(r"^\d{10}$", phone):
        raise ValueError("Phone number must be exactly 10 digits.")

def generate_key_from_user_data(email, name, dob, phone):
    combined = f"{email}{name}{dob}{phone}".encode()
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
@app.route('/home', methods=['GET', 'POST'])
@limiter.limit("50 per day")
def home():
    if 'user' not in session:
        flash("Please log in first.", "warning")
        print("No user in session, redirecting to index.")
        return redirect(url_for('index'))

    email = session['user']
    db_session = Session()
    stack_data = []

    if request.method == 'GET':
        session['decrypted_records'] = {}
        print("Page refreshed, decrypted records reset.")
        return render_template('home.html', email=email, stack_data=stack_data, total_entries=0)

    decrypted_records = session.get('decrypted_records', {})

    if request.method == 'POST':
        action = request.form.get('action', None)
        print("Action received:", action)

        if not action:
            flash("No action specified in request", "danger")
            return redirect(url_for('home'))

        if action == 'encrypt':
            try:
                if not all(key in request.form for key in ['name', 'dob', 'phone']):
                    missing = [key for key in ['name', 'dob', 'phone'] if key not in request.form]
                    flash(f"Missing required fields: {', '.join(missing)}", "danger")
                    print(f"Missing fields: {missing}")
                    return redirect(url_for('home'))

                name = request.form['name'].strip()
                dob = request.form['dob'].strip()
                phone = request.form['phone'].strip()
                notes = request.form.get('notes', '').strip()
                image = request.files.get('image')
                video = request.files.get('video')

                print(f"Processing: name='{name}', dob='{dob}', phone='{phone}', notes='{notes}', image={image}, video={video}")

                validate_name(name)
                validate_dob(dob)
                validate_phone(phone)

                encryption_key = generate_key_from_user_data(email, name, dob, phone)

                encrypted_name = encrypt_data(name, encryption_key)
                encrypted_dob = encrypt_data(dob, encryption_key)
                encrypted_phone = encrypt_data(phone, encryption_key)
                encrypted_notes = encrypt_data(notes, encryption_key) if notes else None

                encrypted_image = None
                if image and image.filename:
                    image_data = image.read()
                    if image_data:
                        encrypted_image = encrypt_data(image_data, encryption_key)
                    else:
                        print("Image file is empty")

                encrypted_video = None
                if video and video.filename:
                    video_data = video.read()
                    if video_data:
                        encrypted_video = encrypt_data(video_data, encryption_key)
                    else:
                        print("Video file is empty")

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
                    'name': name,
                    'dob': dob,
                    'phone': phone,
                    'notes': notes,
                    'image': base64.b64encode(image_data).decode('utf-8') if image and image_data else None,
                    'video': base64.b64encode(video_data).decode('utf-8') if video and video_data else None
                }
                session['decrypted_records'] = decrypted_records

                flash("Data encrypted and stored successfully!", "success")
                logging.info(f"Data stored for {email}")
                print(f"Encryption successful for {email}")

            except ValueError as ve:
                db_session.rollback()
                flash(f"Validation error: {str(ve)}", "danger")
                print(f"Validation error for {email}: {ve}")
            except Exception as e:
                db_session.rollback()
                flash(f"Error: {str(e)}", "danger")
                logging.error(f"Error while storing data: {e}")
                print(f"Encryption error for {email}: {e}")
            finally:
                db_session.close()
                return redirect(url_for('home'))

        elif action == 'decrypt_selected':
            try:
                name = request.form['name'].strip()
                dob = request.form['dob'].strip()
                phone = request.form['phone'].strip()
                selected_ids = request.form.getlist('selected_ids')

                if not all([name, dob, phone]):
                    flash("Please provide name, DOB, and phone number for decryption!", "danger")
                    print("Missing name, dob, or phone for decryption.")
                    return redirect(url_for('home'))

                if not selected_ids:
                    flash("No records selected for decryption!", "warning")
                    print("No IDs selected for decryption.")
                    return redirect(url_for('home'))

                decryption_key = generate_key_from_user_data(email, name, dob, phone)

                records = db_session.query(UserData).filter(UserData.id.in_(selected_ids), UserData.user_email == email).all()
                for record in records:
                    try:
                        decrypted_records[str(record.id)] = {
                            'name': decrypt_data(record.encrypted_name, decryption_key),
                            'dob': decrypt_data(record.encrypted_dob, decryption_key),
                            'phone': decrypt_data(record.encrypted_phone, decryption_key),
                            'notes': decrypt_data(record.encrypted_notes, decryption_key) if record.encrypted_notes else "",
                            'image': base64.b64encode(decrypt_data(record.encrypted_image, decryption_key)).decode('utf-8') if record.encrypted_image else None,
                            'video': base64.b64encode(decrypt_data(record.encrypted_video, decryption_key)).decode('utf-8') if record.encrypted_video else None
                        }
                        print(f"Decrypted ID {record.id} successfully")
                    except Exception as e:
                        print(f"Decryption failed for ID {record.id}: {e}")
                        flash(f"Failed to decrypt record ID {record.id}. Wrong name, DOB, or phone?", "danger")
                session['decrypted_records'] = decrypted_records

                flash("Selected records decrypted successfully!", "success")
                print(f"Decryption successful for {email}")

            except Exception as e:
                flash(f"Error in decryption: {str(e)}", "danger")
                print(f"Decryption error for {email}: {e}")
            finally:
                db_session.close()
                return redirect(url_for('home'))

        elif action == 'delete':
            try:
                record_id = request.form.get('record_id')
                if not record_id:
                    flash("No record ID provided for deletion!", "danger")
                    print("No record_id in delete request")
                    return redirect(url_for('home'))

                record = db_session.query(UserData).filter_by(id=record_id, user_email=email).first()
                if record:
                    db_session.delete(record)
                    db_session.commit()
                    if record_id in decrypted_records:
                        del decrypted_records[record_id]
                        session['decrypted_records'] = decrypted_records
                    flash(f"Record {record_id} deleted successfully!", "success")
                    print(f"Deleted record {record_id} for {email}")
                else:
                    flash(f"Record {record_id} not found or not owned by you!", "danger")
                    print(f"Record {record_id} not found for {email}")

            except Exception as e:
                db_session.rollback()
                flash(f"Error deleting record: {str(e)}", "danger")
                print(f"Delete error for {email}: {e}")
            finally:
                db_session.close()
                return redirect(url_for('home'))

        elif action == 'update':
            try:
                if not all(key in request.form for key in ['name', 'dob', 'phone', 'record_id']):
                    missing = [key for key in ['name', 'dob', 'phone', 'record_id'] if key not in request.form]
                    flash(f"Missing required fields for update: {', '.join(missing)}", "danger")
                    print(f"Missing fields for update: {missing}")
                    return redirect(url_for('home'))

                name = request.form['name'].strip()
                dob = request.form['dob'].strip()
                phone = request.form['phone'].strip()
                record_id = request.form['record_id']
                notes = request.form.get('notes', '').strip()
                image = request.files.get('image')
                video = request.files.get('video')

                validate_name(name)
                validate_dob(dob)
                validate_phone(phone)

                encryption_key = generate_key_from_user_data(email, name, dob, phone)

                record = db_session.query(UserData).filter_by(id=record_id, user_email=email).first()
                if record:
                    record.encrypted_name = encrypt_data(name, encryption_key)
                    record.encrypted_dob = encrypt_data(dob, encryption_key)
                    record.encrypted_phone = encrypt_data(phone, encryption_key)
                    record.encrypted_notes = encrypt_data(notes, encryption_key) if notes else None

                    if image and image.filename:
                        image_data = image.read()
                        if image_data:
                            record.encrypted_image = encrypt_data(image_data, encryption_key)
                    if video and video.filename:
                        video_data = video.read()
                        if video_data:
                            record.encrypted_video = encrypt_data(video_data, encryption_key)

                    db_session.commit()

                    decrypted_records[record_id] = {
                        'name': name,
                        'dob': dob,
                        'phone': phone,
                        'notes': notes,
                        'image': base64.b64encode(image_data).decode('utf-8') if image and image_data else None,
                        'video': base64.b64encode(video_data).decode('utf-8') if video and video_data else None
                    }
                    session['decrypted_records'] = decrypted_records

                    flash(f"Record {record_id} updated successfully!", "success")
                    print(f"Updated record {record_id} for {email}")
                else:
                    flash(f"Record {record_id} not found or not owned by you!", "danger")
                    print(f"Record {record_id} not found for {email}")

            except ValueError as ve:
                db_session.rollback()
                flash(f"Validation error: {str(ve)}", "danger")
                print(f"Validation error for {email}: {ve}")
            except Exception as e:
                db_session.rollback()
                flash(f"Error updating record: {str(e)}", "danger")
                print(f"Update error for {email}: {e}")
            finally:
                db_session.close()
                return redirect(url_for('home'))

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
# Route to handle random photo capture and email sending
@app.route('/send-security-photo', methods=['POST'])
def send_security_photo():
    if 'user' not in session:
        return jsonify({'status': 'error', 'message': 'Not logged in'}), 401

    email = session['user']
    image_data = request.json.get('image')

    if not image_data:
        return jsonify({'status': 'error', 'message': 'No image provided'}), 400

    try:
        image_bytes = base64.b64decode(image_data.split(',')[1])
    except Exception as e:
        print(f"Error decoding image: {e}")
        return jsonify({'status': 'error', 'message': 'Invalid image data'}), 400

    try:
        msg = Message(
            subject="Security Alert: Someone is accessing your NebulaCrypt account",
            recipients=[email],
            body=f"Dear User,\n\nWe detected activity on your NebulaCrypt account. Here’s a photo of the user:\n\nIf this isn’t you, click here to terminate the session: {url_for('terminate_session', _external=True)}\n\nStay secure,\nNebulaCrypt Team",
        )
        msg.attach("security_photo.png", "image/png", image_bytes)
        mail.send(msg)
        print(f"Security photo sent to {email}")
        return jsonify({'status': 'success', 'message': 'Photo sent to your email'})
    except Exception as e:
        print(f"Error sending email: {e}")
        return jsonify({'status': 'error', 'message': 'Failed to send email'}), 500

# Route to terminate the session
@app.route('/terminate-session')
def terminate_session():
    if 'user' in session:
        session.pop('user', None)
        flash("Your session has been terminated due to a security alert.", "warning")
        print("Session terminated via security link")
    return redirect(url_for('index'))

@app.errorhandler(400)
def bad_request(error):
    return render_template('400.html'), 400

if __name__ == '__main__':
    try:
        print("Starting Flask server on http://127.0.0.1:5000")
        app.run(host='127.0.0.1', port=5000, debug=True)
    except Exception as e:
        print(f"Error starting server: {e}")
