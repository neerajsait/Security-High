CREATE TABLE signup (
    id INT AUTO_INCREMENT PRIMARY KEY,
    encrypted_fname VARCHAR(500),
    encrypted_lname VARCHAR(500),
    encrypted_dob VARCHAR(500),
    encrypted_phno VARCHAR(500),
    encrypted_email VARCHAR(500) UNIQUE,
    encrypted_password VARCHAR(500)
);

CREATE TABLE user_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_email VARCHAR(120),
    encrypted_name VARCHAR(500),
    encrypted_dob VARCHAR(500),
    encrypted_phone VARCHAR(500),
    encrypted_notes VARCHAR(1000) NULL,
    encrypted_image LONGBLOB NULL,
    encrypted_video LONGBLOB NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_email) REFERENCES signup(encrypted_email) ON DELETE CASCADE
);



pip install flask flask-mail flask-limiter sqlalchemy python-dotenv cryptography requests




future 
add all thses things . Session Hijacking Protection,Encryption at Rest (DB Compromise Protection)
,CSRF Protection,Secure Email OTPs (for login or file decryption),Log session creation,
and add these to mail failed logins, OTP attemptsNotify user of new device/session logins to the mail

