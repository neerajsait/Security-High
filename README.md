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
    FOREIGN KEY (user_email) REFERENCES signup(encrypted_email) ON DELETE CASCADE
);



pip install flask flask-mail flask-limiter sqlalchemy python-dotenv cryptography requests
