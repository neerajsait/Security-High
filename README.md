CREATE DATABASE IF NOT EXISTS your_database_name;

USE your_database_name;

-- Table for storing user sign-up details
CREATE TABLE IF NOT EXISTS signup (
    id INT AUTO_INCREMENT PRIMARY KEY,
    encrypted_fname VARCHAR(500) NOT NULL,
    encrypted_lname VARCHAR(500) NOT NULL,
    encrypted_dob VARCHAR(500) NOT NULL,
    encrypted_phno VARCHAR(500) NOT NULL,
    encrypted_email VARCHAR(500) NOT NULL UNIQUE,
    encrypted_password VARCHAR(500) NOT NULL
);

-- Table for storing encrypted user data
CREATE TABLE IF NOT EXISTS user_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    encrypted_name VARCHAR(500) NOT NULL,
    encrypted_dob VARCHAR(500) NOT NULL,
    encrypted_phone VARCHAR(500) NOT NULL,
    encrypted_notes VARCHAR(1000),
    encrypted_image LONGBLOB,
    encrypted_video LONGBLOB,
    FOREIGN KEY (user_id) REFERENCES signup(id) ON DELETE CASCADE ON UPDATE CASCADE
);

-- Indexing for faster lookups
CREATE INDEX idx_user_email ON signup (encrypted_email);
CREATE INDEX idx_user_id ON user_data (user_id);
