
CREATE DATABASE IF NOT EXISTS password_manager;
USE password_manager;

CREATE TABLE IF NOT EXISTS passwords (
    id INT AUTO_INCREMENT PRIMARY KEY,
    website VARCHAR(100),
    username VARCHAR(100),
    password VARCHAR(255)
);