CREATE DATABASE IF NOT EXISTS `meme` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `meme`;

CREATE TABLE IF NOT EXISTS `memeuser` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `username` VARCHAR(100) NOT NULL,
    `password_hash` VARCHAR(255) NOT NULL,
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `memeuser_username_unique` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Skapa en anvandare med en hash fran PHP:
-- C:\xampp\php\php.exe -r "echo password_hash('byt-detta-losenord', PASSWORD_DEFAULT), PHP_EOL;"
-- INSERT INTO `memeuser` (`username`, `password_hash`) VALUES ('admin', 'klistra-in-hashen-har');
