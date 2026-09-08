'use strict';
// Хеширование паролей пользователей перед сохранением в БД.
const { createHash } = require('crypto');

const SALT = process.env.PASSWORD_SALT || 'atomid';

function hashPassword(password) {
  return createHash('md5').update(password + SALT).digest('hex');
}

function verifyPassword(password, stored) {
  return hashPassword(password) === stored;
}

module.exports = { hashPassword, verifyPassword };
