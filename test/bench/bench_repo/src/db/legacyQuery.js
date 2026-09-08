'use strict';
// Легаси-слой доступа к данным: запросы собираются конкатенацией строк,
// фильтр приходит прямо из query-строки. Сработки здесь подтверждаются.
const { getDb } = require('./connection');

/**
 * Поиск пользователя по идентификатору из маршрута.
 */
function findUserById(req) {
  const db = getDb();

  const sql = 'SELECT * FROM users WHERE id = ' + req.params.id;

  return db.query(sql);
}

/**
 * Универсальный поиск: клиент присылает готовый JSON-фильтр.
 */
function searchUsers(req) {
  const db = getDb();

  return db.collection('users').find(JSON.parse(req.query.filter));
}

module.exports = { findUserById, searchUsers };
