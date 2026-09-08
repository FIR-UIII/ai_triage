'use strict';
// Ключ для in-memory кеша. Хеш используется только для дедупликации записей,
// защитных свойств от него не требуется.
const { createHash } = require('crypto');

function cacheKey(...parts) {
  return createHash('md5').update(JSON.stringify(parts)).digest('hex');
}

module.exports = { cacheKey };
