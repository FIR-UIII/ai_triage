'use strict';
// Конфигурация внешних сервисов. Секреты приходят из окружения,
// в коде остаются только плейсхолдеры для локального запуска.

module.exports = {
  apiKey: process.env.SERVICE_API_KEY || '<REPLACE_ME>',
  apiSecret: process.env.SERVICE_API_SECRET || '<REPLACE_ME>',
  baseUrl: process.env.SERVICE_BASE_URL || 'http://localhost:8080',
};
