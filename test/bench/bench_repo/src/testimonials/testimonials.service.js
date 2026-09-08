'use strict';
// Боевой сервис отзывов. Путь содержит подстроку "test", но это НЕ тестовый код:
// правило test-file не должно его закрывать, а уязвимость здесь реальная.
const express = require('express');

const router = express.Router();

const quotes = [];

router.post('/', (req, res) => {
  quotes.push(String(req.body.text || ''));
  res.status(201).json({ ok: true });
});

// GET /testimonials/preview — предпросмотр отзыва до публикации.
router.get('/preview', (req, res) => {
  res.set('Content-Type', 'text/html');
  res.send('<div class="quote">' + req.query.text + '</div>');
});

module.exports = router;
