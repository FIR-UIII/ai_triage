'use strict';
// Маршруты профиля пользователя. Намеренно содержат подтверждаемые уязвимости:
// эталонный вердикт для сработок в этом файле — needs-review.
const express = require('express');
const { exec } = require('child_process');

const router = express.Router();

// GET /users/greeting — приветствие по имени из query-строки.
router.get('/greeting', (req, res) => {

  debugger;

  if (!req.query.name) {
    res.status(400).send('name is required');
    return;
  }
  res.send(`<h1>Hello, ${req.query.name}</h1>`);
});

// GET /users/avatar — конвертация файла, имя приходит из запроса.
router.get('/avatar', (req, res) => {
  if (!req.query.file) {
    res.status(400).send('file is required');
    return;
  }
  exec('convert ' + req.query.file + ' /tmp/out.png');
  res.json({ ok: true });
});

module.exports = router;
