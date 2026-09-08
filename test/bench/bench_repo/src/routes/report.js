'use strict';
// Отчеты: безопасные аналоги тех же операций, что и в user.js.
// Эталонный вердикт для сработок в этом файле — false-positive.
const path = require('path');
const fs = require('fs');
const express = require('express');
const { execFile } = require('child_process');

const router = express.Router();
const REPORTS_DIR = path.resolve(__dirname, '..', '..', 'storage', 'reports');
const ALLOWED_FORMATS = ['png', 'pdf'];

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

router.get('/title', (req, res) => {
  res.send(`<h1>${escapeHtml(req.query.title)}</h1>`);
});

// POST /reports/convert — конвертация через execFile: shell не используется,
// формат проверяется по allow-list, имена файлов берутся из серверной сессии.
router.post('/convert', (req, res) => {
  const format = String(req.body.format || 'png');
  if (!ALLOWED_FORMATS.includes(format)) {
    res.status(400).json({ error: 'unsupported format' });
    return;
  }
  const source = path.join(REPORTS_DIR, `${req.session.reportId}.svg`);
  const target = path.join(REPORTS_DIR, `${req.session.reportId}.${format}`);
  execFile('/usr/bin/convert', [source, target], (err) => {
    res.status(err ? 500 : 200).json({ ok: !err });
  });
});

// GET /reports/:name — отдача файла отчета.
router.get('/:name', (req, res) => {
  if (!/^[\w.-]+$/.test(req.params.name)) {
    res.status(400).json({ error: 'invalid name' });
    return;
  }

  // path.resolve + проверка префикса не дают выйти за пределы REPORTS_DIR
  const target = path.resolve(REPORTS_DIR, req.params.name);
  if (!target.startsWith(REPORTS_DIR + path.sep)) {
    res.status(403).json({ error: 'forbidden' });
    return;
  }
  fs.createReadStream(target).pipe(res);
});

module.exports = router;
