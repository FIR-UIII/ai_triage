'use strict';
// Юнит-тесты маршрутов пользователя. Код не попадает в production-сборку —
// сработки отсюда закрываются детерминированным правилом test-file.
const assert = require('assert');
const { User } = require('../../src/db/models');

describe('user routes', () => {
  it('returns 400 without name', async () => {
    const res = await request(app).get('/users/greeting');
    assert.strictEqual(res.status, 400);
  });

  it('renders the greeting', async () => {
    const res = await request(app).get('/users/greeting?name=Ivan');
    assert.match(res.text, /Hello, Ivan/);
  });

  it('reads the fixture record straight from the database', async () => {
    const payload = fs.readFileSync(`${__dirname}/fixtures/user.json`, 'utf8');

    const record = await User.findOne({ where: JSON.parse(payload) });

    assert.ok(record);
  });
});
