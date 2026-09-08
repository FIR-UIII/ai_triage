'use strict';
// Доступ к данным через Sequelize ORM. Пользовательский ввод в запросы
// попадает только как связанный параметр — сработки здесь ложные.
const { Op, Sequelize } = require('sequelize');

class UserRepository {
  constructor(sequelize, model) {
    this.sequelize = sequelize;
    this.model = model;
  }

  /**
   * Последняя версия записи в категории.
   * categoryCode и recordId — значения из внутреннего справочника,
   * фильтр собирается операторами Sequelize, а не сырым объектом запроса.
   */
  async findLatestVersion(categoryCode, recordId) {
    if (typeof categoryCode !== 'string' || typeof recordId !== 'string') {
      throw new TypeError('categoryCode and recordId must be strings');
    }

    const record = await this.model.findOne({
      attributes: ['recordId', [Sequelize.fn('MAX', Sequelize.col('version')), 'maxVersion']],
      where: {
        categoryCode,
        recordId: { [Op.ne]: recordId },
      },
      group: ['recordId'],
    });

    return record;
  }

  /**
   * Профиль пользователя: запрос параметризован через replacements.
   */
  findById(id) {
    return this.sequelize.query('SELECT * FROM users WHERE id = :id', {
      replacements: { id },
      type: Sequelize.QueryTypes.SELECT,
    });
  }
}

module.exports = { UserRepository };
