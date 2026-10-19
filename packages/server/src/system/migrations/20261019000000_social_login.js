exports.up = async function (knex) {
  await knex.schema.createTable('authSignupLocks', (table) => {
    table.string('id', 64).primary();
  });
  await knex.schema.createTable('socialIdentities', (table) => {
    table.increments();
    table.string('provider', 16).notNullable();
    table.specificType('subject', 'varchar(191) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin').notNullable();
    table.integer('userId').unsigned().notNullable().references('id').inTable('users');
    table.unique(['provider', 'subject']);
    table.unique(['userId', 'provider']);
  });
  await knex.schema.createTable('socialAttempts', (table) => {
    table.string('id', 64).primary();
    table.string('browser', 64).notNullable();
    table.string('kind', 16).notNullable();
    table.text('payload').notNullable();
    table.dateTime('expiresAt').notNullable().index();
  });
};

exports.down = async function (knex) {
  await knex.schema.dropTableIfExists('socialAttempts');
  await knex.schema.dropTableIfExists('socialIdentities');
  await knex.schema.dropTableIfExists('authSignupLocks');
};
