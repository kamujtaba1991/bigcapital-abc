exports.up = async function (knex) {
  // Fail without merging or deleting accounts if legacy email collisions need owner resolution.
  const collisions = await knex('users').select(knex.raw('LOWER(TRIM(EMAIL)) AS email_key'))
    .whereNotNull('email').groupByRaw('LOWER(TRIM(EMAIL))').havingRaw('COUNT(*) > 1').first();
  if (collisions) throw new Error('Resolve duplicate user emails before enabling social login. No accounts were changed.');
  await knex.schema.table('users', (table) => {
    table.specificType('emailKey', 'varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin GENERATED ALWAYS AS (LOWER(TRIM(EMAIL))) STORED');
    table.unique(['emailKey'], 'users_email_key_unique');
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
  await knex.schema.table('users', (table) => {
    table.dropUnique(['emailKey'], 'users_email_key_unique');
    table.dropColumn('emailKey');
  });
};
