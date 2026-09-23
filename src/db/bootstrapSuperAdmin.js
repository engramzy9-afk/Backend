'use strict';

const bcrypt = require('bcryptjs');
const { query } = require('./pool');
const { env } = require('../config/env');
const { validatePassword } = require('../utils/passwordPolicy');

async function bootstrapSuperAdmin() {
  const email = env.SUPER_ADMIN_EMAIL;
  const password = env.SUPER_ADMIN_PASSWORD;

  if (!email) {
    console.warn('[bootstrap] SUPER_ADMIN_EMAIL is not set; skipping Super Admin bootstrap.');
    return;
  }

  const existingRes = await query(
    `SELECT * FROM accounts WHERE lower(email) = lower($1)`,
    [email]
  );

  const existing = existingRes.rows[0];

  if (existing) {
    if (existing.role !== 'SUPER_ADMIN' || existing.state !== 'ACTIVE') {
      await query(
        `UPDATE accounts
         SET role = 'SUPER_ADMIN',
             state = 'ACTIVE',
             updated_at = now()
         WHERE id = $1`,
        [existing.id]
      );

      console.log(
        '[bootstrap] Existing Super Admin account normalized to role=SUPER_ADMIN, state=ACTIVE.'
      );
    }

    if (!password) {
      console.log(
        '[bootstrap] Super Admin account already present; password left untouched because SUPER_ADMIN_PASSWORD is not set.'
      );
      return;
    }

    const { valid, errors } = validatePassword(password);

    if (!valid) {
      console.warn(
        '[bootstrap] SUPER_ADMIN_PASSWORD does not meet the password policy:',
        errors.join(' ')
      );
      return;
    }

    const hash = await bcrypt.hash(password, 12);

    await query(
      `UPDATE accounts
       SET password_hash = $2,
           updated_at = now()
       WHERE id = $1`,
      [existing.id, hash]
    );

    console.log('[bootstrap] Super Admin password synchronized from SUPER_ADMIN_PASSWORD.');
    return;
  }

  if (!password) {
    console.warn(
      '[bootstrap] No Super Admin account exists yet and SUPER_ADMIN_PASSWORD is not set.'
    );
    return;
  }

  const { valid, errors } = validatePassword(password);

  if (!valid) {
    console.warn(
      '[bootstrap] SUPER_ADMIN_PASSWORD does not meet the password policy:',
      errors.join(' ')
    );
    return;
  }

  const hash = await bcrypt.hash(password, 12);

  await query(
    `INSERT INTO accounts
     (email, full_name, role, state, password_hash)
     VALUES ($1, $2, 'SUPER_ADMIN', 'ACTIVE', $3)`,
    [email, 'Super Admin', hash]
  );

  console.log(`[bootstrap] Super Admin account created for ${email}.`);
}

module.exports = { bootstrapSuperAdmin };