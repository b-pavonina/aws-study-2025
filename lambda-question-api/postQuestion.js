const mysql = require('mysql2/promise');
require('dotenv').config();

exports.handler = async (event) => {
  const conn = await mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
  });

  const body = JSON.parse(event.body);
  const { title, body: content, token_hash, password_hash } = body;

  const [rows] = await conn.execute(
    'INSERT INTO questions (title, body, token_hash, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, NOW(), NOW())',
    [title, content, token_hash, password_hash]
  );

  await conn.end();

  return {
    statusCode: 200,
    body: JSON.stringify({ message: 'Question created', id: rows.insertId }),
  };
};
