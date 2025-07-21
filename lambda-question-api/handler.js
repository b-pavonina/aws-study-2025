require('dotenv').config();

const mysql = require('mysql2/promise');
const crypto = require('crypto');

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: 'question_board',
});

const sharedSecretKey = process.env.SHARED_SECRET_KEY;
const knownPassword = process.env.ACCESS_PASSWORD;

function verifyUserToken(headers) {
  const clientToken = headers['x-access-token'];
  const expected = crypto
    .createHmac('sha256', sharedSecretKey)
    .update(knownPassword)
    .digest('hex');
  return clientToken === expected;
}

function verifyAdminToken(headers) {
  const adminToken = headers['x-admin-token'];
  const adminPassword = process.env.ADMIN_PASSWORD;
  const expectedAdmin = crypto
    .createHmac('sha256', sharedSecretKey)
    .update(adminPassword)
    .digest('hex');
  return adminToken === expectedAdmin;
}

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers':
    'x-access-token,Content-Type,Authorization,Origin,Accept',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
};

module.exports.auth = async (event) => {
  let password;
  try {
    const body = JSON.parse(event.body || '{}');
    password = body.password;
  } catch (e) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Invalid JSON' }),
      headers: corsHeaders,
    };
  }

  if (!password) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Missing password' }),
      headers: corsHeaders,
    };
  }

  const token = crypto
    .createHmac('sha256', sharedSecretKey)
    .update(password)
    .digest('hex');

  const expected = crypto
    .createHmac('sha256', sharedSecretKey)
    .update(knownPassword)
    .digest('hex');

  // ハッシュ済みの共有パスワードが正しいか判定し、間違っていれば401を返す
  if (token !== expected) {
    return {
      statusCode: 401,
      body: JSON.stringify({ error: 'Invalid password' }),
      headers: corsHeaders,
    };
  }

  return {
    statusCode: 200,
    body: JSON.stringify({ token }),
    headers: corsHeaders,
  };
};

// ユーザー専用: 質問一覧取得
module.exports.getQuestions = async (event) => {
  if (!verifyUserToken(event.headers)) {
    return {
      statusCode: 403,
      body: JSON.stringify({ error: 'Invalid token' }),
      headers: corsHeaders,
    };
  }
  try {
    const [rows] = await pool.query(
      'SELECT id, title, body, nickname, created_at FROM questions ORDER BY created_at DESC'
    );
    return {
      statusCode: 200,
      body: JSON.stringify(rows),
      headers: corsHeaders,
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'DB error' }),
      headers: corsHeaders,
    };
  }
};

// 管理者専用: 質問一覧取得
module.exports.adminGetQuestions = async (event) => {
  if (!verifyAdminToken(event.headers)) {
    return {
      statusCode: 403,
      body: JSON.stringify({ error: 'Invalid admin token' }),
      headers: corsHeaders,
    };
  }
  try {
    const [rows] = await pool.query(
      'SELECT id, title, body, nickname, created_at FROM questions ORDER BY created_at DESC'
    );
    return {
      statusCode: 200,
      body: JSON.stringify(rows),
      headers: corsHeaders,
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'DB error' }),
      headers: corsHeaders,
    };
  }
};

module.exports.createQuestion = async (event) => {
  if (!verifyUserToken(event.headers)) {
    return {
      statusCode: 403,
      body: JSON.stringify({ error: 'Invalid token' }),
      headers: corsHeaders,
    };
  }
  const { title, body, nickname, user_token } = JSON.parse(event.body || '{}');
  if (!title || !body || !user_token) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Missing required fields' }),
      headers: corsHeaders,
    };
  }
  const now = new Date();
  const tokenHash = crypto
    .createHash('sha256')
    .update(user_token)
    .digest('hex');
  try {
    await pool.query(
      `INSERT INTO questions (title, body, nickname, created_at, updated_at, user_token_hash)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [title, body, nickname || null, now, now, tokenHash]
    );
    return {
      statusCode: 201,
      body: JSON.stringify({ message: 'Question created' }),
      headers: corsHeaders,
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'DB insert error', details: err.message }),
      headers: corsHeaders,
    };
  }
};

module.exports.getQuestionDetail = async (event) => {
  if (!verifyUserToken(event.headers)) {
    return {
      statusCode: 403,
      body: JSON.stringify({ error: 'Invalid token' }),
      headers: corsHeaders,
    };
  }
  const id = event.pathParameters && event.pathParameters.id;
  if (!id) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Missing id' }),
      headers: corsHeaders,
    };
  }
  try {
    const [[question]] = await pool.query(
      'SELECT id, title, body, nickname, user_token_hash, created_at FROM questions WHERE id = ?',
      [id]
    );
    const [answers] = await pool.query(
      'SELECT * FROM answers WHERE question_id = ? ORDER BY created_at ASC',
      [id]
    );
    return {
      statusCode: 200,
      body: JSON.stringify({ question, answers }),
      headers: corsHeaders,
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'DB fetch error' }),
      headers: corsHeaders,
    };
  }
};

module.exports.postAnswer = async (event) => {
  if (!verifyUserToken(event.headers)) {
    return {
      statusCode: 403,
      body: JSON.stringify({ error: 'Invalid token' }),
      headers: corsHeaders,
    };
  }
  const { question_id, body, parent_answer_id, nickname, user_token } =
    JSON.parse(event.body || '{}');
  if (!question_id || !body) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Missing fields' }),
      headers: corsHeaders,
    };
  }
  const now = new Date();
  const tokenHash = user_token
    ? crypto.createHash('sha256').update(user_token).digest('hex')
    : null;
  try {
    await pool.query(
      `INSERT INTO answers (question_id, parent_answer_id, body, nickname, user_token_hash, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        question_id,
        parent_answer_id || null,
        body,
        nickname || null,
        tokenHash,
        now,
        now,
      ]
    );
    return {
      statusCode: 201,
      body: JSON.stringify({ message: 'Answer posted' }),
      headers: corsHeaders,
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'DB insert error', details: err.message }),
      headers: corsHeaders,
    };
  }
};

module.exports.updateQuestion = async (event) => {
  if (!verifyUserToken(event.headers)) {
    return {
      statusCode: 403,
      body: JSON.stringify({ error: 'Invalid token' }),
      headers: corsHeaders,
    };
  }

  const id = event.pathParameters && event.pathParameters.id;
  if (!id) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Missing id' }),
      headers: corsHeaders,
    };
  }
  const { title, body, user_token } = JSON.parse(event.body || '{}');

  if (!title || !body) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Missing fields' }),
      headers: corsHeaders,
    };
  }

  try {
    const [[row]] = await pool.query(
      'SELECT user_token_hash FROM questions WHERE id = ?',
      [id]
    );
    if (!row) {
      return {
        statusCode: 404,
        body: JSON.stringify({ error: 'Question not found' }),
        headers: corsHeaders,
      };
    }
    const inputTokenHash = user_token
      ? crypto.createHash('sha256').update(user_token).digest('hex')
      : null;
    if (!(inputTokenHash && row.user_token_hash === inputTokenHash)) {
      return {
        statusCode: 403,
        body: JSON.stringify({ error: 'Not authorized' }),
        headers: corsHeaders,
      };
    }
    await pool.query(
      'UPDATE questions SET title = ?, body = ?, updated_at = ? WHERE id = ?',
      [title, body, new Date(), id]
    );
    return {
      statusCode: 200,
      body: JSON.stringify({ message: 'Question updated' }),
      headers: corsHeaders,
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'DB update error' }),
      headers: corsHeaders,
    };
  }
};

module.exports.updateAnswer = async (event) => {
  if (!verifyUserToken(event.headers)) {
    return {
      statusCode: 403,
      body: JSON.stringify({ error: 'Invalid token' }),
      headers: corsHeaders,
    };
  }

  const id = event.pathParameters && event.pathParameters.id;
  if (!id) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Missing id' }),
      headers: corsHeaders,
    };
  }
  const { body, user_token } = JSON.parse(event.body || '{}');

  if (!body) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Missing body' }),
      headers: corsHeaders,
    };
  }

  try {
    const [[row]] = await pool.query(
      'SELECT user_token_hash FROM answers WHERE id = ?',
      [id]
    );
    if (!row) {
      return {
        statusCode: 404,
        body: JSON.stringify({ error: 'Answer not found' }),
        headers: corsHeaders,
      };
    }
    const tokenHash = user_token
      ? crypto.createHash('sha256').update(user_token).digest('hex')
      : null;
    if (!(tokenHash && row.user_token_hash === tokenHash)) {
      return {
        statusCode: 403,
        body: JSON.stringify({ error: 'Unauthorized' }),
        headers: corsHeaders,
      };
    }
    await pool.query(
      'UPDATE answers SET body = ?, updated_at = ? WHERE id = ?',
      [body, new Date(), id]
    );
    return {
      statusCode: 200,
      body: JSON.stringify({ message: 'Answer updated' }),
      headers: corsHeaders,
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'DB update error', details: err.message }),
      headers: corsHeaders,
    };
  }
};

// --- User registration endpoint ---
module.exports.createUser = async (event) => {
  if (!verifyUserToken(event.headers)) {
    return {
      statusCode: 403,
      body: JSON.stringify({ error: 'Invalid token' }),
      headers: corsHeaders,
    };
  }
  let user_token_hash, password_hash;
  try {
    const body = JSON.parse(event.body || '{}');
    user_token_hash = body.user_token_hash;
    password_hash = body.password_hash;
  } catch (e) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Invalid JSON' }),
      headers: corsHeaders,
    };
  }
  if (!user_token_hash || !password_hash) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Missing required fields' }),
      headers: corsHeaders,
    };
  }
  try {
    // Check if user already exists
    const [rows] = await pool.query(
      'SELECT id FROM users WHERE user_token_hash = ? OR password_hash = ?',
      [user_token_hash, password_hash]
    );
    if (rows.length > 0) {
      return {
        statusCode: 409,
        body: JSON.stringify({ error: 'User already exists' }),
        headers: corsHeaders,
      };
    }
    await pool.query(
      'INSERT INTO users (user_token_hash, password_hash, created_at) VALUES (?, ?, NOW())',
      [user_token_hash, password_hash]
    );
    return {
      statusCode: 201,
      body: JSON.stringify({ message: 'User created' }),
      headers: corsHeaders,
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'DB insert error' }),
      headers: corsHeaders,
    };
  }
};

// --- Delete Question ---
module.exports.deleteQuestion = async (event) => {
  if (!verifyUserToken(event.headers)) {
    return {
      statusCode: 403,
      body: JSON.stringify({ error: 'Invalid token' }),
      headers: corsHeaders,
    };
  }
  const id = event.pathParameters && event.pathParameters.id;
  if (!id) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Missing id' }),
      headers: corsHeaders,
    };
  }
  let user_token;
  try {
    const body = JSON.parse(event.body || '{}');
    user_token = body.user_token;
  } catch (e) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Invalid JSON' }),
      headers: corsHeaders,
    };
  }
  if (!user_token) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Missing user_token' }),
      headers: corsHeaders,
    };
  }
  const tokenHash = crypto
    .createHash('sha256')
    .update(user_token)
    .digest('hex');
  try {
    const [[row]] = await pool.query(
      'SELECT user_token_hash FROM questions WHERE id = ?',
      [id]
    );
    if (!row || row.user_token_hash !== tokenHash) {
      return {
        statusCode: 403,
        body: JSON.stringify({ error: 'Not authorized' }),
        headers: corsHeaders,
      };
    }
    await pool.query('DELETE FROM questions WHERE id = ?', [id]);
    return {
      statusCode: 200,
      body: JSON.stringify({ message: 'Question deleted' }),
      headers: corsHeaders,
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'DB delete error', details: err.message }),
      headers: corsHeaders,
    };
  }
};

// --- Delete Answer ---
module.exports.deleteAnswer = async (event) => {
  if (!verifyUserToken(event.headers)) {
    return {
      statusCode: 403,
      body: JSON.stringify({ error: 'Invalid token' }),
      headers: corsHeaders,
    };
  }
  const id = event.pathParameters && event.pathParameters.id;
  if (!id) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Missing id' }),
      headers: corsHeaders,
    };
  }
  let user_token;
  try {
    const body = JSON.parse(event.body || '{}');
    user_token = body.user_token;
  } catch (e) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Invalid JSON' }),
      headers: corsHeaders,
    };
  }
  if (!user_token) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Missing user_token' }),
      headers: corsHeaders,
    };
  }
  const tokenHash = crypto
    .createHash('sha256')
    .update(user_token)
    .digest('hex');
  try {
    const [[row]] = await pool.query(
      'SELECT user_token_hash FROM answers WHERE id = ?',
      [id]
    );
    if (!row || row.user_token_hash !== tokenHash) {
      return {
        statusCode: 403,
        body: JSON.stringify({ error: 'Not authorized' }),
        headers: corsHeaders,
      };
    }
    await pool.query('DELETE FROM answers WHERE id = ?', [id]);
    return {
      statusCode: 200,
      body: JSON.stringify({ message: 'Answer deleted' }),
      headers: corsHeaders,
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'DB delete error', details: err.message }),
      headers: corsHeaders,
    };
  }
};

// --- 管理者認証 ---
module.exports.adminAuth = async (event) => {
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers':
      'x-access-token,Content-Type,Authorization,Origin,Accept',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  };
  let password;
  try {
    const body = JSON.parse(event.body || '{}');
    password = body.password;
  } catch (e) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Invalid JSON' }),
      headers: corsHeaders,
    };
  }
  if (!password) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Missing password' }),
      headers: corsHeaders,
    };
  }
  const crypto = require('crypto');
  const sharedSecretKey = process.env.SHARED_SECRET_KEY;
  const adminPassword = process.env.ADMIN_PASSWORD;
  const token = crypto
    .createHmac('sha256', sharedSecretKey)
    .update(password)
    .digest('hex');
  const expected = crypto
    .createHmac('sha256', sharedSecretKey)
    .update(adminPassword)
    .digest('hex');
  if (token !== expected) {
    return {
      statusCode: 401,
      body: JSON.stringify({ error: 'Invalid password' }),
      headers: corsHeaders,
    };
  }
  return {
    statusCode: 200,
    body: JSON.stringify({ token }),
    headers: corsHeaders,
  };
};

// 管理者専用: 質問詳細取得
module.exports.adminGetQuestionDetail = async (event) => {
  if (!verifyAdminToken(event.headers)) {
    return {
      statusCode: 403,
      body: JSON.stringify({ error: 'Invalid admin token' }),
      headers: corsHeaders,
    };
  }
  const id = event.pathParameters && event.pathParameters.id;
  if (!id) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Missing id' }),
      headers: corsHeaders,
    };
  }
  try {
    const [[question]] = await pool.query(
      'SELECT id, title, body, nickname, user_token_hash, created_at FROM questions WHERE id = ?',
      [id]
    );
    const [answers] = await pool.query(
      'SELECT * FROM answers WHERE question_id = ? ORDER BY created_at ASC',
      [id]
    );
    return {
      statusCode: 200,
      body: JSON.stringify({ question, answers }),
      headers: corsHeaders,
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'DB fetch error' }),
      headers: corsHeaders,
    };
  }
};

// 管理者専用: 質問編集
module.exports.adminUpdateQuestion = async (event) => {
  if (!verifyAdminToken(event.headers)) {
    return {
      statusCode: 403,
      body: JSON.stringify({ error: 'Invalid admin token' }),
      headers: corsHeaders,
    };
  }
  const id = event.pathParameters && event.pathParameters.id;
  if (!id) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Missing id' }),
      headers: corsHeaders,
    };
  }
  const { title, body } = JSON.parse(event.body || '{}');
  if (!title || !body) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Missing fields' }),
      headers: corsHeaders,
    };
  }
  try {
    await pool.query(
      'UPDATE questions SET title = ?, body = ?, updated_at = ? WHERE id = ?',
      [title, body, new Date(), id]
    );
    return {
      statusCode: 200,
      body: JSON.stringify({ message: 'Question updated' }),
      headers: corsHeaders,
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'DB update error' }),
      headers: corsHeaders,
    };
  }
};

// 管理者専用: 質問削除
module.exports.adminDeleteQuestion = async (event) => {
  if (!verifyAdminToken(event.headers)) {
    return {
      statusCode: 403,
      body: JSON.stringify({ error: 'Invalid admin token' }),
      headers: corsHeaders,
    };
  }
  const id = event.pathParameters && event.pathParameters.id;
  if (!id) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Missing id' }),
      headers: corsHeaders,
    };
  }
  try {
    await pool.query('DELETE FROM questions WHERE id = ?', [id]);
    await pool.query('DELETE FROM answers WHERE question_id = ?', [id]);
    return {
      statusCode: 200,
      body: JSON.stringify({ message: 'Question deleted' }),
      headers: corsHeaders,
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'DB delete error' }),
      headers: corsHeaders,
    };
  }
};

// 管理者専用: 回答編集
module.exports.adminUpdateAnswer = async (event) => {
  if (!verifyAdminToken(event.headers)) {
    return {
      statusCode: 403,
      body: JSON.stringify({ error: 'Invalid admin token' }),
      headers: corsHeaders,
    };
  }
  const id = event.pathParameters && event.pathParameters.id;
  if (!id) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Missing id' }),
      headers: corsHeaders,
    };
  }
  const { body } = JSON.parse(event.body || '{}');
  if (!body) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Missing body' }),
      headers: corsHeaders,
    };
  }
  try {
    await pool.query(
      'UPDATE answers SET body = ?, updated_at = ? WHERE id = ?',
      [body, new Date(), id]
    );
    return {
      statusCode: 200,
      body: JSON.stringify({ message: 'Answer updated' }),
      headers: corsHeaders,
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'DB update error' }),
      headers: corsHeaders,
    };
  }
};

// 管理者専用: 回答削除
module.exports.adminDeleteAnswer = async (event) => {
  if (!verifyAdminToken(event.headers)) {
    return {
      statusCode: 403,
      body: JSON.stringify({ error: 'Invalid admin token' }),
      headers: corsHeaders,
    };
  }
  const id = event.pathParameters && event.pathParameters.id;
  if (!id) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Missing id' }),
      headers: corsHeaders,
    };
  }
  try {
    await pool.query('DELETE FROM answers WHERE id = ?', [id]);
    return {
      statusCode: 200,
      body: JSON.stringify({ message: 'Answer deleted' }),
      headers: corsHeaders,
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'DB delete error' }),
      headers: corsHeaders,
    };
  }
};
