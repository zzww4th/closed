// netlify/functions/validate-password.js
require('dotenv').config(); // 只在本地调试时需要
const bcrypt = require('bcryptjs');
const jwt    = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-change-me';
const JWT_EXPIRES_IN = '2h'; // 根据需求自行调整

exports.handler = async (event, context) => {
  try {
    const { password } = JSON.parse(event.body);
    const storedHash = process.env.NETLIFY_PASSWORD;

    if (!storedHash) {
      return { statusCode: 500, body: JSON.stringify({ error: 'Password not configured' }) };
    }

    const isValid = await bcrypt.compare(password, storedHash);
    if (!isValid) {
      return { statusCode: 401, body: JSON.stringify({ error: 'Invalid password' }) };
    }

    // 生成 JWT
    const token = jwt.sign(
      { loggedIn: true },        // 可以放更多 payload（如用户 ID 等）
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    // 把 token 写入 HttpOnly Cookie，防止 XSS 抢夺
    return {
      statusCode: 200,
      headers: {
        // Set-Cookie 必须放在 headers 中
        'Set-Cookie': `authToken=${token}; HttpOnly; Path=/; Max-Age=7200; SameSite=Lax; Secure`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ success: true })
    };
  } catch (err) {
    console.error(err);
    return { statusCode: 500, body: JSON.stringify({ error: err.message }) };
  }
};
