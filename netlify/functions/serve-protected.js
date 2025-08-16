// netlify/functions/serve-protected.js
const fs   = require('fs');
const path = require('path');
const jwt  = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-change-me';
// 受保护文件夹相对于项目根目录的位置
const PROTECTED_ROOT = path.resolve(__dirname, '../../protected-files');

exports.handler = async (event, context) => {
  // 1️⃣ 读取 authToken Cookie
  const cookies = parseCookies(event.headers.cookie || '');
  const token = cookies.authToken;

  // 2️⃣ 校验 JWT（若不存在或无效直接返回 401）
  if (!token) return unauthorized();

  try {
    jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return unauthorized();
  }

  // 3️⃣ 解析请求的目标文件路径
  // event.path = "/protected/secret.html"
  // 去掉 "/protected" 前缀，得到相对路径
  const requestedPath = decodeURIComponent(event.path.replace(/^\/protected/, ''));
  // 防止目录遍历攻击（如 /protected/../netlify.toml）
  const safePath = path.normalize(requestedPath).replace(/^(\.\.(\/|\\|$))+/, '');
  const filePath = path.join(PROTECTED_ROOT, safePath);

  // 4️⃣ 检查文件是否真的位于受保护目录内
  if (!filePath.startsWith(PROTECTED_ROOT)) {
    return { statusCode: 403, body: 'Forbidden' };
  }

  // 5️⃣ 读取文件并返回
  try {
    const fileExists = fs.existsSync(filePath);
    if (!fileExists) {
      return { statusCode: 404, body: 'Not found' };
    }

    const fileBuffer = fs.readFileSync(filePath);
    const mimeType   = getMimeType(filePath);

    return {
      statusCode: 200,
      headers: {
        'Content-Type': mimeType,
        // 让浏览器知道这是文件下载（可选）
        // 'Content-Disposition': `inline; filename="${path.basename(filePath)}"`
      },
      body: fileBuffer.toString('base64'),
      isBase64Encoded: true
    };
  } catch (err) {
    console.error(err);
    return { statusCode: 500, body: 'Server error' };
  }
};

/* ------------------------ 辅助函数 ------------------------ */

function parseCookies(cookieHeader) {
  const list = {};
  cookieHeader && cookieHeader.split(';').forEach(cookie => {
    const parts = cookie.split('=');
    const key = parts.shift().trim();
    const value = decodeURIComponent(parts.join('='));
    if (key) list[key] = value;
  });
  return list;
}

function unauthorized() {
  // 可以改成 302 重定向到登录页，或返回 JSON 提示前端弹窗
  return {
    statusCode: 302,
    headers: { Location: '/' },
    body: ''
  };
}

function getMimeType(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const map = {
    '.html': 'text/html',
    '.htm':  'text/html',
    '.js':   'application/javascript',
    '.css':  'text/css',
    '.json': 'application/json',
    '.png':  'image/png',
    '.jpg':  'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif':  'image/gif',
    '.svg':  'image/svg+xml',
    '.pdf':  'application/pdf',
    '.txt':  'text/plain',
    // 需要更多类型时自行扩展
  };
  return map[ext] || 'application/octet-stream';
}
