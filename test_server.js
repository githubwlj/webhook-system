const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 7000;

// 基本中间件
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// 简单的测试数据
const testUser = {
  id: '1',
  username: 'admin',
  password_hash: bcrypt.hashSync('admin123', 12)
};

const JWT_SECRET = 'test-secret-key';

// 测试路由
app.get('/', (req, res) => {
  res.json({
    message: 'Webhook Management System Test',
    status: 'Running',
    endpoints: {
      admin: '/admin',
      login: '/admin/login'
    }
  });
});

// 管理员登录页面
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// 管理员登录API
app.post('/admin/login', (req, res) => {
  const { username, password } = req.body;
  
  console.log('Login attempt:', { username, password: '***' });
  
  if (username === testUser.username && bcrypt.compareSync(password, testUser.password_hash)) {
    const token = jwt.sign(
      { id: testUser.id, username: testUser.username, role: 'admin' },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({
      success: true,
      message: '登录成功',
      token,
      user: {
        id: testUser.id,
        username: testUser.username
      }
    });
  } else {
    res.status(401).json({
      success: false,
      message: '用户名或密码错误'
    });
  }
});

// 管理员仪表板
app.get('/admin/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// 启动服务器
app.listen(PORT, () => {
  console.log(`🚀 Test server running on port ${PORT}`);
  console.log(`📡 Visit: http://localhost:${PORT}/admin`);
  console.log(`🔑 Credentials: admin / admin123`);
});