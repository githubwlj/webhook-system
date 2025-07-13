// 加载环境变量
require('dotenv').config({
  path: process.env.NODE_ENV === 'production' ? '.env.production' : '.env'
});

const express = require('express');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const crypto = require('crypto');
const axios = require('axios');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const { body, param, query, validationResult } = require('express-validator');
const winston = require('winston');
const expressWinston = require('express-winston');
const Joi = require('joi');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 6998;

// 信任代理设置（只信任特定代理）
const trustProxy = process.env.TRUST_PROXY;
if (trustProxy && trustProxy !== 'false') {
  app.set('trust proxy', trustProxy);
}

// 数据存储文件路径
const DATA_DIR = path.join(__dirname, 'data');
const TOKENS_FILE = path.join(DATA_DIR, 'tokens.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const LOGS_FILE = path.join(DATA_DIR, 'logs.json');

// 确保数据目录存在 (同步初始化是可以接受的)
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// 异步数据存储类
class DataStore {
  constructor() {
    this.tokens = [];
    this.users = [];
    this.logs = [];
    this.initialized = false;
    this._writeQueue = new Map(); // 防止并发写入
  }

  async init() {
    if (this.initialized) return;
    
    try {
      this.tokens = await this.loadData(TOKENS_FILE, []);
      this.users = await this.loadData(USERS_FILE, []);
      this.logs = await this.loadData(LOGS_FILE, []);
      
      // 创建默认管理员用户
      await this.initDefaultUser();
      this.initialized = true;
      console.log('📊 数据存储初始化完成');
    } catch (error) {
      console.error('❌ 数据存储初始化失败:', error);
      throw error;
    }
  }

  async loadData(filePath, defaultData) {
    try {
      if (fs.existsSync(filePath)) {
        const data = await fs.promises.readFile(filePath, 'utf8');
        return JSON.parse(data);
      }
    } catch (error) {
      console.error('Error loading data from', filePath, error);
    }
    return defaultData;
  }

  async saveData(filePath, data) {
    try {
      // 防止并发写入同一文件
      if (this._writeQueue.has(filePath)) {
        await this._writeQueue.get(filePath);
      }
      
      const writePromise = fs.promises.writeFile(filePath, JSON.stringify(data, null, 2));
      this._writeQueue.set(filePath, writePromise);
      
      await writePromise;
      this._writeQueue.delete(filePath);
    } catch (error) {
      this._writeQueue.delete(filePath);
      console.error('Error saving data to', filePath, error);
      throw error;
    }
  }

  async initDefaultUser() {
    const adminExists = this.users.some(user => user.username === 'admin');
    if (!adminExists) {
      const defaultPassword = process.env.DEFAULT_ADMIN_PASSWORD || 'admin123';
      const hashedPassword = bcrypt.hashSync(defaultPassword, 12);
      
      this.users.push({
        id: crypto.randomUUID(),
        username: 'admin',
        password_hash: hashedPassword,
        created_at: Math.floor(Date.now() / 1000),
        last_login: null
      });
      
      await this.saveData(USERS_FILE, this.users);
      console.log('🔐 默认管理员用户已创建，请及时修改密码！');
    }
  }

  // 内部方法：安全的异步保存（自动处理错误）
  _saveDataSafe(filePath, data) {
    // 使用 setImmediate 避免阻塞，但不等待结果
    setImmediate(async () => {
      try {
        await this.saveData(filePath, data);
      } catch (error) {
        console.error('异步保存失败:', filePath, error);
      }
    });
  }
  findUser(username) {
    return this.users.find(user => user.username === username);
  }

  updateUserLastLogin(userId) {
    const user = this.users.find(u => u.id === userId);
    if (user) {
      user.last_login = Math.floor(Date.now() / 1000);
      user.login_count = (user.login_count || 0) + 1;
      this._saveDataSafe(USERS_FILE, this.users);
    }
  }

  updateUserPassword(userId, newPasswordHash) {
    const user = this.users.find(u => u.id === userId);
    if (user) {
      user.password_hash = newPasswordHash;
      this._saveDataSafe(USERS_FILE, this.users);
      return true;
    }
    return false;
  }

  // 令牌相关方法
  getAllTokens() {
    return this.tokens;
  }

  createToken(tokenData) {
    // 检查名称唯一性
    const existingToken = this.tokens.find(token => 
      token.name.toLowerCase() === tokenData.name.toLowerCase() && 
      token.status !== 'deleted'
    );
    
    if (existingToken) {
      throw new Error('令牌名称已存在，请使用不同的名称');
    }
    
    // 检查管理员令牌限制
    if (tokenData.type === 'admin') {
      const existingAdminToken = this.tokens.find(token => 
        token.type === 'admin' && token.status !== 'deleted'
      );
      
      if (existingAdminToken) {
        throw new Error('系统只能存在一个管理员令牌，如需更换请先删除现有管理员令牌');
      }
    }
    
    // 检查主要UI令牌设置
    if (tokenData.type === 'ui_access' && tokenData.is_primary) {
      const existingPrimaryUI = this.tokens.find(token => 
        token.type === 'ui_access' && token.is_primary && token.status !== 'deleted'
      );
      
      if (existingPrimaryUI) {
        throw new Error('只能设置一个主要的UI访问令牌');
      }
    }
    
    const token = {
      id: crypto.randomUUID(),
      ...tokenData,
      created_at: Math.floor(Date.now() / 1000),
      last_used: null,
      use_count: 0
    };
    this.tokens.push(token);
    this._saveDataSafe(TOKENS_FILE, this.tokens);
    return token;
  }

  findToken(value) {
    return this.tokens.find(token => token.value === value && token.status === 'active');
  }

  updateTokenUsage(tokenId) {
    const token = this.tokens.find(t => t.id === tokenId);
    if (token) {
      token.last_used = Math.floor(Date.now() / 1000);
      token.use_count++;
      this._saveDataSafe(TOKENS_FILE, this.tokens);
    }
  }

  deleteToken(tokenId) {
    const tokenToDelete = this.tokens.find(t => t.id === tokenId);
    
    if (!tokenToDelete) {
      return false;
    }
    
    // 检查是否为管理员令牌，禁止删除
    if (tokenToDelete.type === 'admin') {
      throw new Error('管理员令牌不能被删除，只能修改');
    }
    
    // 对Webhook密钥实施软删除
    if (tokenToDelete.type === 'webhook_secret') {
      tokenToDelete.status = 'deleted';
      tokenToDelete.deleted_at = Math.floor(Date.now() / 1000);
      this._saveDataSafe(TOKENS_FILE, this.tokens);
      return true;
    }
    
    // 其他令牌执行真正的删除
    const index = this.tokens.findIndex(t => t.id === tokenId);
    if (index > -1) {
      this.tokens.splice(index, 1);
      this._saveDataSafe(TOKENS_FILE, this.tokens);
      return true;
    }
    return false;
  }

  updateToken(tokenId, updateData) {
    const token = this.tokens.find(t => t.id === tokenId);
    
    if (!token) {
      throw new Error('令牌不存在');
    }
    
    // 检查名称唯一性（如果更改了名称）
    if (updateData.name && updateData.name.toLowerCase() !== token.name.toLowerCase()) {
      const existingToken = this.tokens.find(t => 
        t.name.toLowerCase() === updateData.name.toLowerCase() && 
        t.status !== 'deleted' && 
        t.id !== tokenId
      );
      
      if (existingToken) {
        throw new Error('令牌名称已存在，请使用不同的名称');
      }
    }
    
    // 更新令牌数据
    Object.assign(token, updateData, {
      updated_at: Math.floor(Date.now() / 1000)
    });
    
    this._saveDataSafe(TOKENS_FILE, this.tokens);
    return token;
  }

  // 日志相关方法
  addLog(logEntry) {
    const log = {
      id: crypto.randomUUID(),
      timestamp: Math.floor(Date.now() / 1000),
      ...logEntry
    };
    this.logs.push(log);
    
    // 保持最多1000条日志
    if (this.logs.length > 1000) {
      this.logs = this.logs.slice(-1000);
    }
    
    this._saveDataSafe(LOGS_FILE, this.logs);
  }

  getSimpleLogs(limit = 50) {
    return this.logs.slice(-limit).reverse();
  }

  getStats() {
    const totalTokens = this.tokens.length;
    const activeTokens = this.tokens.filter(t => t.status === 'active').length;
    const todayStart = Math.floor(Date.now() / 1000) - 24 * 60 * 60;
    const todayRequests = this.logs.filter(log => log.timestamp > todayStart).length;
    
    return {
      totalTokens,
      activeTokens,
      todayRequests
    };
  }
}

// 初始化数据存储（异步）
const dataStore = new DataStore();

async function initializeApp() {
  await dataStore.init();
  console.log('✅ 应用初始化完成');
}

// 调用初始化
initializeApp().catch(error => {
  console.error('❌ 应用初始化失败:', error);
  process.exit(1);
});

// JWT密钥 - 安全修复：确保JWT密钥在环境变量中配置
const JWT_SECRET = (() => {
  if (process.env.JWT_SECRET) {
    return process.env.JWT_SECRET;
  }
  
  // 开发环境警告
  if (process.env.NODE_ENV !== 'production') {
    console.warn('⚠️  警告: JWT_SECRET 环境变量未设置，使用默认密钥。生产环境中必须设置！');
    return 'dev-only-jwt-secret-please-change-in-production';
  }
  
  // 生产环境强制要求
  throw new Error('🚨 安全错误: 生产环境必须设置 JWT_SECRET 环境变量！');
})();

// 配置日志
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: './logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: './logs/combined.log' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

// 安全中间件
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// 压缩响应
app.use(compression());

// CORS配置
const corsOptions = {
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
  credentials: true,
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

// 请求日志
app.use(expressWinston.logger({
  winstonInstance: logger,
  meta: true,
  msg: "HTTP {{req.method}} {{req.url}}",
  expressFormat: true,
  colorize: false,
  ignoreRoute: function (req, res) { return false; }
}));

// 速率限制
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15分钟
  max: process.env.RATE_LIMIT_MAX || 100,
  message: {
    error: 'Too many requests from this IP, please try again later.',
    retryAfter: 900
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    // 如果无法确定真实IP，或者是本地IP，则跳过限制
    const ip = req.ip;
    return !ip || 
           ip === '127.0.0.1' || 
           ip === '::1' || 
           ip.includes('127.0.0.1') || 
           ip.includes('::ffff:127.0.0.1');
  }
});

const webhookLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1分钟
  max: process.env.WEBHOOK_RATE_LIMIT || 50,
  message: {
    error: 'Too many webhook requests, please try again later.',
    retryAfter: 60
  },
  skip: (req) => {
    // 如果无法确定真实IP，或者是本地IP，则跳过限制
    const ip = req.ip;
    return !ip || 
           ip === '127.0.0.1' || 
           ip === '::1' || 
           ip.includes('127.0.0.1') || 
           ip.includes('::ffff:127.0.0.1');
  }
});

// 慢速请求保护
const speedLimiter = slowDown({
  windowMs: 15 * 60 * 1000,
  delayAfter: 50,
  delayMs: () => 500,
  maxDelayMs: 20000,
  skip: (req) => {
    // 如果无法确定真实IP，或者是本地IP，则跳过限制
    const ip = req.ip;
    return !ip || 
           ip === '127.0.0.1' || 
           ip === '::1' || 
           ip.includes('127.0.0.1') || 
           ip.includes('::ffff:127.0.0.1');
  }
});

app.use(limiter);
app.use(speedLimiter);

// 解析请求体
app.use(express.json({ 
  limit: '10mb',
  verify: (req, res, buf) => {
    req.rawBody = buf;
  },
  strict: false
}));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// 静态文件服务（用于Web UI）
app.use('/ui', express.static(path.join(__dirname, 'public')));

// 身份验证中间件
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = req.query.token;
  const adminToken = process.env.ADMIN_TOKEN;
  const uiAccessKey = process.env.UI_ACCESS_KEY;

  // 检查Authorization头或查询参数中的token
  const providedToken = authHeader?.replace('Bearer ', '') || token;

  if (!providedToken) {
    return res.status(401).json({ 
      error: 'Authentication required', 
      message: 'Please provide admin token' 
    });
  }

  // 检查是否是JWT令牌
  if (providedToken.startsWith('eyJ')) {
    try {
      const decoded = jwt.verify(providedToken, JWT_SECRET);
      req.user = decoded;
      return next();
    } catch (error) {
      return res.status(403).json({ 
        error: 'Invalid token', 
        message: 'JWT verification failed' 
      });
    }
  }

  // 检查数据库中的令牌
  const dbToken = dataStore.findToken(providedToken);
  if (dbToken) {
    // 检查是否过期
    if (dbToken.expiry_date && dbToken.expiry_date < Date.now()) {
      return res.status(403).json({ 
        error: 'Token expired', 
        message: 'Token has expired' 
      });
    }
    
    // 更新使用记录
    dataStore.updateTokenUsage(dbToken.id);
    
    req.token = dbToken;
    return next();
  }

  // 检查环境变量中的令牌（向后兼容）
  if (adminToken && providedToken === adminToken) {
    return next();
  }
  
  if (uiAccessKey && providedToken === uiAccessKey) {
    return next();
  }

  // 如果不是环境变量令牌，且也不是JWT或数据库令牌，则拒绝
  logger.warn('Unauthorized access attempt', {
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    path: req.path,
    token: providedToken.substring(0, 10) + '...'
  });
  
  return res.status(403).json({ 
    error: 'Access denied', 
    message: 'Invalid token' 
  });
}

// 管理员认证中间件
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ 
      error: 'Admin access required', 
      message: 'This endpoint requires admin privileges' 
    });
  }
  next();
}

// 安全的存储实现
class SecureWebhookStore {
  constructor() {
    this.receivers = new Map();
    this.senders = new Map();
    this.logs = [];
    this.maxLogs = parseInt(process.env.MAX_LOG_ENTRIES) || 1000;
  }

  addReceiver(id, config) {
    if (!id || typeof id !== 'string') {
      throw new Error('Invalid receiver ID');
    }
    
    const sanitizedConfig = {
      id: id.replace(/[^a-zA-Z0-9-_]/g, ''),
      secret: config.secret,
      description: config.description || '',
      createdAt: new Date().toISOString(),
      lastUsed: null,
      useCount: 0
    };
    
    this.receivers.set(sanitizedConfig.id, sanitizedConfig);
    return sanitizedConfig;
  }

  getReceiver(id) {
    return this.receivers.get(id);
  }

  deleteReceiver(id) {
    return this.receivers.delete(id);
  }

  addLog(type, data) {
    const sanitizedData = this.sanitizeLogData(data);
    const logEntry = {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      type,
      data: sanitizedData
    };
    
    this.logs.push(logEntry);
    
    // 保持日志数量限制
    if (this.logs.length > this.maxLogs) {
      this.logs.shift();
    }
    
    logger.info('Webhook event', logEntry);
  }

  sanitizeLogData(data) {
    const sanitized = { ...data };
    
    // 移除敏感信息
    if (sanitized.payload) {
      delete sanitized.payload.password;
      delete sanitized.payload.token;
      delete sanitized.payload.secret;
    }
    
    // 限制字符串长度
    Object.keys(sanitized).forEach(key => {
      if (typeof sanitized[key] === 'string' && sanitized[key].length > 1000) {
        sanitized[key] = sanitized[key].substring(0, 1000) + '...';
      }
    });
    
    return sanitized;
  }

  getFilteredLogs(filters) {
    let logs = [...this.logs]; // 创建副本避免修改原数组
    
    // 应用过滤条件
    if (filters.type) {
      logs = logs.filter(log => log.type === filters.type);
    }
    
    if (filters.level) {
      logs = logs.filter(log => log.level === filters.level);
    }
    
    if (filters.search) {
      const searchTerm = filters.search.toLowerCase();
      logs = logs.filter(log => {
        const logText = JSON.stringify(log).toLowerCase();
        return logText.includes(searchTerm);
      });
    }
    
    if (filters.dateFrom || filters.dateTo) {
      logs = logs.filter(log => {
        const logDate = new Date(log.timestamp);
        if (filters.dateFrom && logDate < filters.dateFrom) return false;
        if (filters.dateTo && logDate > filters.dateTo) return false;
        return true;
      });
    }
    
    // 按时间戳降序排序（最新的在前面）
    logs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    
    const total = logs.length;
    const offset = filters.offset || 0;
    const limit = Math.min(filters.limit || 50, 100);
    const paginatedLogs = logs.slice(offset, offset + limit);
    
    return {
      logs: paginatedLogs,
      total: total,
      offset: offset,
      limit: limit
    };
  }

  getLogs(limit = 50, type = null, offset = 0) {
    // 保持向后兼容，调用新的过滤方法
    return this.getFilteredLogs({
      limit,
      offset,
      type
    });
  }
}

const webhookStore = new SecureWebhookStore();

// 输入验证schemas
const webhookIdSchema = Joi.string().pattern(/^[a-zA-Z0-9_-]+$/).min(3).max(50).required();
const webhookConfigSchema = Joi.object({
  id: webhookIdSchema,
  secret: Joi.string().min(16).max(256).allow('').optional(),
  description: Joi.string().max(500).optional()
});

const webhookSendSchema = Joi.object({
  url: Joi.string().uri().required(),
  payload: Joi.object().required(),
  secret: Joi.string().min(16).max(256).optional(),
  headers: Joi.object().optional()
});

// 工具函数
function generateSignature(payload, secret) {
  return crypto
    .createHmac('sha256', secret)
    .update(JSON.stringify(payload))
    .digest('hex');
}

function verifySignature(payload, signature, secret) {
  try {
    const expectedSignature = generateSignature(payload, secret);
    return crypto.timingSafeEqual(
      Buffer.from(signature, 'hex'),
      Buffer.from(expectedSignature, 'hex')
    );
  } catch (error) {
    return false;
  }
}

// 增强的SSRF防护函数
function isPrivateIP(hostname) {
  // IPv4私有地址范围检查
  const ipv4PrivateRanges = [
    /^127\./, // 127.0.0.0/8 - 回环地址
    /^10\./, // 10.0.0.0/8 - 私有网络A类
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // 172.16.0.0/12 - 私有网络B类
    /^192\.168\./, // 192.168.0.0/16 - 私有网络C类
    /^169\.254\./, // 169.254.0.0/16 - 链路本地地址
    /^224\./, // 224.0.0.0/4 - 多播地址
    /^240\./, // 240.0.0.0/4 - 保留地址
    /^0\./, // 0.0.0.0/8 - 当前网络
    /^255\.255\.255\.255$/ // 广播地址
  ];
  
  // IPv6私有地址范围检查
  const ipv6PrivateRanges = [
    /^::1$/, // ::1 - IPv6回环地址
    /^fe80:/i, // fe80::/10 - 链路本地地址
    /^fc00:/i, // fc00::/7 - 唯一本地地址
    /^::ffff:/, // ::ffff:0:0/96 - IPv4映射地址
    /^::/, // :: - 全零地址
    /^ff/i // ff00::/8 - 多播地址
  ];
  
  // 主机名检查
  const restrictedHostnames = [
    'localhost',
    'local',
    'internal',
    'intranet',
    'private'
  ];
  
  const lowerHostname = hostname.toLowerCase();
  
  // 检查受限主机名
  if (restrictedHostnames.some(restricted => lowerHostname.includes(restricted))) {
    return true;
  }
  
  // 检查IPv4私有地址
  if (ipv4PrivateRanges.some(range => range.test(hostname))) {
    return true;
  }
  
  // 检查IPv6私有地址
  if (ipv6PrivateRanges.some(range => range.test(hostname))) {
    return true;
  }
  
  return false;
}

function sanitizeUrl(url) {
  try {
    const parsedUrl = new URL(url);
    
    // 只允许HTTP和HTTPS协议
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
      throw new Error('只允许 HTTP 和 HTTPS 协议');
    }
    
    // 检查端口号（阻止危险端口）
    const dangerousPorts = [
      22, 23, 25, 53, 80, 110, 143, 443, 993, 995, // 常见服务端口
      135, 139, 445, // Windows端口
      1433, 1521, 3306, 5432, 5984, 6379, 9200, 9300, // 数据库端口
      2049, 2181, 3000, 3001, 4369, 5672, 8080, 8081, 8090, // 其他服务
      11211, 27017, 27018, 27019 // 缓存和数据库
    ];
    
    const port = parsedUrl.port ? parseInt(parsedUrl.port) : 
                 (parsedUrl.protocol === 'https:' ? 443 : 80);
    
    // 阻止内部网络访问
    const hostname = parsedUrl.hostname.toLowerCase();
    if (isPrivateIP(hostname)) {
      throw new Error('禁止访问内部网络地址');
    }
    
    // 阻止访问危险端口（除了标准HTTP/HTTPS端口）
    if (port !== 80 && port !== 443 && dangerousPorts.includes(port)) {
      throw new Error(`禁止访问端口 ${port}`);
    }
    
    // 限制URL长度
    if (url.length > 2048) {
      throw new Error('URL长度超过限制');
    }
    
    return parsedUrl.toString();
  } catch (error) {
    if (error.message.includes('禁止') || error.message.includes('只允许') || error.message.includes('超过')) {
      throw error;
    }
    throw new Error('无效的URL格式');
  }
}

// 验证中间件
const validateRequest = (schema) => {
  return (req, res, next) => {
    const { error } = schema.validate(req.body);
    if (error) {
      return res.status(400).json({
        error: 'Validation failed',
        details: error.details.map(detail => detail.message)
      });
    }
    next();
  };
};

// 主页面
app.get('/', (req, res) => {
  res.json({
    message: 'Webhook System API',
    version: '1.0.0',
    security: 'Enhanced',
    endpoints: {
      receive: '/webhook/receive/:id',
      send: '/webhook/send',
      config: '/webhook/config',
      logs: '/webhook/logs',
      dashboard: '/ui',
      admin: '/admin'
    }
  });
});

// 管理员登录页面
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// 管理员登录API
app.post('/admin/login', 
  body('username').isLength({ min: 3 }).trim(),
  body('password').isLength({ min: 6 }),
  body('captcha').isLength({ min: 5, max: 5 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        success: false,
        message: '输入验证失败',
        errors: errors.array()
      });
    }

    const { username, password, captcha } = req.body;
    
    try {
      // 查找用户
      const user = dataStore.findUser(username);
      if (!user) {
        return res.status(401).json({ 
          success: false,
          message: '用户名或密码错误'
        });
      }

      // 验证密码
      const isValidPassword = bcrypt.compareSync(password, user.password_hash);
      if (!isValidPassword) {
        return res.status(401).json({ 
          success: false,
          message: '用户名或密码错误'
        });
      }

      // 更新最后登录时间
      dataStore.updateUserLastLogin(user.id);

      // 生成JWT令牌
      const token = jwt.sign(
        { 
          id: user.id, 
          username: user.username, 
          role: 'admin' 
        },
        JWT_SECRET,
        { expiresIn: '24h' }
      );

      // 记录登录日志
      dataStore.addLog({
        level: 'info',
        message: 'Admin login successful',
        data: JSON.stringify({ username, timestamp: Date.now() }),
        ip: req.ip,
        user_agent: req.get('User-Agent')
      });

      res.json({
        success: true,
        message: '登录成功',
        token,
        user: {
          id: user.id,
          username: user.username,
          lastLogin: user.last_login
        }
      });
    } catch (error) {
      logger.error('Admin login error', error);
      res.status(500).json({ 
        success: false,
        message: '登录失败，请重试'
      });
    }
  }
);

// 管理员仪表板页面
app.get('/admin/dashboard', requireAuth, requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// 管理员统计API
app.get('/admin/stats', requireAuth, requireAdmin, (req, res) => {
  try {
    const stats = dataStore.getStats();
    const totalWebhooks = webhookStore.receivers.size;
    
    res.json({
      success: true,
      ...stats,
      totalWebhooks,
      uptime: Math.floor(process.uptime()) + '秒',
      memory: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + 'MB'
    });
  } catch (error) {
    logger.error('Stats error', error);
    res.status(500).json({ 
      success: false,
      message: '获取统计数据失败'
    });
  }
});

// 获取令牌列表
app.get('/admin/tokens', requireAuth, requireAdmin, (req, res) => {
  try {
    const tokens = dataStore.getAllTokens().map(token => ({
      id: token.id,
      name: token.name,
      type: token.type,
      description: token.description,
      status: token.status,
      createdAt: new Date(token.created_at * 1000).toISOString(),
      lastUsed: token.last_used ? new Date(token.last_used * 1000).toISOString() : null,
      useCount: token.use_count
    }));
    
    res.json({
      success: true,
      tokens
    });
  } catch (error) {
    logger.error('Get tokens error', error);
    res.status(500).json({ 
      success: false,
      message: '获取令牌列表失败'
    });
  }
});

// 创建新令牌
app.post('/admin/tokens', 
  requireAuth, 
  requireAdmin,
  body('name').isLength({ min: 1 }).trim(),
  body('type').isIn(['admin', 'ui_access', 'api_access', 'webhook_secret']),
  body('description').optional().isLength({ max: 500 }),
  body('expiry').optional({ nullable: true, checkFalsy: true }).isInt({ min: 1 }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        success: false,
        message: '输入验证失败',
        errors: errors.array()
      });
    }

    const { name, type, description, expiry } = req.body;
    
    try {
      const tokenValue = crypto.randomBytes(32).toString('hex');
      const expiryDate = expiry ? Date.now() + (expiry * 24 * 60 * 60 * 1000) : null;
      
      const token = dataStore.createToken({
        name,
        type,
        value: tokenValue,
        description,
        status: 'active',
        expiry_date: expiryDate
      });

      // 记录创建日志
      dataStore.addLog({
        level: 'info',
        message: 'Token created',
        data: JSON.stringify({ tokenId: token.id, name, type, createdBy: req.user.username }),
        ip: req.ip,
        user_agent: req.get('User-Agent')
      });

      res.json({
        success: true,
        message: '令牌创建成功',
        token: {
          id: token.id,
          name,
          type,
          value: tokenValue,
          description,
          expiryDate
        }
      });
    } catch (error) {
      logger.error('Create token error', error);
      res.status(400).json({ 
        success: false,
        message: error.message || '创建令牌失败'
      });
    }
  }
);

// 获取令牌详情（用于复制）
app.get('/admin/tokens/:id/reveal', requireAuth, requireAdmin, (req, res) => {
  try {
    const token = dataStore.getAllTokens().find(t => t.id === req.params.id);
    
    if (!token) {
      return res.status(404).json({ 
        success: false,
        message: '令牌不存在'
      });
    }

    res.json({
      success: true,
      token: token.value
    });
  } catch (error) {
    logger.error('Reveal token error', error);
    res.status(500).json({ 
      success: false,
      message: '获取令牌失败'
    });
  }
});

// 更新令牌状态（启用/禁用）
app.patch('/admin/tokens/:id/status', requireAuth, requireAdmin, (req, res) => {
  try {
    const { status } = req.body;
    
    if (!['active', 'disabled'].includes(status)) {
      return res.status(400).json({
        success: false,
        message: '无效的状态值'
      });
    }
    
    const token = dataStore.getAllTokens().find(t => t.id === req.params.id);
    if (!token) {
      return res.status(404).json({
        success: false,
        message: '令牌不存在'
      });
    }
    
    // 更新令牌状态
    token.status = status;
    token.updated_at = Math.floor(Date.now() / 1000);
    dataStore.saveData(TOKENS_FILE, dataStore.tokens);
    
    // 记录状态更改日志
    dataStore.addLog({
      level: 'info',
      message: 'Token status changed',
      data: JSON.stringify({ 
        tokenId: req.params.id, 
        tokenName: token.name,
        oldStatus: token.status,
        newStatus: status,
        changedBy: req.user.username 
      }),
      ip: req.ip,
      user_agent: req.get('User-Agent')
    });
    
    res.json({
      success: true,
      message: `令牌已${status === 'active' ? '启用' : '禁用'}`
    });
  } catch (error) {
    logger.error('Update token status error', error);
    res.status(500).json({
      success: false,
      message: '更新令牌状态失败'
    });
  }
});

// 更新令牌
app.put('/admin/tokens/:id', 
  requireAuth, 
  requireAdmin,
  body('name').optional().isLength({ min: 1 }).trim(),
  body('description').optional().isLength({ max: 500 }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        success: false,
        message: '输入验证失败',
        errors: errors.array()
      });
    }

    const { name, description } = req.body;
    
    try {
      const updatedToken = dataStore.updateToken(req.params.id, {
        name,
        description
      });

      // 记录更新日志
      dataStore.addLog({
        level: 'info',
        message: 'Token updated',
        data: JSON.stringify({ 
          tokenId: req.params.id, 
          tokenName: updatedToken.name,
          updatedBy: req.user.username 
        }),
        ip: req.ip,
        user_agent: req.get('User-Agent')
      });

      res.json({
        success: true,
        message: '令牌更新成功',
        token: {
          id: updatedToken.id,
          name: updatedToken.name,
          type: updatedToken.type,
          description: updatedToken.description
        }
      });
    } catch (error) {
      logger.error('Update token error', error);
      res.status(500).json({ 
        success: false,
        message: error.message || '更新令牌失败'
      });
    }
  }
);

// 删除令牌
app.delete('/admin/tokens/:id', requireAuth, requireAdmin, (req, res) => {
  try {
    const tokenToDelete = dataStore.getAllTokens().find(t => t.id === req.params.id);
    
    if (!tokenToDelete) {
      return res.status(404).json({ 
        success: false,
        message: '令牌不存在'
      });
    }
    
    // 检查是否为当前JWT会话用的令牌（防止删除正在使用的管理员令牌）
    if (req.token && req.token.id === req.params.id) {
      return res.status(400).json({
        success: false,
        message: '不能删除当前正在使用的令牌'
      });
    }
    
    const success = dataStore.deleteToken(req.params.id);
    
    if (!success) {
      return res.status(404).json({ 
        success: false,
        message: '令牌不存在'
      });
    }

    // 记录删除日志
    dataStore.addLog({
      level: 'info',
      message: 'Token deleted',
      data: JSON.stringify({ 
        tokenId: req.params.id, 
        tokenName: tokenToDelete.name,
        tokenType: tokenToDelete.type,
        deletedBy: req.user.username 
      }),
      ip: req.ip,
      user_agent: req.get('User-Agent')
    });

    res.json({
      success: true,
      message: '令牌删除成功'
    });
  } catch (error) {
    logger.error('Delete token error', error);
    res.status(500).json({ 
      success: false,
      message: '删除令牌失败'
    });
  }
});

// 获取管理员账户信息
app.get('/admin/profile', requireAuth, requireAdmin, (req, res) => {
  try {
    const user = dataStore.findUser(req.user.username);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: '用户不存在'
      });
    }

    res.json({
      success: true,
      username: user.username,
      lastLogin: user.last_login ? new Date(user.last_login * 1000).toISOString() : null,
      loginCount: user.login_count || 0,
      createdAt: new Date(user.created_at * 1000).toISOString()
    });
  } catch (error) {
    logger.error('Get profile error', error);
    res.status(500).json({
      success: false,
      message: '获取账户信息失败'
    });
  }
});

// 修改密码
app.post('/admin/change-password', 
  requireAuth, 
  requireAdmin,
  body('currentPassword').isLength({ min: 1 }),
  body('newPassword').isLength({ min: 6 }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: '输入验证失败',
        errors: errors.array()
      });
    }

    const { currentPassword, newPassword } = req.body;
    
    try {
      const user = dataStore.findUser(req.user.username);
      if (!user) {
        return res.status(404).json({
          success: false,
          message: '用户不存在'
        });
      }

      // 验证当前密码
      const isValidPassword = bcrypt.compareSync(currentPassword, user.password_hash);
      if (!isValidPassword) {
        return res.status(401).json({
          success: false,
          message: '当前密码错误'
        });
      }

      // 生成新密码哈希
      const newPasswordHash = bcrypt.hashSync(newPassword, 12);
      
      // 更新密码
      const success = dataStore.updateUserPassword(user.id, newPasswordHash);
      if (!success) {
        throw new Error('密码更新失败');
      }

      // 记录密码修改日志
      dataStore.addLog({
        level: 'info',
        message: 'Password changed',
        data: JSON.stringify({ username: user.username, timestamp: Date.now() }),
        ip: req.ip,
        user_agent: req.get('User-Agent')
      });

      res.json({
        success: true,
        message: '密码修改成功'
      });
    } catch (error) {
      logger.error('Change password error', error);
      res.status(500).json({
        success: false,
        message: '密码修改失败'
      });
    }
  }
);

// Web UI仪表板（需要身份验证）
app.get('/ui', 
  requireAuth,
  (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  }
);

// API端点用于Web UI获取数据（轻量级认证）
app.get('/api/dashboard/stats', 
  (req, res) => {
    try {
      const receivers = Array.from(webhookStore.receivers.values());
      const logsResult = webhookStore.getLogs(100);
      const logs = logsResult.logs || []; // 获取实际的日志数组
      
      const stats = {
        totalReceivers: receivers.length,
        totalRequests: logs.length,
        recentRequests: logs.filter(log => {
          const logTime = new Date(log.timestamp);
          const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
          return logTime > oneHourAgo;
        }).length,
        successfulRequests: logs.filter(log => 
          log.type === 'RECEIVED' || log.type === 'SENT'
        ).length,
        failedRequests: logs.filter(log => 
          log.type.includes('ERROR') || log.type.includes('FAILED')
        ).length
      };
      
      res.json(stats);
    } catch (error) {
      console.error('Stats API error:', error);
      res.status(500).json({ 
        error: 'Internal server error',
        message: 'Failed to load statistics'
      });
    }
  }
);

// API端点用于Web UI获取最近日志（轻量级认证）
app.get('/api/dashboard/recent-logs', 
  query('limit').optional().isInt({ min: 1, max: 50 }),
  (req, res) => {
    try {
      const limit = parseInt(req.query.limit) || 20;
      const logsResult = webhookStore.getLogs(limit);
      
      res.json({
        logs: logsResult.logs || [], // 获取实际的日志数组
        total: logsResult.total || 0
      });
    } catch (error) {
      console.error('Recent logs API error:', error);
      res.status(500).json({ 
        error: 'Internal server error',
        message: 'Failed to load recent logs'
      });
    }
  }
);

// 接收webhook
app.post('/webhook/receive/:id', 
  webhookLimiter,
  param('id').matches(/^[a-zA-Z0-9_-]+$/).isLength({ min: 3, max: 50 }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Invalid webhook ID',
        details: errors.array()
      });
    }

    const webhookId = req.params.id;
    const payload = req.body;
    const signature = req.headers['x-webhook-signature'];
    
    // 检查webhook是否存在
    const webhookConfig = webhookStore.getReceiver(webhookId);
    if (!webhookConfig) {
      webhookStore.addLog('WEBHOOK_NOT_FOUND', {
        webhookId,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });
      return res.status(404).json({ error: 'Webhook not found' });
    }
    
    // 验证签名（如果配置了密钥）
    if (webhookConfig.secret) {
      if (!signature) {
        webhookStore.addLog('MISSING_SIGNATURE', {
          webhookId,
          ip: req.ip
        });
        return res.status(401).json({ error: 'Signature required' });
      }
      
      if (!verifySignature(payload, signature, webhookConfig.secret)) {
        webhookStore.addLog('SIGNATURE_VERIFICATION_FAILED', {
          webhookId,
          ip: req.ip
        });
        return res.status(401).json({ error: 'Invalid signature' });
      }
    }
    
    // 更新使用统计
    webhookConfig.lastUsed = new Date().toISOString();
    webhookConfig.useCount++;
    
    // 记录接收到的webhook
    webhookStore.addLog('RECEIVED', {
      webhookId,
      payload,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });
    
    res.json({ 
      success: true, 
      message: 'Webhook received successfully',
      timestamp: new Date().toISOString()
    });
  }
);

// 发送webhook
app.post('/webhook/send', 
  validateRequest(webhookSendSchema),
  async (req, res) => {
    const { url, payload, secret, headers = {} } = req.body;
    
    try {
      // 验证和清理URL
      const sanitizedUrl = sanitizeUrl(url);
      
      const requestHeaders = { ...headers };
      
      // 如果提供了密钥，添加签名
      if (secret) {
        const signature = generateSignature(payload, secret);
        requestHeaders['X-Webhook-Signature'] = signature;
      }
      
      // 添加默认headers
      requestHeaders['Content-Type'] = 'application/json';
      requestHeaders['User-Agent'] = 'Webhook-System/1.0';
      
      const response = await axios.post(sanitizedUrl, payload, {
        headers: requestHeaders,
        timeout: parseInt(process.env.WEBHOOK_TIMEOUT) || 30000,
        maxRedirects: 3,
        validateStatus: (status) => status < 500
      });
      
      webhookStore.addLog('SENT', {
        url: sanitizedUrl,
        status: response.status,
        responseHeaders: response.headers
      });
      
      res.json({
        success: true,
        message: 'Webhook sent successfully',
        status: response.status,
        timestamp: new Date().toISOString()
      });
      
    } catch (error) {
      webhookStore.addLog('SEND_ERROR', {
        url: req.body.url,
        error: error.message,
        status: error.response?.status
      });
      
      res.status(500).json({
        success: false,
        error: 'Failed to send webhook',
        details: error.message,
        timestamp: new Date().toISOString()
      });
    }
  }
);

// 配置webhook接收器
app.post('/webhook/config/receiver', 
  validateRequest(webhookConfigSchema),
  (req, res) => {
    const { id, secret, description } = req.body;
    
    try {
      // 处理空字符串的secret - 转换为undefined
      const processedSecret = secret && secret.trim() !== '' ? secret : undefined;
      const config = webhookStore.addReceiver(id, { secret: processedSecret, description });
      config.url = `${req.protocol}://${req.get('host')}/webhook/receive/${config.id}`;
      
      webhookStore.addLog('RECEIVER_CONFIGURED', { 
        id: config.id, 
        description: config.description 
      });
      
      res.json({
        success: true,
        message: 'Webhook receiver configured',
        config: {
          id: config.id,
          description: config.description,
          url: config.url,
          createdAt: config.createdAt
        }
      });
    } catch (error) {
      res.status(400).json({
        success: false,
        error: error.message
      });
    }
  }
);

// 获取webhook配置（需要身份验证）
app.get('/webhook/config', 
  requireAuth,
  (req, res) => {
    const receivers = Array.from(webhookStore.receivers.values()).map(config => ({
      id: config.id,
      description: config.description,
      createdAt: config.createdAt,
      lastUsed: config.lastUsed,
      useCount: config.useCount
    }));
    
    res.json({
      receivers,
      totalReceivers: receivers.length
    });
  }
);

// 获取日志（需要身份验证）
app.get('/webhook/logs', 
  requireAuth,
  query('limit').optional().isInt({ min: 1, max: 100 }),
  query('offset').optional().isInt({ min: 0 }),
  query('type').optional().isAlpha(),
  query('level').optional().isIn(['info', 'warn', 'error']),
  query('search').optional().isString().isLength({ max: 100 }),
  query('date_from').optional().isISO8601(),
  query('date_to').optional().isISO8601(),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Invalid query parameters',
        details: errors.array()
      });
    }

    const filters = {
      limit: parseInt(req.query.limit) || 50,
      offset: parseInt(req.query.offset) || 0,
      type: req.query.type,
      level: req.query.level,
      search: req.query.search,
      dateFrom: req.query.date_from ? new Date(req.query.date_from) : null,
      dateTo: req.query.date_to ? new Date(req.query.date_to) : null
    };
    
    const result = webhookStore.getFilteredLogs(filters);
    
    res.json({
      logs: result.logs,
      total: result.total,
      limit: result.limit,
      offset: result.offset,
      filters: {
        type: filters.type || 'all',
        level: filters.level || 'all',
        search: filters.search || '',
        dateRange: filters.dateFrom && filters.dateTo ? {
          from: filters.dateFrom.toISOString(),
          to: filters.dateTo.toISOString()
        } : null
      }
    });
  }
);

// 删除webhook接收器（需要身份验证）
app.delete('/webhook/config/receiver/:id', 
  requireAuth,
  param('id').matches(/^[a-zA-Z0-9_-]+$/).isLength({ min: 3, max: 50 }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Invalid webhook ID',
        details: errors.array()
      });
    }

    const id = req.params.id;
    
    if (webhookStore.deleteReceiver(id)) {
      webhookStore.addLog('RECEIVER_DELETED', { id });
      res.json({ success: true, message: 'Webhook receiver deleted' });
    } else {
      res.status(404).json({ error: 'Webhook receiver not found' });
    }
  }
);

// 通用webhook接收端点（兼容外部系统格式要求）
app.post('/webhook', 
  webhookLimiter,
  (req, res) => {
    const payload = req.body;
    const authHeader = req.headers.authorization;
    const userAgent = req.get('User-Agent');
    const ip = req.ip;
    
    // 准备记录数据 - 智能提取事件信息
    let logData = {
      webhookId: 'general',
      payload,
      ip,
      userAgent,
      authHeader: authHeader ? 'Bearer ***' : 'none' // 隐藏实际token
    };

    // 如果是结构化数据，添加解析后的信息
    if (payload && typeof payload === 'object') {
      const eventType = payload.eventType || payload.type || 'unknown';
      const eventTitle = payload.eventTypeName || payload.title || 'no title';
      
      // 提取内容数据 - 支持多种格式
      let contentData = null;
      if (payload.data) {
        if (typeof payload.data === 'string') {
          contentData = payload.data;
        } else if (payload.data?.content) {
          contentData = payload.data.content;
        } else if (payload.data?.singlePageData?.title) {
          contentData = payload.data.singlePageData.title;
        } else {
          contentData = JSON.stringify(payload.data);
        }
      } else if (payload.content) {
        contentData = payload.content;
      }
      
      // 扩展logData包含解析后的信息
      logData.eventType = eventType;
      logData.eventTypeName = eventTitle;
      logData.content = contentData || '无内容';
      logData.eventTime = payload.hookTime || new Date().toISOString();
    }

    // 记录接收到的webhook
    webhookStore.addLog('RECEIVED', logData);
    
    // 验证数据格式（可选）
    if (payload && typeof payload === 'object') {
      // 智能提取事件信息
      const eventType = payload.eventType || payload.type || 'unknown';
      const eventTitle = payload.eventTypeName || payload.title || 'no title';
      
      // 提取内容数据 - 支持多种格式
      let contentData = null;
      if (payload.data) {
        if (typeof payload.data === 'string') {
          contentData = payload.data;
        } else if (payload.data?.content) {
          contentData = payload.data.content;
        } else if (payload.data?.singlePageData?.title) {
          contentData = payload.data.singlePageData.title;
        } else {
          contentData = JSON.stringify(payload.data);
        }
      } else if (payload.content) {
        contentData = payload.content;
      }
      
      const hasContent = !!contentData;
      const pageTitle = payload.data?.singlePageData?.title || null;
      
      // 记录更详细的webhook信息到dataStore
      dataStore.addLog({
        level: 'info',
        message: 'General webhook received',
        data: JSON.stringify({
          webhookId: 'general',
          eventType: eventType,
          eventTypeName: eventTitle,
          content: contentData || '无内容',
          eventTime: payload.hookTime || new Date().toISOString(),
          ip: ip,
          userAgent: userAgent
        }),
        ip: ip,
        user_agent: userAgent
      });
      
      logger.info('General webhook received', {
        eventType: eventType,
        eventTypeName: eventTitle,
        type: eventType, // 保持向后兼容
        title: pageTitle ? `${eventTitle} - ${pageTitle}页面` : eventTitle,
        content: contentData,
        hasContent: hasContent,
        hasValues: Array.isArray(payload.values),
        hookTime: payload.hookTime,
        timestamp: payload.timestamp || Date.now()
      });
    }
    
    res.json({ 
      success: true, 
      message: 'Webhook received successfully',
      timestamp: new Date().toISOString()
    });
  }
);

// 健康检查
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    version: '1.0.0'
  });
});

// 错误日志中间件
app.use(expressWinston.errorLogger({
  winstonInstance: logger,
  meta: true,
  msg: "HTTP {{req.method}} {{req.url}} {{res.statusCode}} {{res.responseTime}}ms",
}));

// 全局错误处理
app.use((err, req, res, next) => {
  logger.error('Unhandled error', {
    error: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip
  });
  
  res.status(500).json({ 
    error: 'Internal server error',
    timestamp: new Date().toISOString(),
    requestId: req.headers['x-request-id'] || 'unknown'
  });
});

// 404处理
app.use((req, res) => {
  res.status(404).json({ 
    error: 'Endpoint not found',
    path: req.path,
    method: req.method,
    timestamp: new Date().toISOString()
  });
});

// 优雅关闭
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully');
  process.exit(0);
});

const server = app.listen(PORT, () => {
  logger.info(`🚀 Webhook System server running on port ${PORT}`);
  logger.info(`📡 API documentation: http://localhost:${PORT}`);
  logger.info(`🔒 Security: Enhanced with rate limiting and validation`);
});

module.exports = { app, server };