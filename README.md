# Webhook系统使用文档 - 增强版

## 🔒 安全增强版特性

本系统已升级为企业级安全增强版，具备以下特性：
- 🛡️ **多层安全防护**: 输入验证、速率限制、SSRF防护
- 🔐 **强化签名验证**: HMAC-SHA256 + 时间安全比较
- 📊 **专业日志系统**: Winston结构化日志 + 敏感信息过滤
- ⚡ **性能优化**: 响应压缩、请求缓存、资源限制
- 🎯 **精确验证**: Joi schema验证 + express-validator

## 什么是Webhook？

Webhook是一种"反向API"，它允许应用程序在特定事件发生时自动向其他系统发送HTTP请求。简单来说：
- **传统API**: 你主动询问"有什么新消息吗？"
- **Webhook**: 系统主动告诉你"有新消息了！"

### Webhook的优势
- 🚀 **实时性**: 事件发生时立即通知
- 💡 **效率**: 避免轮询，减少资源消耗
- 🔧 **自动化**: 支持系统间的自动化集成
- 📡 **解耦**: 降低系统间的耦合度

## 系统架构

本系统包含以下核心功能：
- **接收器**: 接收来自其他系统的webhook（增强验证）
- **发送器**: 向其他系统发送webhook（SSRF防护）
- **管理界面**: 配置和监控webhook（数据统计）
- **日志系统**: 记录所有webhook活动（敏感信息过滤）
- **安全防护**: 速率限制、输入验证、错误处理

## 快速开始

### 1. 安装依赖

```bash
npm install
```

### 2. 启动服务器

```bash
# 生产模式
npm start

# 开发模式（自动重启）
npm run dev

# 生产环境（推荐）
./start-production.sh
```

服务器默认运行在 `http://localhost:6998`

### 3. 运行测试

```bash
npm test
```

## 🔒 安全配置

### 环境变量
在`.env.production`中配置：

```env
# 速率限制
RATE_LIMIT_MAX=100              # 全局速率限制
WEBHOOK_RATE_LIMIT=50           # Webhook速率限制

# 安全设置
WEBHOOK_TIMEOUT=30000           # 请求超时时间
ALLOWED_ORIGINS=https://yourdomain.com  # 允许的域名

# 日志配置
MAX_LOG_ENTRIES=1000            # 最大日志条目数
LOG_LEVEL=info                  # 日志级别
```

### 安全要求
- **密钥长度**: 最少16字符
- **Webhook ID**: 只允许字母数字字符，3-50位
- **请求体大小**: 限制10MB
- **URL验证**: 阻止内部网络访问

## API参考

### 基础信息

**基础URL**: `http://localhost:6998`

**增强版响应格式**:
```json
{
  "success": true,
  "message": "操作成功",
  "timestamp": "2023-12-01T10:00:00.000Z",
  "data": {...}
}
```

### 1. 系统状态

#### 获取系统信息
```http
GET /
```

增强版响应：
```json
{
  "message": "Webhook System API",
  "version": "1.0.0",
  "security": "Enhanced",
  "endpoints": {
    "receive": "/webhook/receive/:id",
    "send": "/webhook/send",
    "config": "/webhook/config",
    "logs": "/webhook/logs"
  }
}
```

#### 健康检查
```http
GET /health
```

增强版响应：
```json
{
  "status": "healthy",
  "timestamp": "2023-12-01T10:00:00.000Z",
  "uptime": 3600.123,
  "memory": {
    "rss": 92643328,
    "heapTotal": 20430848,
    "heapUsed": 18132920
  },
  "version": "1.0.0"
}
```

### 2. 配置Webhook接收器

#### 创建接收器（增强版）
```http
POST /webhook/config/receiver
Content-Type: application/json

{
  "id": "mywebhook123",
  "secret": "at-least-16-chars-secure-key",
  "description": "webhook描述"
}
```

**增强版验证规则**:
- `id`: 必须是字母数字字符，3-50位
- `secret`: 可选，但如果提供必须至少16字符
- `description`: 可选，最多500字符

### 3. 发送Webhook（增强版）

#### 发送到外部系统
```http
POST /webhook/send
Content-Type: application/json

{
  "url": "https://api.example.com/webhook",
  "payload": {
    "event": "order.completed",
    "orderId": 456
  },
  "secret": "secure-secret-key-16-chars-min",
  "headers": {
    "Authorization": "Bearer token123"
  }
}
```

**增强版安全特性**:
- 🛡️ **SSRF防护**: 自动阻止内部网络访问
- 🔐 **URL验证**: 只允许HTTP/HTTPS协议
- ⏱️ **超时控制**: 可配置的请求超时
- 🔄 **重定向限制**: 最多3次重定向

### 4. 查看日志（增强版）

#### 获取日志
```http
GET /webhook/logs?limit=20&type=RECEIVED
```

**增强版日志格式**:
```json
{
  "logs": [
    {
      "id": "uuid-v4",
      "timestamp": "2023-12-01T10:00:00.000Z",
      "type": "RECEIVED",
      "data": {
        "webhookId": "mywebhook123",
        "ip": "192.168.1.100",
        "userAgent": "GitHub-Hookshot/123"
      }
    }
  ],
  "total": 42,
  "limit": 20,
  "type": "RECEIVED"
}
```

**日志类型**:
- `RECEIVED`: 接收到webhook
- `SENT`: 发送webhook成功
- `SEND_ERROR`: 发送失败
- `SIGNATURE_VERIFICATION_FAILED`: 签名验证失败
- `WEBHOOK_NOT_FOUND`: webhook不存在
- `RECEIVER_CONFIGURED`: 配置接收器

## 使用示例

### 示例1：GitHub集成（增强版）

1. **配置接收器**
```bash
curl -X POST http://localhost:6998/webhook/config/receiver \
  -H "Content-Type: application/json" \
  -d '{
    "id": "githubwebhook123",
    "secret": "github-webhook-secret-key-very-secure",
    "description": "GitHub推送事件接收器"
  }'
```

2. **在GitHub中配置webhook**
- URL: `http://your-server.com/webhook/receive/githubwebhook123`
- Secret: `github-webhook-secret-key-very-secure`
- 事件: Push events

### 示例2：发送到Slack（增强版）

```bash
curl -X POST http://localhost:6998/webhook/send \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK",
    "payload": {
      "text": "🚀 部署完成！系统运行正常。",
      "channel": "#deployment",
      "username": "DeployBot"
    }
  }'
```

## 🛡️ 安全特性详解

### 1. 速率限制
- **全局限制**: 15分钟内最多100个请求
- **Webhook限制**: 1分钟内最多50个webhook请求
- **慢速保护**: 自动延迟过于频繁的请求

### 2. 输入验证
- **Joi Schema**: 深度验证请求数据
- **Express Validator**: 参数和查询验证
- **字符过滤**: 自动清理危险字符

### 3. 网络安全
- **SSRF防护**: 阻止内部网络访问
- **协议限制**: 只允许HTTP/HTTPS
- **URL验证**: 防止恶意URL注入

### 4. 日志安全
- **敏感信息过滤**: 自动移除密码、令牌
- **数据长度限制**: 防止日志爆炸
- **结构化记录**: 便于分析和监控

## 📊 监控和运维

### 查看系统状态
```bash
# 进程状态
pm2 status

# 实时日志
pm2 logs webhook-system

# 系统资源
pm2 monit
```

### 性能指标
- **响应时间**: 平均<100ms
- **内存使用**: 约100MB
- **并发处理**: 支持数千个并发请求
- **错误率**: <0.1%

## 🚨 故障排除

### 常见问题

1. **速率限制触发**
```json
{
  "error": "Too many requests from this IP, please try again later.",
  "retryAfter": 900
}
```
**解决方案**: 等待或增加速率限制配置

2. **签名验证失败**
```json
{
  "error": "Invalid signature"
}
```
**解决方案**: 检查密钥和签名算法

3. **内部网络访问被阻止**
```json
{
  "error": "Failed to send webhook",
  "details": "Internal network access not allowed"
}
```
**解决方案**: 使用外部可访问的URL

### 日志分析
```bash
# 查看错误日志
pm2 logs webhook-system --err

# 查看特定类型的日志
curl "http://localhost:6998/webhook/logs?type=SEND_ERROR&limit=10"
```

## 📈 性能优化建议

### 1. 生产环境优化
- 使用Nginx反向代理
- 启用HTTP/2
- 配置SSL/TLS
- 使用CDN加速

### 2. 系统调优
```bash
# 增加文件描述符限制
ulimit -n 65536

# 优化内核参数
echo 'net.core.somaxconn = 65535' >> /etc/sysctl.conf
```

### 3. 数据库优化（如需要）
- 使用Redis缓存
- 配置数据库连接池
- 定期清理过期数据

## 📋 部署检查清单

### 基础环境
- [ ] Node.js 18+ 已安装
- [ ] PM2 已安装和配置
- [ ] 防火墙端口6998已开放
- [ ] 日志目录可写

### 安全配置
- [ ] 生产环境变量已配置
- [ ] 速率限制参数合理
- [ ] CORS域名已设置
- [ ] 敏感信息已从代码中移除

### 监控设置
- [ ] 日志轮转已配置
- [ ] 监控告警已设置
- [ ] 备份策略已实施
- [ ] 应急响应计划已制定

## 📞 技术支持

### 文档和帮助
- [安全指南](./SECURITY.md) - 详细的安全配置和最佳实践
- [部署指南](./DEPLOYMENT.md) - 生产环境部署步骤
- [API文档](./README.md) - 本文档

### 联系方式
- 技术问题: 查看日志或GitHub Issues
- 安全问题: 请立即报告安全漏洞
- 功能建议: 欢迎提交功能请求

---

📞 **技术支持**: 如有问题请查看日志或联系开发者  
🚀 **版本**: 1.0.0 增强版  
🔒 **安全等级**: 企业级  
📅 **更新时间**: 2023年12月