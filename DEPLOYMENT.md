# 生产环境部署指南

## 🚀 快速部署

### 1. 一键启动生产环境
```bash
./start-production.sh
```

### 2. 手动部署步骤

#### 安装依赖
```bash
npm install
```

#### 安装PM2（如果未安装）
```bash
npm install -g pm2
```

#### 启动生产环境
```bash
pm2 start ecosystem.config.js --env production
pm2 save
```

## 📊 服务管理

### 常用命令
```bash
# 查看服务状态
pm2 status

# 查看日志
pm2 logs webhook-system

# 重启服务
pm2 restart webhook-system

# 停止服务
pm2 stop webhook-system

# 删除服务
pm2 delete webhook-system
```

### 使用脚本管理
```bash
# 启动生产环境
./start-production.sh

# 停止服务
./stop-production.sh

# 重启服务
./restart-production.sh
```

## 🔧 配置说明

### 端口配置
- 生产环境端口: **6998**
- 访问地址: `http://localhost:6998`

### 环境变量
生产环境配置文件: `.env.production`
```env
PORT=6998
NODE_ENV=production
LOG_LEVEL=info
```

### PM2配置
配置文件: `ecosystem.config.js`
- 进程名称: webhook-system
- 运行模式: fork
- 内存限制: 1G
- 日志路径: ./logs/

## 📋 日志管理

### 日志文件位置
```
logs/
├── combined.log    # 综合日志
├── out.log         # 输出日志
└── error.log       # 错误日志
```

### 查看日志
```bash
# 实时查看日志
pm2 logs webhook-system

# 查看错误日志
pm2 logs webhook-system --err

# 查看输出日志
pm2 logs webhook-system --out
```

## 🛡️ 安全配置

### 防火墙设置
```bash
# 开放6998端口
sudo ufw allow 6998

# 查看防火墙状态
sudo ufw status
```

### 反向代理配置（Nginx）
```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://localhost:6998;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## 🔍 监控和诊断

### 性能监控
```bash
# 查看进程资源使用
pm2 monit

# 查看进程详情
pm2 show webhook-system
```

### 健康检查
```bash
# 检查服务状态
curl http://localhost:6998/health

# 检查API响应
curl http://localhost:6998/
```

## 🚨 故障排除

### 常见问题

1. **端口被占用**
```bash
# 查看端口使用情况
lsof -i :6998
# 或
netstat -tlnp | grep :6998
```

2. **权限问题**
```bash
# 给脚本添加执行权限
chmod +x *.sh
```

3. **服务启动失败**
```bash
# 查看详细日志
pm2 logs webhook-system --lines 50
```

### 重新部署
```bash
# 停止服务
pm2 stop webhook-system

# 拉取最新代码
git pull

# 安装依赖
npm install

# 重新启动
pm2 start ecosystem.config.js --env production
```

## 📈 性能优化

### 系统优化
```bash
# 增加文件描述符限制
ulimit -n 65536

# 优化内核参数
echo 'net.core.somaxconn = 65535' >> /etc/sysctl.conf
sysctl -p
```

### 应用优化
- 启用gzip压缩
- 使用CDN加速
- 数据库连接池优化
- 缓存策略

## 📞 技术支持

如遇问题，请查看：
1. 服务日志: `pm2 logs webhook-system`
2. 系统日志: `/var/log/syslog`
3. 错误日志: `./logs/error.log`

---

## 🎯 部署检查清单

- [ ] Node.js已安装
- [ ] PM2已安装
- [ ] 依赖包已安装
- [ ] 环境变量已配置
- [ ] 防火墙端口已开放
- [ ] 服务启动成功
- [ ] 健康检查通过
- [ ] 日志正常输出

部署完成后，访问 `http://localhost:6998` 验证服务是否正常运行。