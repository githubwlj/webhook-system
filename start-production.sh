#!/bin/bash

# Webhook系统生产环境启动脚本
# 使用方法: ./start-production.sh

echo "🚀 启动Webhook系统生产环境..."

# 检查Node.js是否安装
if ! command -v node &> /dev/null; then
    echo "❌ Node.js未安装，请先安装Node.js"
    exit 1
fi

# 检查npm是否安装
if ! command -v npm &> /dev/null; then
    echo "❌ npm未安装，请先安装npm"
    exit 1
fi

# 创建logs目录
mkdir -p logs

# 安装依赖
echo "📦 安装依赖包..."
npm install

# 检查PM2是否安装
if ! command -v pm2 &> /dev/null; then
    echo "📦 安装PM2进程管理器..."
    npm install -g pm2
fi

# 停止现有进程
echo "🛑 停止现有进程..."
pm2 stop webhook-system 2>/dev/null || true
pm2 delete webhook-system 2>/dev/null || true

# 启动生产环境
echo "🚀 启动生产环境..."
pm2 start ecosystem.config.js --env production

# 保存PM2配置
pm2 save

# 设置开机自启
pm2 startup

echo "✅ Webhook系统已成功启动！"
echo "📊 查看状态: pm2 status"
echo "📋 查看日志: pm2 logs webhook-system"
echo "🌐 访问地址: http://localhost:6998"
echo "⚡ 重启服务: pm2 restart webhook-system"
echo "🛑 停止服务: pm2 stop webhook-system"