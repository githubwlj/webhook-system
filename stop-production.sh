#!/bin/bash

# Webhook系统停止脚本
# 使用方法: ./stop-production.sh

echo "🛑 停止Webhook系统..."

# 停止PM2进程
pm2 stop webhook-system 2>/dev/null || echo "⚠️  进程未运行或已停止"

# 删除PM2进程
pm2 delete webhook-system 2>/dev/null || echo "⚠️  进程未找到或已删除"

echo "✅ Webhook系统已停止"