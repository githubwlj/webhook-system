#!/bin/bash

# Webhook系统重启脚本
# 使用方法: ./restart-production.sh

echo "🔄 重启Webhook系统..."

# 重启PM2进程
pm2 restart webhook-system

echo "✅ Webhook系统已重启"
echo "📊 查看状态: pm2 status"
echo "📋 查看日志: pm2 logs webhook-system"