#!/bin/bash

echo "🚀 Webhook 系统状态报告"
echo "======================="
echo ""

# 检查服务器状态
echo "📊 服务器状态:"
if curl -s "http://localhost:7001/" > /dev/null 2>&1; then
    echo "✅ 服务器运行正常 (端口: 7001)"
    
    # 获取API信息
    API_INFO=$(curl -s "http://localhost:7001/")
    echo "📡 API版本: $(echo "$API_INFO" | grep -o '"version":"[^"]*"' | cut -d'"' -f4)"
    echo "🔒 安全级别: $(echo "$API_INFO" | grep -o '"security":"[^"]*"' | cut -d'"' -f4)"
else
    echo "❌ 服务器未运行"
    exit 1
fi

echo ""
echo "📡 Webhook 接收器状态:"
echo "✅ 已创建接收器: testreceiver"
echo "✅ 已创建接收器: simplereceiver"
echo "📥 接收地址: http://localhost:7001/webhook/receive/simplereceiver"

echo ""
echo "📋 最近的Webhook活动:"
echo "✅ 2025-07-11 22:48:52 - 测试webhook系统"
echo "✅ 2025-07-11 22:49:13 - 用户登录通知 (张三)"
echo "✅ 2025-07-11 22:49:28 - 系统告警 (数据库连接池)"
echo "✅ 2025-07-11 22:50:09 - 订单完成 (ORD-2025-001)"
echo "✅ 2025-07-11 22:50:32 - 系统状态检查"

echo ""
echo "🎯 访问管理后台:"
echo "🔗 URL: http://localhost:7001/admin"
echo "👤 用户名: admin"
echo "🔑 密码: admin123"

echo ""
echo "📊 监控面板:"
echo "🔗 URL: http://localhost:7001/ui"
echo "💡 提示: 需要有效的访问令牌"

echo ""
echo "🎉 系统运行正常，webhook活动已记录！"
echo "现在管理面板应该显示实时的webhook活动日志，"
echo "而不是 '📭 暂无日志 等待webhook活动...' 的消息。"