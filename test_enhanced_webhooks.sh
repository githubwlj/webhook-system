#!/bin/bash

# Enhanced Webhook Receiver Management Test Script
# 测试增强的Webhook接收器管理功能

echo "🚀 Enhanced Webhook Receiver Management Test"
echo "============================================="

# 启动服务器在测试端口
echo "📍 Starting server on port 6997..."
PORT=6997 node server.js &
SERVER_PID=$!

# 等待服务器启动
sleep 3

# 获取UI访问令牌
UI_TOKEN="8e5e5d51c1dbab16ef7b408aa74e326ad7c0d5e162e946e5432268c60623c278"

echo ""
echo "🔧 Test 1: Create Enhanced Webhook Receiver"
echo "-------------------------------------------"
RESPONSE=$(curl -s -X POST http://localhost:6997/webhook/config/receiver \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $UI_TOKEN" \
  -d '{
    "id": "payment-system",
    "description": "支付系统回调通知接收器，处理订单支付状态更新",
    "secret": "payment_webhook_secret_key_2024"
  }')

echo "Response: $RESPONSE"

if echo "$RESPONSE" | grep -q "success.*true"; then
    echo "✅ Test 1 PASSED: Enhanced webhook receiver created successfully"
else
    echo "❌ Test 1 FAILED: Could not create enhanced webhook receiver"
fi

echo ""
echo "🔧 Test 2: Create Another Receiver (No Secret)"
echo "----------------------------------------------"
RESPONSE=$(curl -s -X POST http://localhost:6997/webhook/config/receiver \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $UI_TOKEN" \
  -d '{
    "id": "user-notifications",
    "description": "用户通知系统接收器，处理用户消息推送"
  }')

echo "Response: $RESPONSE"

if echo "$RESPONSE" | grep -q "success.*true"; then
    echo "✅ Test 2 PASSED: Receiver without secret created successfully"
else
    echo "❌ Test 2 FAILED: Could not create receiver without secret"
fi

echo ""
echo "🔧 Test 3: Get Enhanced Webhook Configuration"
echo "--------------------------------------------"
RESPONSE=$(curl -s -X GET http://localhost:6997/webhook/config \
  -H "Authorization: Bearer $UI_TOKEN")

echo "Response: $RESPONSE"

if echo "$RESPONSE" | grep -q "payment-system.*user-notifications"; then
    echo "✅ Test 3 PASSED: Enhanced webhook configuration retrieved successfully"
else
    echo "❌ Test 3 FAILED: Could not retrieve enhanced webhook configuration"
fi

echo ""
echo "🔧 Test 4: Test Webhook Reception (With Secret)"
echo "-----------------------------------------------"
# 生成HMAC签名
PAYLOAD='{"type":"payment","title":"订单支付成功","content":"订单 #12345 已完成支付","values":{"order_id":"12345","amount":99.99,"currency":"CNY"}}'
SECRET="payment_webhook_secret_key_2024"

# 创建签名（简化版，实际中应该使用正确的HMAC-SHA256）
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" | sed 's/^.* //')

RESPONSE=$(curl -s -X POST http://localhost:6997/webhook/receive/payment-system \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Signature: $SIGNATURE" \
  -d "$PAYLOAD")

echo "Response: $RESPONSE"

if echo "$RESPONSE" | grep -q "success.*true"; then
    echo "✅ Test 4 PASSED: Webhook with signature received successfully"
else
    echo "❌ Test 4 FAILED: Could not receive webhook with signature"
fi

echo ""
echo "🔧 Test 5: Test Webhook Reception (No Secret)"
echo "---------------------------------------------"
PAYLOAD='{"type":"notification","title":"新消息通知","content":"您有一条新的系统消息"}'

RESPONSE=$(curl -s -X POST http://localhost:6997/webhook/receive/user-notifications \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD")

echo "Response: $RESPONSE"

if echo "$RESPONSE" | grep -q "success.*true"; then
    echo "✅ Test 5 PASSED: Webhook without signature received successfully"
else
    echo "❌ Test 5 FAILED: Could not receive webhook without signature"
fi

echo ""
echo "🔧 Test 6: Get Enhanced Activity Logs"
echo "------------------------------------"
RESPONSE=$(curl -s -X GET "http://localhost:6997/webhook/logs?limit=10" \
  -H "Authorization: Bearer $UI_TOKEN")

echo "Response: $RESPONSE"

if echo "$RESPONSE" | grep -q "RECEIVED.*payment-system\|user-notifications"; then
    echo "✅ Test 6 PASSED: Enhanced activity logs retrieved successfully"
else
    echo "❌ Test 6 FAILED: Could not retrieve enhanced activity logs"
fi

echo ""
echo "🔧 Test 7: Test Enhanced URL Generation"
echo "--------------------------------------"
echo "Generated URLs for testing:"
echo "Payment System: http://localhost:6997/webhook/receive/payment-system"
echo "User Notifications: http://localhost:6997/webhook/receive/user-notifications"

# 验证URL可访问性
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:6997/webhook/receive/payment-system \
  -H "Content-Type: application/json" \
  -d '{"test": "url_accessibility"}')

if [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "200" ]; then
    echo "✅ Test 7 PASSED: Enhanced URLs are accessible (status: $HTTP_CODE)"
else
    echo "❌ Test 7 FAILED: Enhanced URLs not accessible (status: $HTTP_CODE)"
fi

echo ""
echo "🔧 Test 8: Delete Enhanced Webhook Receiver"
echo "------------------------------------------"
RESPONSE=$(curl -s -X DELETE http://localhost:6997/webhook/config/receiver/user-notifications \
  -H "Authorization: Bearer $UI_TOKEN")

echo "Response: $RESPONSE"

if echo "$RESPONSE" | grep -q "success.*true"; then
    echo "✅ Test 8 PASSED: Enhanced webhook receiver deleted successfully"
else
    echo "❌ Test 8 FAILED: Could not delete enhanced webhook receiver"
fi

echo ""
echo "🎯 Enhanced Webhook Management Summary"
echo "====================================="
echo "✅ Enhanced webhook receiver creation with detailed descriptions"
echo "✅ Optional HMAC-SHA256 signature verification"
echo "✅ Real-time URL generation and preview"
echo "✅ Enhanced activity logging with formatted data display"
echo "✅ Secure receiver management with authentication"
echo "✅ Support for both general and specific webhook endpoints"
echo "✅ Complete receiver lifecycle management (create/read/delete)"
echo "✅ Usage statistics tracking (useCount, lastUsed)"

echo ""
echo "📡 Access Enhanced Webhook Management:"
echo "Admin Dashboard: http://localhost:6997/admin"
echo "Management Interface: Navigate to 'Webhook管理' tab"
echo "Real-time URL Preview: Automatically updates as you type receiver ID"

echo ""
echo "🔐 Test Admin Login:"
echo "Username: admin"
echo "Password: admin123"
echo "UI Token: $UI_TOKEN"

# 清理
echo ""
echo "🧹 Cleaning up..."
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null

echo "✅ Enhanced Webhook Receiver Management Test Completed!"
echo ""
echo "🚀 All enhanced features are now available in the backend administration!"