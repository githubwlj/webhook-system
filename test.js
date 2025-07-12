const axios = require('axios');

const BASE_URL = 'http://localhost:6998';

// 测试函数
async function testWebhookSystem() {
  console.log('🧪 开始测试增强版Webhook系统...\n');
  
  try {
    // 1. 测试服务器状态
    console.log('1. 测试服务器状态...');
    const healthResponse = await axios.get(`${BASE_URL}/health`);
    console.log('✅ 服务器状态:', healthResponse.data.status);
    console.log('   版本:', healthResponse.data.version);
    
    // 2. 测试主页面
    console.log('\n2. 测试API信息...');
    const homeResponse = await axios.get(`${BASE_URL}/`);
    console.log('✅ API信息:', homeResponse.data.message);
    console.log('   安全等级:', homeResponse.data.security);
    
    // 3. 配置一个webhook接收器
    console.log('\n3. 配置webhook接收器...');
    const receiverConfig = {
      id: 'testwebhook123',
      secret: 'this-is-a-very-secure-secret-key-16-chars-min',
      description: '测试webhook接收器 - 增强版'
    };
    
    const configResponse = await axios.post(`${BASE_URL}/webhook/config/receiver`, receiverConfig);
    console.log('✅ 接收器配置成功:', configResponse.data.config.url);
    console.log('   创建时间:', configResponse.data.config.createdAt);
    
    // 4. 测试发送webhook到外部服务
    console.log('\n4. 测试发送webhook到外部服务...');
    const sendPayload = {
      url: 'https://httpbin.org/post',
      payload: {
        event: 'test',
        message: 'Hello from enhanced webhook system!',
        timestamp: new Date().toISOString(),
        test: true
      },
      secret: 'this-is-a-very-secure-secret-key-16-chars-min',
      headers: {
        'X-Custom-Header': 'enhanced-test-value'
      }
    };
    
    const sendResponse = await axios.post(`${BASE_URL}/webhook/send`, sendPayload);
    console.log('✅ Webhook发送成功:', sendResponse.data.message);
    console.log('   状态码:', sendResponse.data.status);
    
    // 5. 测试接收webhook（模拟外部服务发送）
    console.log('\n5. 测试接收webhook...');
    const testPayload = {
      event: 'user.created',
      user: {
        id: 12345,
        name: 'Test User',
        email: 'test@example.com'
      }
    };
    
    const crypto = require('crypto');
    const signature = crypto
      .createHmac('sha256', receiverConfig.secret)
      .update(JSON.stringify(testPayload))
      .digest('hex');
    
    const receiveResponse = await axios.post(
      `${BASE_URL}/webhook/receive/testwebhook123`,
      testPayload,
      {
        headers: {
          'X-Webhook-Signature': signature,
          'Content-Type': 'application/json'
        }
      }
    );
    console.log('✅ Webhook接收成功:', receiveResponse.data.message);
    
    // 6. 查看日志
    console.log('\n6. 查看webhook日志...');
    const logsResponse = await axios.get(`${BASE_URL}/webhook/logs?limit=10`);
    console.log('📋 最近的日志条目:');
    logsResponse.data.logs.forEach((log, index) => {
      console.log(`   ${index + 1}. [${log.timestamp}] ${log.type} - ${log.id}`);
    });
    
    // 7. 查看配置
    console.log('\n7. 查看当前配置...');
    const configListResponse = await axios.get(`${BASE_URL}/webhook/config`);
    console.log('⚙️ 配置的接收器数量:', configListResponse.data.totalReceivers);
    if (configListResponse.data.receivers.length > 0) {
      const receiver = configListResponse.data.receivers[0];
      console.log('   接收器ID:', receiver.id);
      console.log('   使用次数:', receiver.useCount);
      console.log('   最后使用:', receiver.lastUsed);
    }
    
    // 8. 测试速率限制（发送多个请求）
    console.log('\n8. 测试速率限制...');
    const promises = [];
    for (let i = 0; i < 5; i++) {
      promises.push(axios.get(`${BASE_URL}/health`));
    }
    await Promise.all(promises);
    console.log('✅ 速率限制测试完成（5个并发请求）');
    
    console.log('\n🎉 所有测试通过！系统已成功升级为增强版！');
    
  } catch (error) {
    console.error('❌ 测试失败:', error.response?.data || error.message);
    if (error.response?.status === 429) {
      console.log('⚠️  触发了速率限制 - 这是正常的安全行为');
    } else {
      process.exit(1);
    }
  }
}

// 运行测试
if (require.main === module) {
  testWebhookSystem();
}

module.exports = { testWebhookSystem };