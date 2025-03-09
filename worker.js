// 环境变量 WORKER_AUTH_KEY 用于接口鉴权
// 环境变量 XIAOBAI_COOKIE_KEYS 需要包含有效的Bearer令牌（每行一个）

const HMAC_SECRET = "TkoWuEN8cpDJubb7Zfwxln16NQDZIc8z";
const FIXED_DEVICE_ID = "de9b27e8e4f729c55f4d4e9e0ce3c937_1741362388656_638599";
const USER_ID = 104296504;
const TIME_OFFSET = 0; // 根据实际情况调整时间偏移量

async function sha256Base64(data) {
  const buffer = await crypto.subtle.digest(
    'SHA-256', 
    new TextEncoder().encode(data)
  );
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

async function generateHeaders(body) {
  const xDate = new Date(Date.now() + TIME_OFFSET).toUTCString();
  const digest = `SHA-256=${await sha256Base64(body)}`;
  
  // HMAC-SHA1签名
  const hmacKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(HMAC_SECRET),
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign(
    'HMAC',
    hmacKey,
    new TextEncoder().encode(`x-date: ${xDate}\ndigest: ${digest}`.replace(/\r\n/g, '\n'))
  );
  
  const signatureB64 = btoa(String.fromCharCode(...new Uint8Array(signature)));

  return {
    'accept': 'text/event-stream',
    'authorization': `hmac username="web.1.0.beta", algorithm="hmac-sha1", headers="x-date digest", signature="${signatureB64}"`,
    'content-type': 'application/json',
    'digest': digest,
    'x-date': xDate,
    'x-yuanshi-authorization': `Bearer ${apiKey}`,
    'x-yuanshi-appname': 'wenxiaobai',
    'x-yuanshi-appversioncode': '',
    'x-yuanshi-appversionname': '3.1.0',
    'x-yuanshi-channel': 'browser',
    'x-yuanshi-deviceid': FIXED_DEVICE_ID,
    'x-yuanshi-platform': 'web',
    'origin': 'https://www.wenxiaobai.com',
    'referer': 'https://www.wenxiaobai.com/',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
    'sec-ch-ua': '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-site'
  };
}

function buildRequestBody(openaiData) {
  const lastMessage = openaiData.messages
    .slice()
    .reverse()
    .find(m => m.role === 'user')?.content || "";
    
  return JSON.stringify({
    userId: USER_ID,
    botId: "200006",
    botAlias: "custom",
    query: lastMessage,
    isRetry: false,
    breakingStrategy: 0,
    isNewConversation: true,
    mediaInfos: [],
    turnIndex: 0,
    rewriteQuery: "",
    capabilities: [{
      defaultQuery: "",
      capability: "otherBot",
      capabilityRang: 0,
      minAppVersion: "",
      botId: 200004,
      exclusiveCapabilities: null,
      defaultSelected: false,
      defaultHidden: false,
      key: "deep_think",
      defaultPlaceholder: "",
      isPromptMenu: false,
      promptMenu: false,
      _id: "deep_think"
    }],
    attachmentInfo: { url: { infoList: [] } },
    inputWay: "proactive",
    pureQuery: ""
  });
}

class StreamProcessor {
  constructor(writer) {
    this.writer = writer;
    this.buffer = '';
    this.inThinkChain = false;
    this.thinkTimer = null;
    this.openaiId = `chatcmpl-${crypto.randomUUID().replace(/-/g, '')}`;
    this.created = Math.floor(Date.now() / 1000);
  }

  async process(chunk) {
    this.buffer += new TextDecoder().decode(chunk);
    let index;
    while ((index = this.buffer.indexOf('\n\n')) >= 0) {
      const block = this.buffer.slice(0, index);
      this.buffer = this.buffer.slice(index + 2);
      await this.parseEventBlock(block);
    }
  }

  async parseEventBlock(block) {
    let eventType = 'message';
    let data = '';
    const lines = block.split('\n');
    for (const line of lines) {
      if (line.startsWith('event:')) {
        eventType = line.slice(6).trim();
      } else if (line.startsWith('data:')) {
        data += line.slice(5).trim();
      }
    }
    if (data) {
      try {
        const jsonData = JSON.parse(data);
        await this.handleEvent(eventType, jsonData);
      } catch (e) {
        console.error('Parse error', e);
      }
    }
  }

  async handleEvent(eventType, data) {
    switch (eventType) {
      case 'message':
        await this.handleMessage(data);
        break;
      case 'generateEnd':
        await this.finalize();
        break;
    }
  }

  async handleMessage(data) {
    const content = data.content || '';
    
    // 处理思维链开始
    if (content.includes('```ys_think') && !this.inThinkChain) {
      await this.startThinkChain();
    }
    
    // 处理思维链结束
    if (content.includes('</end>') && this.inThinkChain) {
      await this.endThinkChain();
    }
    
    // 转发正式内容（仅在非思考链状态）
    if (!this.inThinkChain && content) {
      await this.sendChunk(this.cleanContent(content));
    }
  }
  
  async startThinkChain() {
    if (this.thinkTimer) return;
    
    this.inThinkChain = true;
    await this.sendChunk('<think>');
    
    this.thinkTimer = setInterval(async () => {
      const char = String.fromCharCode(65 + Math.floor(Math.random() * 26));
      await this.sendChunk(char);
    }, 2000);
  }

  async endThinkChain() {
    clearInterval(this.thinkTimer);
    this.inThinkChain = false;
    await this.sendChunk('</think>');
  }

  cleanContent(content) {
    return content
      .replace(/<icon>[^]*?<\/icon>/g, '')
      .replace(/```ys_think/g, '')
      .replace(/<start>[^]*?<\/start>/g, '')
      .replace(/<end>[^]*?<\/end>/g, '')
      .replace(/\n+/g, '\n');
  }

  async sendChunk(content, finish = false) {
    const chunk = {
      id: this.openaiId,
      object: "chat.completion.chunk",
      created: this.created,
      model: "Wenxiaobai-DeepSeek-R1",
      choices: [{
        index: 0,
        delta: finish ? {} : { content },
        finish_reason: finish ? "stop" : null
      }]
    };
    
    await this.writer.write(
      new TextEncoder().encode(`data: ${JSON.stringify(chunk)}\n\n`)
    );
  }

  async finalize() {
    clearInterval(this.thinkTimer);
    await this.sendChunk('', true);
    await this.writer.close();
  }
}

export default {
  async fetch(request, env) {
    // CORS预检处理
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
          "Access-Control-Max-Age": "86400"
        }
      });
    }

    // 鉴权验证
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || authHeader !== `Bearer ${env.WORKER_AUTH_KEY}`) {
      return new Response(JSON.stringify({
        error: { message: "Unauthorized", type: "auth_error" }
      }), { 
        status: 401,
        headers: { 
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*" 
        }
      });
    }

    // 路由处理
    const url = new URL(request.url);
    if (url.pathname === "/v1/models") {
      return new Response(JSON.stringify({
        object: "list",
        data: [{
          id: "Wenxiaobai-DeepSeek-R1",
          object: "model",
          created: 1686935002,
          owned_by: "wenxiaobai"
        }]
      }), {
        headers: { 
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*" 
        }
      });
    }

    try {
      const apiKeys = (env.XIAOBAI_COOKIE_KEYS || "")
        .split("\n")
        .map(k => k.trim())
        .filter(Boolean);

      if (apiKeys.length === 0) {
        throw new Error("No API keys configured");
      }

      const requestData = await request.json();
      
      // 顺序尝试所有密钥
      for (const apiKey of apiKeys) {
        try {
          const requestBody = buildRequestBody(requestData);
          const headers = await generateHeaders(requestBody);
          headers['x-yuanshi-authorization'] = `Bearer ${apiKey}`;

          const xbResponse = await fetch(
            "https://api-bj.wenxiaobai.com/api/v1.0/core/conversation/chat/v1",
            {
              method: "POST",
              headers: headers,
              body: requestBody
            }
          );

          if (!xbResponse.ok) throw new Error(`HTTP ${xbResponse.status}`);
          
          return requestData.stream 
            ? this.handleStream(xbResponse) 
            : this.handleJson(xbResponse);

        } catch (error) {
          console.error(`Key failed: ${error.message}`);
          if (apiKey === apiKeys[apiKeys.length - 1]) throw error;
        }
      }
    } catch (error) {
      return new Response(JSON.stringify({
        error: { message: `Starrina Proxy Error`, type: "api_error" }
      }), { 
        status: 500,
        headers: { 
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*" 
        }
      });
    }
  },

  handleStream(response) {
    const { readable, writable } = new TransformStream();
    const writer = writable.getWriter();
    const processor = new StreamProcessor(writer);

    (async () => {
      const reader = response.body.getReader();
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          await processor.process(new TextDecoder().decode(value));
        }
        await processor.finalize();
      } catch (error) {
        console.error('Stream Error:', error);
        writer.abort(error);
      }
    })();

    return new Response(readable, {
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Access-Control-Allow-Origin": "*"
      }
    });
  },

  async handleJson(response) {
    const data = await response.json();
    return new Response(JSON.stringify({
      id: `chatcmpl-${crypto.randomUUID()}`,
      object: "chat.completion",
      created: Math.floor(Date.now() / 1000),
      model: "Wenxiaobai-DeepSeek-R1",
      choices: [{
        message: { role: "assistant", content: data.content }
      }]
    }), {
      headers: { 
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*" 
      }
    });
  }
}
