const http = require('node:http');
const https = require('node:https');

async function waitForReadiness(baseUrl, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  const readyUrl = `${baseUrl}/health/ready`;
  let lastError = '';
  while (Date.now() < deadline) {
    try {
      const response = await requestJson(readyUrl, { method: 'GET' });
      if (response.status === 'ready') return;
      lastError = JSON.stringify(response);
    } catch (error) {
      lastError = error.message;
    }
    await sleep(1500);
  }
  throw new Error(`Timed out waiting for ${readyUrl}. Last error: ${lastError}`);
}

async function requestJson(urlString, init) {
  const response = await request(urlString, init);
  const text = response.body;
  if (response.status < 200 || response.status >= 300) {
    throw new HttpError(response.status, text);
  }
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return {};
  }
}

function request(urlString, init = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlString);
    const lib = url.protocol === 'https:' ? https : http;
    const req = lib.request(
      url,
      {
        method: init.method || 'GET',
        headers: init.headers || {},
        timeout: 10000,
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          resolve({
            status: res.statusCode || 0,
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });
      },
    );
    req.on('timeout', () => req.destroy(new Error(`Request timed out: ${urlString}`)));
    req.on('error', reject);
    if (init.body !== undefined) req.write(init.body);
    req.end();
  });
}

class HttpError extends Error {
  constructor(status, responseText) {
    super(`HTTP ${status}: ${responseText}`);
    this.status = status;
    this.responseText = responseText;
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

module.exports = {
  HttpError,
  requestJson,
  waitForReadiness,
};
