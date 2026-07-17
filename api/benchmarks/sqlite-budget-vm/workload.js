import http from 'k6/http';
import { check, randomSeed, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

const BASE_URL = __ENV.BASE_URL || 'http://127.0.0.1:3301';
const EMAIL = __ENV.BENCHMARK_EMAIL || 'benchmark-user@loadtest.local';
const PASSWORD = __ENV.BENCHMARK_PASSWORD || 'Benchmark-User-Password-2026!';
const ORG = __ENV.BENCHMARK_ORG || 'benchmark-org';
const SERVICE = __ENV.BENCHMARK_SERVICE || 'benchmark-service';
const CLIENT_ID = __ENV.DEVICE_CLIENT_ID || 'platform-admin-cli';
const VUS = Number.parseInt(__ENV.VUS || '1', 10);
const DURATION = __ENV.DURATION || '15s';
const THINK_TIME = Number.parseFloat(__ENV.THINK_TIME || '1');
const SEED = Number.parseInt(__ENV.SEED || '20260716', 10);

const operationFailures = new Rate('operation_failures');
const subscriptionLatency = new Trend('subscription_latency', true);
const deviceCodeLatency = new Trend('device_code_latency', true);
const tokenPollLatency = new Trend('token_poll_latency', true);
const userLatency = new Trend('user_latency', true);
const subscriptionOperations = new Counter('subscription_operations');
const deviceOperations = new Counter('device_operations');
const userOperations = new Counter('user_operations');
const deviceCodeHttpErrors = new Counter('device_code_http_errors');
const tokenPollHttpErrors = new Counter('token_poll_http_errors');
const tokenPollSemanticErrors = new Counter('token_poll_semantic_errors');

export const options = {
  scenarios: {
    benchmark: {
      executor: 'constant-vus',
      vus: VUS,
      duration: DURATION,
      gracefulStop: '30s',
    },
  },
  thresholds: {
    operation_failures: ['rate<0.01'],
    http_req_duration: ['p(99)<30000'],
    'device_code_http_errors{status:400}': ['count>=0'],
    'device_code_http_errors{status:429}': ['count>=0'],
    'device_code_http_errors{status:500}': ['count>=0'],
    'device_code_http_errors{status:503}': ['count>=0'],
    'token_poll_http_errors{status:400}': ['count>=0'],
    'token_poll_http_errors{status:429}': ['count>=0'],
    'token_poll_http_errors{status:500}': ['count>=0'],
    'token_poll_http_errors{status:503}': ['count>=0'],
  },
  summaryTrendStats: ['min', 'med', 'avg', 'p(90)', 'p(95)', 'p(99)', 'max'],
  setupTimeout: '30s',
};

const json = {
  headers: { 'Content-Type': 'application/json' },
  responseCallback: http.expectedStatuses(200),
};

export function setup() {
  const response = http.post(
    `${BASE_URL}/api/auth/login`,
    JSON.stringify({
      email: EMAIL,
      password: PASSWORD,
      org_slug: ORG,
      service_slug: SERVICE,
    }),
    json,
  );

  if (response.status !== 200) {
    throw new Error(`benchmark login failed: HTTP ${response.status}: ${response.body}`);
  }

  return { accessToken: response.json('access_token') };
}

let seeded = false;

export default function (data) {
  if (!seeded) {
    randomSeed(SEED + __VU);
    seeded = true;
  }

  const choice = Math.random();
  let ok = false;

  if (choice < 0.70) {
    subscriptionOperations.add(1);
    const response = http.get(`${BASE_URL}/api/subscription`, {
      headers: { Authorization: `Bearer ${data.accessToken}` },
      responseCallback: http.expectedStatuses(200),
      tags: { operation: 'subscription' },
    });
    subscriptionLatency.add(response.timings.duration);
    ok = check(response, { 'subscription returned 200': (r) => r.status === 200 });
  } else if (choice < 0.90) {
    deviceOperations.add(1);
    const codeResponse = http.post(
      `${BASE_URL}/auth/device/code`,
      JSON.stringify({
        client_id: CLIENT_ID,
        org: 'platform',
        service: 'admin-cli',
      }),
      { ...json, tags: { operation: 'device_code' } },
    );
    deviceCodeLatency.add(codeResponse.timings.duration);
    if (codeResponse.status !== 200) {
      deviceCodeHttpErrors.add(1, {
        status: String(codeResponse.status),
        error_code: String(codeResponse.json('error_code') || 'none'),
      });
    }

    const deviceCode = codeResponse.json('device_code');
    let pollResponse = null;
    if (codeResponse.status === 200 && deviceCode) {
      pollResponse = http.post(
        `${BASE_URL}/auth/token`,
        JSON.stringify({
          client_id: CLIENT_ID,
          device_code: deviceCode,
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        }),
        {
          headers: { 'Content-Type': 'application/json' },
          responseCallback: http.expectedStatuses(400),
          tags: { operation: 'token_poll' },
        },
      );
      tokenPollLatency.add(pollResponse.timings.duration);
      if (pollResponse.status !== 400) {
        tokenPollHttpErrors.add(1, {
          status: String(pollResponse.status),
          error_code: String(pollResponse.json('error_code') || 'none'),
        });
      }
      if (pollResponse.status === 400 && pollResponse.json('error_code') !== 'DEVICE_CODE_PENDING') {
        tokenPollSemanticErrors.add(1);
      }
    }

    ok = check(codeResponse, { 'device code returned 200': (r) => r.status === 200 });
    ok = check(pollResponse, {
      'token poll returned authorization_pending': (r) =>
        r !== null && r.status === 400 && r.json('error_code') === 'DEVICE_CODE_PENDING',
    }) && ok;
  } else {
    userOperations.add(1);
    const response = http.get(`${BASE_URL}/api/user`, {
      headers: { Authorization: `Bearer ${data.accessToken}` },
      responseCallback: http.expectedStatuses(200),
      tags: { operation: 'user' },
    });
    userLatency.add(response.timings.duration);
    ok = check(response, { 'user returned 200': (r) => r.status === 200 });
  }

  operationFailures.add(!ok);
  if (THINK_TIME > 0) sleep(THINK_TIME);
}
