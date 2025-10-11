<template>
  <div class="container">
    <h1>SSO Authentication Test</h1>

    <div v-if="!token" class="auth-section">
      <div class="flow-section">
        <h2>Redirect Flow</h2>
        <p>Test standard OAuth redirect flow for end-users</p>
        <button @click="startRedirectFlow" class="btn">Login with GitHub (Redirect)</button>
      </div>
    </div>

    <div v-else class="user-section">
      <h2>Authenticated!</h2>
      <div class="token-display">
        <p><strong>JWT Token:</strong></p>
        <code>{{ token.substring(0, 50) }}...</code>
      </div>
      <div class="user-info">
        <p><strong>User ID:</strong> {{ decodedToken?.sub }}</p>
        <p><strong>Email:</strong> {{ decodedToken?.email }}</p>
        <p><strong>Organization:</strong> {{ decodedToken?.org || 'N/A' }}</p>
        <p><strong>Service:</strong> {{ decodedToken?.service || 'N/A' }}</p>
      </div>
      <button @click="logout" class="btn btn-secondary">Logout</button>
    </div>

    <div v-if="error" class="error">
      {{ error }}
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue';
import { SsoClient } from '@drmhse/sso-sdk';

const API_URL = 'http://localhost:3000';
const ORG_SLUG = 'amp-dev';
const SERVICE_SLUG = 'sdd';
const REDIRECT_URI = 'http://localhost:4000';

const sso = new SsoClient({ baseURL: API_URL });

const token = ref(null);
const error = ref(null);

const decodedToken = computed(() => {
  if (!token.value) return null;
  try {
    const payload = token.value.split('.')[1];
    return JSON.parse(atob(payload));
  } catch (e) {
    return null;
  }
});

onMounted(() => {
  const urlParams = new URLSearchParams(window.location.search);
  const tokenParam = urlParams.get('token');

  if (tokenParam) {
    token.value = tokenParam;
    localStorage.setItem('sso_token', tokenParam);
    window.history.replaceState({}, document.title, '/');
  } else {
    const savedToken = localStorage.getItem('sso_token');
    if (savedToken) {
      token.value = savedToken;
    }
  }
});

function startRedirectFlow() {
  error.value = null;
  const loginUrl = sso.auth.getLoginUrl('github', {
    org: ORG_SLUG,
    service: SERVICE_SLUG,
    redirect_uri: REDIRECT_URI,
  });
  window.location.href = loginUrl;
}

function logout() {
  token.value = null;
  localStorage.removeItem('sso_token');
  error.value = null;
}
</script>

<style scoped>
.container {
  max-width: 800px;
  margin: 50px auto;
  padding: 20px;
}

h1 {
  color: #333;
  border-bottom: 2px solid #007bff;
  padding-bottom: 10px;
}

h2 {
  color: #555;
  margin-top: 20px;
}

.auth-section {
  display: flex;
  gap: 30px;
  margin-top: 30px;
}

.flow-section {
  flex: 1;
  padding: 20px;
  border: 1px solid #ddd;
  border-radius: 8px;
  background: #f9f9f9;
}

.btn {
  padding: 12px 24px;
  font-size: 16px;
  background: #007bff;
  color: white;
  border: none;
  border-radius: 5px;
  cursor: pointer;
  width: 100%;
}

.btn:hover:not(:disabled) {
  background: #0056b3;
}

.btn:disabled {
  background: #ccc;
  cursor: not-allowed;
}

.btn-secondary {
  background: #6c757d;
  margin-top: 20px;
}

.btn-secondary:hover {
  background: #5a6268;
}

.user-section {
  margin-top: 30px;
  padding: 20px;
  border: 1px solid #28a745;
  border-radius: 8px;
  background: #f0fff4;
}

.token-display {
  margin: 15px 0;
  padding: 10px;
  background: white;
  border-radius: 5px;
}

.token-display code {
  display: block;
  padding: 10px;
  background: #f4f4f4;
  border-radius: 3px;
  word-break: break-all;
}

.user-info {
  margin: 15px 0;
}

.user-info p {
  margin: 8px 0;
}

.error {
  margin-top: 20px;
  padding: 15px;
  background: #f8d7da;
  color: #721c24;
  border: 1px solid #f5c6cb;
  border-radius: 5px;
}
</style>
