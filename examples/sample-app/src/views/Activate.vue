<template>
  <div class="container">
    <!-- Step 1: Enter code -->
    <div v-if="!loginContext">
      <h1>Activate Your Device</h1>
      <p>Enter the code displayed on your CLI or device to authorize access.</p>

      <form @submit.prevent="verifyCode" class="form">
        <input
          v-model="userCode"
          type="text"
          placeholder="XXXX-XXXX"
          required
          :disabled="loading"
          pattern="[A-Z0-9]{4}-[A-Z0-9]{4}"
          maxlength="9"
        />
        <button type="submit" :disabled="loading" class="btn">
          {{ loading ? 'Verifying...' : 'Continue' }}
        </button>
      </form>

      <p v-if="error" class="error">{{ error }}</p>
    </div>

    <!-- Step 2: Choose provider -->
    <div v-else>
      <h1>Authorize Device</h1>
      <p>
        Sign in to complete activation for <strong>{{ loginContext.service_slug }}</strong> service
        in the <strong>{{ loginContext.org_slug }}</strong> organization.
      </p>

      <div v-if="providers.length > 0" class="provider-buttons">
        <button
          v-for="provider in providers"
          :key="provider"
          @click="handleLogin(provider)"
          class="provider-btn"
        >
          {{ formatProviderName(provider) }}
        </button>
      </div>

      <p v-else class="error">
        No login providers configured for this service. Please contact your administrator.
      </p>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue';
import { SsoClient } from '@drmhse/sso-sdk';

const API_URL = 'http://localhost:3000';
const sso = new SsoClient({ baseURL: API_URL });

const userCode = ref('');
const loading = ref(false);
const error = ref('');
const loginContext = ref(null);
const providers = ref([]);

const verifyCode = async () => {
  loading.value = true;
  error.value = '';

  try {
    const context = await sso.auth.deviceCode.verify(userCode.value);
    loginContext.value = context;
    providers.value = context.available_providers || [];
  } catch (err) {
    error.value = err.message || 'Invalid or expired code. Please try again.';
  } finally {
    loading.value = false;
  }
};

const handleLogin = (provider) => {
  // Use the end-user BYOO login flow (not admin flow)
  const loginUrl = sso.auth.getLoginUrl(provider, {
    org: loginContext.value.org_slug,
    service: loginContext.value.service_slug,
    user_code: userCode.value,
  });
  window.location.href = loginUrl;
};

const formatProviderName = (provider) => {
  return `Sign in with ${provider.charAt(0).toUpperCase() + provider.slice(1)}`;
};
</script>

<style scoped>
.container {
  max-width: 500px;
  margin: 50px auto;
  padding: 30px;
  border: 1px solid #ddd;
  border-radius: 8px;
  background: white;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
}

h1 {
  color: #333;
  margin-bottom: 10px;
  font-size: 24px;
}

p {
  color: #666;
  margin-bottom: 20px;
  line-height: 1.5;
}

.form {
  display: flex;
  flex-direction: column;
  gap: 15px;
  margin-top: 20px;
}

input {
  padding: 12px;
  font-size: 18px;
  border: 1px solid #ddd;
  border-radius: 5px;
  text-align: center;
  letter-spacing: 2px;
  text-transform: uppercase;
}

input:focus {
  outline: none;
  border-color: #007bff;
  box-shadow: 0 0 0 3px rgba(0, 123, 255, 0.1);
}

.btn {
  padding: 12px 24px;
  font-size: 16px;
  background: #007bff;
  color: white;
  border: none;
  border-radius: 5px;
  cursor: pointer;
  transition: background 0.2s;
}

.btn:hover:not(:disabled) {
  background: #0056b3;
}

.btn:disabled {
  background: #ccc;
  cursor: not-allowed;
}

.provider-buttons {
  display: flex;
  flex-direction: column;
  gap: 12px;
  margin-top: 20px;
}

.provider-btn {
  padding: 15px 20px;
  font-size: 16px;
  background: white;
  color: #333;
  border: 2px solid #007bff;
  border-radius: 5px;
  cursor: pointer;
  transition: all 0.2s;
}

.provider-btn:hover {
  background: #007bff;
  color: white;
}

.loading {
  text-align: center;
  padding: 20px;
  color: #666;
  font-style: italic;
}

.error {
  color: #d32f2f;
  margin-top: 15px;
  padding: 12px;
  background: #ffebee;
  border-radius: 5px;
  border-left: 4px solid #d32f2f;
}

strong {
  color: #007bff;
}
</style>
