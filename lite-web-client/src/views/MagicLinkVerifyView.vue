<template>
  <AuthShell title="Verifying your sign-in link" description="We’re checking your AuthOS magic link.">
    <AuthStatusPanel
      :status="status"
      loading-text="Checking your magic link..."
      success-text="Signed in. Redirecting..."
      :error-text="errorMessage"
    />
  </AuthShell>
</template>

<script setup>
import { onMounted, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import AuthShell from '@/components/AuthShell.vue';
import AuthStatusPanel from '@/features/auth/components/AuthStatusPanel.vue';
import { sso } from '@/lib/api';
import { useAuthStore } from '@/stores/auth';
import { useAuthFlowStore } from '@/stores/authFlow';
import {
  appendTokensToRedirectUri,
  authRouteWithContext,
  firstQueryValue,
  getAuthFlowContext,
} from '@/utils/authFlowContext';
import { postLoginRedirect } from '@/utils/redirects';
import { scrubCurrentUrl } from '@/utils/urlSecurity';

const route = useRoute();
const router = useRouter();
const authStore = useAuthStore();
const authFlowStore = useAuthFlowStore();

const status = ref('loading');
const errorMessage = ref('');
const token = firstQueryValue(route.query.token);
const authContext = getAuthFlowContext(route);
const redirectUri = authContext.isServiceFlow ? authContext.redirectUri : '';

onMounted(async () => {
  if (!token) {
    status.value = 'error';
    errorMessage.value = 'This sign-in link is missing its verification token.';
    return;
  }

  scrubCurrentUrl({ queryKeys: ['token'] });

  try {
    const response = await sso.magicLinks.verify(token, redirectUri || undefined);

    if (response?.requires_mfa && response?.preauth_token) {
      authFlowStore.setMfaChallenge({
        preauthToken: response.preauth_token,
        redirectUri,
        redirectPath: postLoginRedirect(route),
        supportPath: authRouteWithContext(route, '/support'),
      });
      await router.replace('/mfa-challenge');
      return;
    }

    if (!response?.access_token || !response?.refresh_token) {
      throw new Error('The sign-in link response was incomplete.');
    }

    await authStore.handleLoginCallback(response.access_token, response.refresh_token);
    status.value = 'success';

    if (redirectUri) {
      window.location.href = appendTokensToRedirectUri(redirectUri, response.access_token, response.refresh_token);
      return;
    }

    router.push(postLoginRedirect(route));
  } catch (error) {
    status.value = 'error';
    errorMessage.value = error.message || 'This sign-in link is invalid or expired.';
  }
});
</script>
