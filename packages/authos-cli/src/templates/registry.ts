import type { Framework, StylingVariant } from '../utils';

export interface Template {
  name: string;
  description: string;
  files: TemplateFile[];
}

export interface TemplateFile {
  name: string;
  // Content nested by variant -> framework
  content: Record<StylingVariant, Record<Framework, string>>;
  // Extra files for variants that need them (e.g., .module.css)
  extraFiles?: Partial<Record<StylingVariant, { name: string; content: string }[]>>;
}

/**
 * Login form component template
 */
const loginFormReact = `"use client";

import { useState } from "react";
import { useAuthOS } from "@drmhse/authos-react";
import { AuthErrorCodes } from "@drmhse/sso-sdk";

interface LoginFormProps {
  onSuccess?: () => void;
  redirectTo?: string;
}

export function LoginForm({ onSuccess, redirectTo }: LoginFormProps) {
  const { client } = useAuthOS();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [mfaRequired, setMfaRequired] = useState(false);
  const [mfaCode, setMfaCode] = useState("");
  const [mfaToken, setMfaToken] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const response = await client.auth.login({ email, password });

      if (response.mfa_required) {
        setMfaRequired(true);
        setMfaToken(response.mfa_token || null);
      } else {
        onSuccess?.();
        if (redirectTo) {
          window.location.href = redirectTo;
        }
      }
    } catch (err: unknown) {
      if (err && typeof err === "object" && "errorCode" in err) {
        const apiError = err as { errorCode: string; message: string };
        if (apiError.errorCode === AuthErrorCodes.MFA_REQUIRED) {
          setMfaRequired(true);
        } else {
          setError(apiError.message || "Login failed");
        }
      } else {
        setError("An unexpected error occurred");
      }
    } finally {
      setLoading(false);
    }
  };

  const handleMfaSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      await client.auth.verifyMfa({ code: mfaCode, mfa_token: mfaToken! });
      onSuccess?.();
      if (redirectTo) {
        window.location.href = redirectTo;
      }
    } catch (err: unknown) {
      if (err && typeof err === "object" && "message" in err) {
        setError((err as { message: string }).message || "Invalid MFA code");
      } else {
        setError("Invalid MFA code");
      }
    } finally {
      setLoading(false);
    }
  };

  if (mfaRequired) {
    return (
      <form onSubmit={handleMfaSubmit} className="space-y-4 w-full max-w-sm">
        <div className="text-center mb-6">
          <h2 className="text-xl font-semibold">Two-Factor Authentication</h2>
          <p className="text-gray-600 text-sm mt-1">
            Enter the code from your authenticator app
          </p>
        </div>

        {error && (
          <div className="bg-red-50 text-red-600 px-4 py-2 rounded-md text-sm">
            {error}
          </div>
        )}

        <div>
          <label htmlFor="mfa-code" className="block text-sm font-medium mb-1">
            Verification Code
          </label>
          <input
            id="mfa-code"
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            value={mfaCode}
            onChange={(e) => setMfaCode(e.target.value)}
            className="w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            placeholder="000000"
            maxLength={6}
            required
          />
        </div>

        <button
          type="submit"
          disabled={loading}
          className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? "Verifying..." : "Verify"}
        </button>

        <button
          type="button"
          onClick={() => setMfaRequired(false)}
          className="w-full text-gray-600 text-sm hover:underline"
        >
          Back to login
        </button>
      </form>
    );
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4 w-full max-w-sm">
      <div className="text-center mb-6">
        <h2 className="text-xl font-semibold">Sign In</h2>
        <p className="text-gray-600 text-sm mt-1">
          Enter your credentials to continue
        </p>
      </div>

      {error && (
        <div className="bg-red-50 text-red-600 px-4 py-2 rounded-md text-sm">
          {error}
        </div>
      )}

      <div>
        <label htmlFor="email" className="block text-sm font-medium mb-1">
          Email
        </label>
        <input
          id="email"
          type="email"
          autoComplete="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          placeholder="you@example.com"
          required
        />
      </div>

      <div>
        <label htmlFor="password" className="block text-sm font-medium mb-1">
          Password
        </label>
        <input
          id="password"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          placeholder="Your password"
          required
        />
      </div>

      <button
        type="submit"
        disabled={loading}
        className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {loading ? "Signing in..." : "Sign In"}
      </button>
    </form>
  );
}
`;

const loginFormVue = `<script setup lang="ts">
import { ref } from "vue";
import { useAuthOS } from "@drmhse/authos-vue";
import { AuthErrorCodes } from "@drmhse/sso-sdk";

interface Props {
  redirectTo?: string;
}

const props = defineProps<Props>();
const emit = defineEmits<{
  success: [];
}>();

const { client } = useAuthOS();

const email = ref("");
const password = ref("");
const error = ref<string | null>(null);
const loading = ref(false);
const mfaRequired = ref(false);
const mfaCode = ref("");
const mfaToken = ref<string | null>(null);

async function handleSubmit() {
  error.value = null;
  loading.value = true;

  try {
    const response = await client.auth.login({
      email: email.value,
      password: password.value,
    });

    if (response.mfa_required) {
      mfaRequired.value = true;
      mfaToken.value = response.mfa_token || null;
    } else {
      emit("success");
      if (props.redirectTo) {
        window.location.href = props.redirectTo;
      }
    }
  } catch (err: unknown) {
    if (err && typeof err === "object" && "errorCode" in err) {
      const apiError = err as { errorCode: string; message: string };
      if (apiError.errorCode === AuthErrorCodes.MFA_REQUIRED) {
        mfaRequired.value = true;
      } else {
        error.value = apiError.message || "Login failed";
      }
    } else {
      error.value = "An unexpected error occurred";
    }
  } finally {
    loading.value = false;
  }
}

async function handleMfaSubmit() {
  error.value = null;
  loading.value = true;

  try {
    await client.auth.verifyMfa({
      code: mfaCode.value,
      mfa_token: mfaToken.value!,
    });
    emit("success");
    if (props.redirectTo) {
      window.location.href = props.redirectTo;
    }
  } catch (err: unknown) {
    if (err && typeof err === "object" && "message" in err) {
      error.value = (err as { message: string }).message || "Invalid MFA code";
    } else {
      error.value = "Invalid MFA code";
    }
  } finally {
    loading.value = false;
  }
}

function backToLogin() {
  mfaRequired.value = false;
  mfaCode.value = "";
  error.value = null;
}
</script>

<template>
  <form
    v-if="mfaRequired"
    @submit.prevent="handleMfaSubmit"
    class="space-y-4 w-full max-w-sm"
  >
    <div class="text-center mb-6">
      <h2 class="text-xl font-semibold">Two-Factor Authentication</h2>
      <p class="text-gray-600 text-sm mt-1">
        Enter the code from your authenticator app
      </p>
    </div>

    <div
      v-if="error"
      class="bg-red-50 text-red-600 px-4 py-2 rounded-md text-sm"
    >
      {{ error }}
    </div>

    <div>
      <label for="mfa-code" class="block text-sm font-medium mb-1">
        Verification Code
      </label>
      <input
        id="mfa-code"
        v-model="mfaCode"
        type="text"
        inputmode="numeric"
        autocomplete="one-time-code"
        class="w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
        placeholder="000000"
        maxlength="6"
        required
      />
    </div>

    <button
      type="submit"
      :disabled="loading"
      class="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
    >
      {{ loading ? "Verifying..." : "Verify" }}
    </button>

    <button
      type="button"
      @click="backToLogin"
      class="w-full text-gray-600 text-sm hover:underline"
    >
      Back to login
    </button>
  </form>

  <form v-else @submit.prevent="handleSubmit" class="space-y-4 w-full max-w-sm">
    <div class="text-center mb-6">
      <h2 class="text-xl font-semibold">Sign In</h2>
      <p class="text-gray-600 text-sm mt-1">
        Enter your credentials to continue
      </p>
    </div>

    <div
      v-if="error"
      class="bg-red-50 text-red-600 px-4 py-2 rounded-md text-sm"
    >
      {{ error }}
    </div>

    <div>
      <label for="email" class="block text-sm font-medium mb-1"> Email </label>
      <input
        id="email"
        v-model="email"
        type="email"
        autocomplete="email"
        class="w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
        placeholder="you@example.com"
        required
      />
    </div>

    <div>
      <label for="password" class="block text-sm font-medium mb-1">
        Password
      </label>
      <input
        id="password"
        v-model="password"
        type="password"
        autocomplete="current-password"
        class="w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
        placeholder="Your password"
        required
      />
    </div>

    <button
      type="submit"
      :disabled="loading"
      class="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
    >
      {{ loading ? "Signing in..." : "Sign In" }}
    </button>
  </form>
</template>
`;

/**
 * Organization switcher component template
 */
const orgSwitcherReact = `"use client";

import { useState, useRef, useEffect } from "react";
import { useOrganization, useUser } from "@drmhse/authos-react";

export function OrganizationSwitcher() {
  const { organization, organizations, switchOrganization, loading } = useOrganization();
  const { user } = useUser();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (ref.current && !ref.current.contains(event.target as Node)) {
        setOpen(false);
      }
    }

    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  if (!user || organizations.length === 0) {
    return null;
  }

  const handleSwitch = async (slug: string) => {
    await switchOrganization(slug);
    setOpen(false);
  };

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen(!open)}
        disabled={loading}
        className="flex items-center gap-2 px-3 py-2 text-sm border rounded-md hover:bg-gray-50 disabled:opacity-50"
      >
        <span className="font-medium">
          {organization?.name || "Select Organization"}
        </span>
        <svg
          className={\`w-4 h-4 transition-transform \${open ? "rotate-180" : ""}\`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M19 9l-7 7-7-7"
          />
        </svg>
      </button>

      {open && (
        <div className="absolute right-0 mt-2 w-56 bg-white border rounded-md shadow-lg z-50">
          <div className="py-1">
            {organizations.map((org) => (
              <button
                key={org.slug}
                onClick={() => handleSwitch(org.slug)}
                className={\`w-full text-left px-4 py-2 text-sm hover:bg-gray-100 flex items-center justify-between \${
                  org.slug === organization?.slug ? "bg-blue-50" : ""
                }\`}
              >
                <span>{org.name}</span>
                {org.slug === organization?.slug && (
                  <svg
                    className="w-4 h-4 text-blue-600"
                    fill="currentColor"
                    viewBox="0 0 20 20"
                  >
                    <path
                      fillRule="evenodd"
                      d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
                      clipRule="evenodd"
                    />
                  </svg>
                )}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
`;

const orgSwitcherVue = `<script setup lang="ts">
import { ref, onMounted, onUnmounted } from "vue";
import { useOrganization, useUser } from "@drmhse/authos-vue";

const { organization, organizations, switchOrganization, loading } = useOrganization();
const { user } = useUser();

const open = ref(false);
const dropdownRef = ref<HTMLDivElement | null>(null);

function handleClickOutside(event: MouseEvent) {
  if (dropdownRef.value && !dropdownRef.value.contains(event.target as Node)) {
    open.value = false;
  }
}

onMounted(() => {
  document.addEventListener("mousedown", handleClickOutside);
});

onUnmounted(() => {
  document.removeEventListener("mousedown", handleClickOutside);
});

async function handleSwitch(slug: string) {
  await switchOrganization(slug);
  open.value = false;
}
</script>

<template>
  <div v-if="user && organizations.length > 0" ref="dropdownRef" class="relative">
    <button
      @click="open = !open"
      :disabled="loading"
      class="flex items-center gap-2 px-3 py-2 text-sm border rounded-md hover:bg-gray-50 disabled:opacity-50"
    >
      <span class="font-medium">
        {{ organization?.name || "Select Organization" }}
      </span>
      <svg
        :class="['w-4 h-4 transition-transform', open ? 'rotate-180' : '']"
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
      >
        <path
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="2"
          d="M19 9l-7 7-7-7"
        />
      </svg>
    </button>

    <div
      v-if="open"
      class="absolute right-0 mt-2 w-56 bg-white border rounded-md shadow-lg z-50"
    >
      <div class="py-1">
        <button
          v-for="org in organizations"
          :key="org.slug"
          @click="handleSwitch(org.slug)"
          :class="[
            'w-full text-left px-4 py-2 text-sm hover:bg-gray-100 flex items-center justify-between',
            org.slug === organization?.slug ? 'bg-blue-50' : '',
          ]"
        >
          <span>{{ org.name }}</span>
          <svg
            v-if="org.slug === organization?.slug"
            class="w-4 h-4 text-blue-600"
            fill="currentColor"
            viewBox="0 0 20 20"
          >
            <path
              fill-rule="evenodd"
              d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
              clip-rule="evenodd"
            />
          </svg>
        </button>
      </div>
    </div>
  </div>
</template>
`;

/**
 * User profile/button component template
 */
const userProfileReact = `"use client";

import { useState, useRef, useEffect } from "react";
import { useUser, useAuthOS } from "@drmhse/authos-react";

interface UserProfileProps {
  onSignOut?: () => void;
}

export function UserProfile({ onSignOut }: UserProfileProps) {
  const { user } = useUser();
  const { client } = useAuthOS();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (ref.current && !ref.current.contains(event.target as Node)) {
        setOpen(false);
      }
    }

    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  if (!user) {
    return null;
  }

  const handleSignOut = async () => {
    await client.auth.logout();
    onSignOut?.();
    setOpen(false);
  };

  const initials = user.name
    ? user.name
        .split(" ")
        .map((n) => n[0])
        .join("")
        .toUpperCase()
        .slice(0, 2)
    : user.email[0].toUpperCase();

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-2 p-1 rounded-full hover:bg-gray-100"
      >
        {user.avatar_url ? (
          <img
            src={user.avatar_url}
            alt={user.name || user.email}
            className="w-8 h-8 rounded-full object-cover"
          />
        ) : (
          <div className="w-8 h-8 rounded-full bg-blue-600 text-white flex items-center justify-center text-sm font-medium">
            {initials}
          </div>
        )}
      </button>

      {open && (
        <div className="absolute right-0 mt-2 w-64 bg-white border rounded-md shadow-lg z-50">
          <div className="p-4 border-b">
            <div className="font-medium">{user.name || "User"}</div>
            <div className="text-sm text-gray-600">{user.email}</div>
          </div>
          <div className="py-1">
            <button
              onClick={handleSignOut}
              className="w-full text-left px-4 py-2 text-sm text-red-600 hover:bg-red-50"
            >
              Sign out
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
`;

const userProfileVue = `<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from "vue";
import { useUser, useAuthOS } from "@drmhse/authos-vue";

const emit = defineEmits<{
  signOut: [];
}>();

const { user } = useUser();
const { client } = useAuthOS();

const open = ref(false);
const dropdownRef = ref<HTMLDivElement | null>(null);

const initials = computed(() => {
  if (!user.value) return "";
  if (user.value.name) {
    return user.value.name
      .split(" ")
      .map((n) => n[0])
      .join("")
      .toUpperCase()
      .slice(0, 2);
  }
  return user.value.email[0].toUpperCase();
});

function handleClickOutside(event: MouseEvent) {
  if (dropdownRef.value && !dropdownRef.value.contains(event.target as Node)) {
    open.value = false;
  }
}

onMounted(() => {
  document.addEventListener("mousedown", handleClickOutside);
});

onUnmounted(() => {
  document.removeEventListener("mousedown", handleClickOutside);
});

async function handleSignOut() {
  await client.auth.logout();
  emit("signOut");
  open.value = false;
}
</script>

<template>
  <div v-if="user" ref="dropdownRef" class="relative">
    <button
      @click="open = !open"
      class="flex items-center gap-2 p-1 rounded-full hover:bg-gray-100"
    >
      <img
        v-if="user.avatar_url"
        :src="user.avatar_url"
        :alt="user.name || user.email"
        class="w-8 h-8 rounded-full object-cover"
      />
      <div
        v-else
        class="w-8 h-8 rounded-full bg-blue-600 text-white flex items-center justify-center text-sm font-medium"
      >
        {{ initials }}
      </div>
    </button>

    <div
      v-if="open"
      class="absolute right-0 mt-2 w-64 bg-white border rounded-md shadow-lg z-50"
    >
      <div class="p-4 border-b">
        <div class="font-medium">{{ user.name || "User" }}</div>
        <div class="text-sm text-gray-600">{{ user.email }}</div>
      </div>
      <div class="py-1">
        <button
          @click="handleSignOut"
          class="w-full text-left px-4 py-2 text-sm text-red-600 hover:bg-red-50"
        >
          Sign out
        </button>
      </div>
    </div>
  </div>
</template>
`;

// =============================================================================
// CSS MODULES VARIANTS
// =============================================================================

const loginFormReactCssModules = `"use client";

import { useState } from "react";
import { useAuthOS } from "@drmhse/authos-react";
import { AuthErrorCodes } from "@drmhse/sso-sdk";
import styles from "./LoginForm.module.css";

interface LoginFormProps {
  onSuccess?: () => void;
  redirectTo?: string;
}

export function LoginForm({ onSuccess, redirectTo }: LoginFormProps) {
  const { client } = useAuthOS();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [mfaRequired, setMfaRequired] = useState(false);
  const [mfaCode, setMfaCode] = useState("");
  const [mfaToken, setMfaToken] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const response = await client.auth.login({ email, password });

      if (response.mfa_required) {
        setMfaRequired(true);
        setMfaToken(response.mfa_token || null);
      } else {
        onSuccess?.();
        if (redirectTo) {
          window.location.href = redirectTo;
        }
      }
    } catch (err: unknown) {
      if (err && typeof err === "object" && "errorCode" in err) {
        const apiError = err as { errorCode: string; message: string };
        if (apiError.errorCode === AuthErrorCodes.MFA_REQUIRED) {
          setMfaRequired(true);
        } else {
          setError(apiError.message || "Login failed");
        }
      } else {
        setError("An unexpected error occurred");
      }
    } finally {
      setLoading(false);
    }
  };

  const handleMfaSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      await client.auth.verifyMfa({ code: mfaCode, mfa_token: mfaToken! });
      onSuccess?.();
      if (redirectTo) {
        window.location.href = redirectTo;
      }
    } catch (err: unknown) {
      if (err && typeof err === "object" && "message" in err) {
        setError((err as { message: string }).message || "Invalid MFA code");
      } else {
        setError("Invalid MFA code");
      }
    } finally {
      setLoading(false);
    }
  };

  if (mfaRequired) {
    return (
      <form onSubmit={handleMfaSubmit} className={styles.form}>
        <div className={styles.header}>
          <h2 className={styles.title}>Two-Factor Authentication</h2>
          <p className={styles.subtitle}>Enter the code from your authenticator app</p>
        </div>

        {error && <div className={styles.error}>{error}</div>}

        <div className={styles.field}>
          <label htmlFor="mfa-code" className={styles.label}>Verification Code</label>
          <input
            id="mfa-code"
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            value={mfaCode}
            onChange={(e) => setMfaCode(e.target.value)}
            className={styles.input}
            placeholder="000000"
            maxLength={6}
            required
          />
        </div>

        <button type="submit" disabled={loading} className={styles.button}>
          {loading ? "Verifying..." : "Verify"}
        </button>

        <button type="button" onClick={() => setMfaRequired(false)} className={styles.link}>
          Back to login
        </button>
      </form>
    );
  }

  return (
    <form onSubmit={handleSubmit} className={styles.form}>
      <div className={styles.header}>
        <h2 className={styles.title}>Sign In</h2>
        <p className={styles.subtitle}>Enter your credentials to continue</p>
      </div>

      {error && <div className={styles.error}>{error}</div>}

      <div className={styles.field}>
        <label htmlFor="email" className={styles.label}>Email</label>
        <input
          id="email"
          type="email"
          autoComplete="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className={styles.input}
          placeholder="you@example.com"
          required
        />
      </div>

      <div className={styles.field}>
        <label htmlFor="password" className={styles.label}>Password</label>
        <input
          id="password"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className={styles.input}
          placeholder="Your password"
          required
        />
      </div>

      <button type="submit" disabled={loading} className={styles.button}>
        {loading ? "Signing in..." : "Sign In"}
      </button>
    </form>
  );
}
`;

const loginFormCssModulesStyles = `.form {
  display: flex;
  flex-direction: column;
  gap: 1rem;
  width: 100%;
  max-width: 24rem;
}

.header {
  text-align: center;
  margin-bottom: 1.5rem;
}

.title {
  font-size: 1.25rem;
  font-weight: 600;
  margin: 0;
}

.subtitle {
  color: #6b7280;
  font-size: 0.875rem;
  margin-top: 0.25rem;
}

.field {
  display: flex;
  flex-direction: column;
}

.label {
  font-size: 0.875rem;
  font-weight: 500;
  margin-bottom: 0.25rem;
}

.input {
  width: 100%;
  padding: 0.5rem 0.75rem;
  border: 1px solid #e2e8f0;
  border-radius: 0.375rem;
  font-size: 1rem;
}

.input:focus {
  outline: none;
  border-color: #3b82f6;
  box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
}

.button {
  width: 100%;
  padding: 0.5rem 1rem;
  background-color: #2563eb;
  color: white;
  border: none;
  border-radius: 0.375rem;
  font-weight: 500;
  cursor: pointer;
  font-size: 1rem;
}

.button:hover {
  background-color: #1d4ed8;
}

.button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.error {
  background-color: #fef2f2;
  color: #dc2626;
  padding: 0.5rem 1rem;
  border-radius: 0.375rem;
  font-size: 0.875rem;
}

.link {
  background: none;
  border: none;
  color: #6b7280;
  font-size: 0.875rem;
  cursor: pointer;
  text-align: center;
}

.link:hover {
  text-decoration: underline;
}
`;

const loginFormVueScoped = `<script setup lang="ts">
import { ref } from "vue";
import { useAuthOS } from "@drmhse/authos-vue";
import { AuthErrorCodes } from "@drmhse/sso-sdk";

interface Props {
  redirectTo?: string;
}

const props = defineProps<Props>();
const emit = defineEmits<{
  success: [];
}>();

const { client } = useAuthOS();

const email = ref("");
const password = ref("");
const error = ref<string | null>(null);
const loading = ref(false);
const mfaRequired = ref(false);
const mfaCode = ref("");
const mfaToken = ref<string | null>(null);

async function handleSubmit() {
  error.value = null;
  loading.value = true;

  try {
    const response = await client.auth.login({
      email: email.value,
      password: password.value,
    });

    if (response.mfa_required) {
      mfaRequired.value = true;
      mfaToken.value = response.mfa_token || null;
    } else {
      emit("success");
      if (props.redirectTo) {
        window.location.href = props.redirectTo;
      }
    }
  } catch (err: unknown) {
    if (err && typeof err === "object" && "errorCode" in err) {
      const apiError = err as { errorCode: string; message: string };
      if (apiError.errorCode === AuthErrorCodes.MFA_REQUIRED) {
        mfaRequired.value = true;
      } else {
        error.value = apiError.message || "Login failed";
      }
    } else {
      error.value = "An unexpected error occurred";
    }
  } finally {
    loading.value = false;
  }
}

async function handleMfaSubmit() {
  error.value = null;
  loading.value = true;

  try {
    await client.auth.verifyMfa({
      code: mfaCode.value,
      mfa_token: mfaToken.value!,
    });
    emit("success");
    if (props.redirectTo) {
      window.location.href = props.redirectTo;
    }
  } catch (err: unknown) {
    if (err && typeof err === "object" && "message" in err) {
      error.value = (err as { message: string }).message || "Invalid MFA code";
    } else {
      error.value = "Invalid MFA code";
    }
  } finally {
    loading.value = false;
  }
}

function backToLogin() {
  mfaRequired.value = false;
  mfaCode.value = "";
  error.value = null;
}
</script>

<template>
  <form v-if="mfaRequired" @submit.prevent="handleMfaSubmit" class="form">
    <div class="header">
      <h2 class="title">Two-Factor Authentication</h2>
      <p class="subtitle">Enter the code from your authenticator app</p>
    </div>

    <div v-if="error" class="error">{{ error }}</div>

    <div class="field">
      <label for="mfa-code" class="label">Verification Code</label>
      <input
        id="mfa-code"
        v-model="mfaCode"
        type="text"
        inputmode="numeric"
        autocomplete="one-time-code"
        class="input"
        placeholder="000000"
        maxlength="6"
        required
      />
    </div>

    <button type="submit" :disabled="loading" class="button">
      {{ loading ? "Verifying..." : "Verify" }}
    </button>

    <button type="button" @click="backToLogin" class="link">Back to login</button>
  </form>

  <form v-else @submit.prevent="handleSubmit" class="form">
    <div class="header">
      <h2 class="title">Sign In</h2>
      <p class="subtitle">Enter your credentials to continue</p>
    </div>

    <div v-if="error" class="error">{{ error }}</div>

    <div class="field">
      <label for="email" class="label">Email</label>
      <input
        id="email"
        v-model="email"
        type="email"
        autocomplete="email"
        class="input"
        placeholder="you@example.com"
        required
      />
    </div>

    <div class="field">
      <label for="password" class="label">Password</label>
      <input
        id="password"
        v-model="password"
        type="password"
        autocomplete="current-password"
        class="input"
        placeholder="Your password"
        required
      />
    </div>

    <button type="submit" :disabled="loading" class="button">
      {{ loading ? "Signing in..." : "Sign In" }}
    </button>
  </form>
</template>

<style scoped>
.form {
  display: flex;
  flex-direction: column;
  gap: 1rem;
  width: 100%;
  max-width: 24rem;
}

.header {
  text-align: center;
  margin-bottom: 1.5rem;
}

.title {
  font-size: 1.25rem;
  font-weight: 600;
  margin: 0;
}

.subtitle {
  color: #6b7280;
  font-size: 0.875rem;
  margin-top: 0.25rem;
}

.field {
  display: flex;
  flex-direction: column;
}

.label {
  font-size: 0.875rem;
  font-weight: 500;
  margin-bottom: 0.25rem;
}

.input {
  width: 100%;
  padding: 0.5rem 0.75rem;
  border: 1px solid #e2e8f0;
  border-radius: 0.375rem;
  font-size: 1rem;
}

.input:focus {
  outline: none;
  border-color: #3b82f6;
  box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
}

.button {
  width: 100%;
  padding: 0.5rem 1rem;
  background-color: #2563eb;
  color: white;
  border: none;
  border-radius: 0.375rem;
  font-weight: 500;
  cursor: pointer;
}

.button:hover {
  background-color: #1d4ed8;
}

.button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.error {
  background-color: #fef2f2;
  color: #dc2626;
  padding: 0.5rem 1rem;
  border-radius: 0.375rem;
  font-size: 0.875rem;
}

.link {
  background: none;
  border: none;
  color: #6b7280;
  font-size: 0.875rem;
  cursor: pointer;
  text-align: center;
}

.link:hover {
  text-decoration: underline;
}
</style>
`;

/**
 * Template registry
 */
export const templates: Record<string, Template> = {
  'login-form': {
    name: 'Login Form',
    description: 'A styled login form with email/password and MFA support',
    files: [
      {
        name: 'LoginForm',
        content: {
          tailwind: {
            react: loginFormReact,
            next: loginFormReact,
            vue: loginFormVue,
            nuxt: loginFormVue,
            unknown: loginFormReact,
          },
          'css-modules': {
            react: loginFormReactCssModules,
            next: loginFormReactCssModules,
            vue: loginFormVueScoped,
            nuxt: loginFormVueScoped,
            unknown: loginFormReactCssModules,
          },
          none: {
            react: loginFormReact,  // Fallback to tailwind for now
            next: loginFormReact,
            vue: loginFormVue,
            nuxt: loginFormVue,
            unknown: loginFormReact,
          },
        },
        extraFiles: {
          'css-modules': [
            { name: 'LoginForm.module.css', content: loginFormCssModulesStyles },
          ],
        },
      },
    ],
  },
  'org-switcher': {
    name: 'Organization Switcher',
    description: 'A dropdown component for switching between organizations',
    files: [
      {
        name: 'OrganizationSwitcher',
        content: {
          tailwind: {
            react: orgSwitcherReact,
            next: orgSwitcherReact,
            vue: orgSwitcherVue,
            nuxt: orgSwitcherVue,
            unknown: orgSwitcherReact,
          },
          'css-modules': {
            react: orgSwitcherReact,  // Will add CSS modules variant later
            next: orgSwitcherReact,
            vue: orgSwitcherVue,
            nuxt: orgSwitcherVue,
            unknown: orgSwitcherReact,
          },
          none: {
            react: orgSwitcherReact,
            next: orgSwitcherReact,
            vue: orgSwitcherVue,
            nuxt: orgSwitcherVue,
            unknown: orgSwitcherReact,
          },
        },
      },
    ],
  },
  'user-profile': {
    name: 'User Profile',
    description: 'A user avatar button with dropdown menu and sign out',
    files: [
      {
        name: 'UserProfile',
        content: {
          tailwind: {
            react: userProfileReact,
            next: userProfileReact,
            vue: userProfileVue,
            nuxt: userProfileVue,
            unknown: userProfileReact,
          },
          'css-modules': {
            react: userProfileReact,  // Will add CSS modules variant later
            next: userProfileReact,
            vue: userProfileVue,
            nuxt: userProfileVue,
            unknown: userProfileReact,
          },
          none: {
            react: userProfileReact,
            next: userProfileReact,
            vue: userProfileVue,
            nuxt: userProfileVue,
            unknown: userProfileReact,
          },
        },
      },
    ],
  },
};

/**
 * Get list of available template names
 */
export function getAvailableTemplates(): string[] {
  return Object.keys(templates);
}

/**
 * Get a template by name
 */
export function getTemplate(name: string): Template | null {
  return templates[name] || null;
}
