<template>
  <aside class="workspace-sidebar" :class="{ 'workspace-sidebar--open': mobileOpen }">
    <div class="workspace-sidebar__brand">
      <div class="workspace-sidebar__brand-lockup">
        <LiteBrand compact size="sm" />
        <div class="workspace-sidebar__brand-copy">
          <div class="workspace-sidebar__brand-title">AuthOS Lite</div>
        </div>
      </div>

      <button type="button" class="icon-button workspace-sidebar__close" aria-label="Close navigation" @click="$emit('close')">
        <X class="icon-button__icon" />
      </button>
    </div>

    <div class="workspace-sidebar__section-label">Workspace</div>

    <nav class="workspace-nav">
      <RouterLink
        v-for="item in navItems"
        :key="item.to"
        :to="item.to"
        class="workspace-nav__link"
        active-class="workspace-nav__link--active"
        @click="$emit('close')"
      >
        <component :is="item.icon" class="workspace-nav__icon" />
        <span>{{ item.label }}</span>
      </RouterLink>
    </nav>

    <div class="workspace-sidebar__spacer"></div>

    <button
      v-if="fullClientUrl"
      type="button"
      class="workspace-sidebar__secondary-link"
      @click="handleOpenFullClient"
    >
      <ExternalLink class="workspace-sidebar__secondary-icon" />
      Open full client
    </button>

    <div class="workspace-sidebar__footer">
      <div class="workspace-sidebar__user">
        <div class="workspace-sidebar__avatar">{{ userInitial }}</div>
        <div class="workspace-sidebar__user-copy">
          <div class="workspace-sidebar__user-email">{{ userEmail || 'AuthOS user' }}</div>
          <div class="workspace-sidebar__user-role">{{ userRole || 'Member' }}</div>
        </div>
      </div>

      <button type="button" class="workspace-signout" @click="handleLogout">
        <LogOut class="workspace-signout__icon" />
        Sign Out
      </button>
    </div>
  </aside>
</template>

<script setup>
import { computed } from 'vue';
import { RouterLink } from 'vue-router';
import {
  AppWindow,
  Building2,
  ExternalLink,
  LayoutDashboard,
  LogOut,
  Settings,
  ShieldCheck,
  Users,
  X,
} from '@lucide/vue';
import LiteBrand from '@/components/LiteBrand.vue';

const props = defineProps({
  showSetup: { type: Boolean, default: false },
  userEmail: { type: String, default: '' },
  userRole: { type: String, default: '' },
  fullClientUrl: { type: String, default: '' },
  mobileOpen: { type: Boolean, default: false },
});

const emit = defineEmits(['logout', 'open-full-client', 'close']);

const navItems = computed(() => {
  const items = [
    { to: '/app/overview', label: 'Overview', icon: LayoutDashboard },
    { to: '/app/applications', label: 'Applications', icon: AppWindow },
    { to: '/app/users', label: 'Users', icon: Users },
    { to: '/app/organization', label: 'Organization', icon: Building2 },
    { to: '/app/account-security', label: 'Account Security', icon: ShieldCheck },
  ];

  if (props.showSetup) {
    items.push({ to: '/app/platform-setup', label: 'Platform Setup', icon: Settings });
  }

  return items;
});

const userInitial = computed(() => (props.userEmail || 'A').trim().charAt(0).toUpperCase());

function handleOpenFullClient() {
  emit('close');
  emit('open-full-client');
}

function handleLogout() {
  emit('close');
  emit('logout');
}
</script>
