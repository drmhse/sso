<template>
  <component :is="layout">
    <router-view />
  </component>
</template>

<script setup>
import { computed } from 'vue';
import { useRoute } from 'vue-router';
import AppLayout from '@/layouts/AppLayout.vue';
import AuthLayout from '@/layouts/AuthLayout.vue';

const route = useRoute();

const layout = computed(() => {
  const layoutType = route.meta.layout;
  return layoutType === 'auth' ? AuthLayout : AppLayout;
});
</script>
