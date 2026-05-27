<template>
  <section class="workspace-card stack">
    <div class="users-toolbar">
      <div class="field users-toolbar__search">
        <label for="users-search" class="sr-only">Search users</label>
        <input
          id="users-search"
          :value="search"
          class="input input-lg"
          type="search"
          placeholder="Search users..."
          @input="$emit('update:search', $event.target.value)"
        />
      </div>

      <div v-if="serviceOptions.length > 1" class="field users-toolbar__filter">
        <label for="users-service-filter" class="sr-only">Filter by application</label>
        <select
          id="users-service-filter"
          :value="selectedServiceSlug"
          class="input"
          @change="$emit('update:selectedServiceSlug', $event.target.value)"
        >
          <option value="">All applications</option>
          <option v-for="service in serviceOptions" :key="service.slug" :value="service.slug">
            {{ service.name }}
          </option>
        </select>
      </div>
    </div>

    <div class="users-table">
      <div class="users-table__header">
        <span>Email</span>
        <span>Providers</span>
        <span>Subscriptions</span>
      </div>

      <button
        v-for="entry in users"
        :key="entry.user.id"
        type="button"
        class="users-table__row"
        :class="{ 'users-table__row--active': selectedUserId === entry.user.id }"
        @click="$emit('select', entry.user.id)"
      >
        <div class="users-table__cell users-table__cell--primary">
          <strong>{{ entry.user.email }}</strong>
          <span class="muted">Joined {{ formatDateTime(entry.user.created_at, 'Unknown') }}</span>
        </div>

        <div class="users-table__cell users-provider-chips">
          <span v-for="provider in providerNameList(entry.identities)" :key="provider" class="tag-chip">
            {{ provider }}
          </span>
        </div>

        <div class="users-table__cell users-table__cell--count">
          <span class="count-pill">{{ entry.subscriptions.length }}</span>
        </div>
      </button>
    </div>
  </section>
</template>

<script setup>
import { formatDateTime, providerNameList } from '@/utils/formatting';

defineProps({
  users: { type: Array, default: () => [] },
  search: { type: String, default: '' },
  selectedServiceSlug: { type: String, default: '' },
  selectedUserId: { type: String, default: '' },
  serviceOptions: { type: Array, default: () => [] },
});

defineEmits(['update:search', 'update:selectedServiceSlug', 'select']);
</script>
