<template>
  <section class="workspace-card stack">
    <div class="section-header">
      <div>
        <h2 class="section-title">Immutable Details</h2>
        <p class="section-copy">Reference values used when integrating your client app.</p>
      </div>
    </div>

    <div class="detail-list">
      <div class="detail-list__row">
        <span class="detail-list__label">Client ID</span>
        <strong class="detail-list__value code">{{ service?.client_id || 'Unavailable' }}</strong>
      </div>
      <div class="detail-list__row">
        <span class="detail-list__label">Application Type</span>
        <strong class="detail-list__value">{{ service?.service_type || 'Unknown' }}</strong>
      </div>
      <div class="detail-list__row">
        <span class="detail-list__label">Internal Slug</span>
        <strong class="detail-list__value code">{{ service?.slug || 'Unavailable' }}</strong>
      </div>
    </div>
  </section>
</template>

<script setup>
defineProps({
  service: { type: Object, default: null },
});
</script>
