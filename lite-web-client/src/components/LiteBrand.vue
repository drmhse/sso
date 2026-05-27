<template>
  <div class="lite-brand" :class="[`lite-brand--${size}`, { 'lite-brand--compact': compact }]">
    <div class="lite-brand__badge" aria-hidden="true">
      <svg viewBox="990 496 80 90" class="lite-brand__mark" xmlns="http://www.w3.org/2000/svg">
        <path
          d="M1008,518L1008,505C1016.567,482.323 1046.231,483.053 1052,507L1052,518L1044,518L1044,509C1038.257,493.154 1018.945,495.034 1016,509L1016,518L1008,518"
          fill="currentColor"
        />
        <path
          d="M1066,566L1066,573.824C1066,578.337 1062.337,582 1057.824,582L1051,582L1051,566L1066,566Z"
          fill="currentColor"
        />
        <path
          d="M1008,582L1002.176,582C997.663,582 994,578.337 994,573.824L994,566L1008,566L1008,582Z"
          fill="currentColor"
        />
        <path
          d="M994,536L994,529.176C994,524.663 997.663,521 1002.176,521L1008,521L1008,536L994,536Z"
          fill="currentColor"
        />
        <rect x="994" y="540" width="14" height="22" fill="currentColor" />
        <path
          d="M1012,521L1028,521L1028,534L1032,534L1032,521L1047,521L1047,536L1041,536L1041,540L1047,540L1047,562L1041,562L1041,566L1047,566L1047,582L1032,582L1032,569L1028,569L1028,582L1012,582L1012,566L1019,566L1019,562L1012,562L1012,540L1019,540L1019,536L1012,536L1012,521ZM1026.602,551.12C1024.454,549.925 1023,547.631 1023,545C1023,541.137 1026.137,538 1030,538C1033.863,538 1037,541.137 1037,545C1037,547.694 1035.475,550.035 1033.241,551.205L1036,565L1024,565L1026.602,551.12Z"
          fill="currentColor"
        />
        <path
          d="M1051,521L1057.824,521C1062.337,521 1066,524.663 1066,529.176L1066,536L1051,536L1051,521Z"
          fill="currentColor"
        />
        <rect x="1051" y="540" width="15" height="22" fill="currentColor" />
      </svg>
    </div>

    <div v-if="!compact" class="lite-brand__copy">
      <div class="lite-brand__title">{{ title }}</div>
      <div v-if="tagline" class="lite-brand__tagline">{{ tagline }}</div>
    </div>
  </div>
</template>

<script setup>
defineProps({
  title: { type: String, default: 'AuthOS Lite' },
  tagline: { type: String, default: 'Secure access management gateway' },
  size: { type: String, default: 'lg' },
  compact: { type: Boolean, default: false },
});
</script>
