<template>
  <TransitionRoot appear :show="isOpen" as="template">
    <Dialog as="div" @close="handleClose" class="relative z-50">
      <TransitionChild
        as="template"
        enter="duration-300 ease-out"
        enter-from="opacity-0"
        enter-to="opacity-100"
        leave="duration-200 ease-in"
        leave-from="opacity-100"
        leave-to="opacity-0"
      >
        <div class="fixed inset-0 bg-black bg-opacity-25" />
      </TransitionChild>

      <div class="fixed inset-0 overflow-y-auto">
        <div class="flex min-h-full items-center justify-center p-4 text-center">
          <TransitionChild
            as="template"
            enter="duration-300 ease-out"
            enter-from="opacity-0 scale-95"
            enter-to="opacity-100 scale-100"
            leave="duration-200 ease-in"
            leave-from="opacity-100 scale-100"
            leave-to="opacity-0 scale-95"
          >
            <DialogPanel
              class="w-full transform overflow-hidden rounded-2xl bg-white p-6 text-left align-middle shadow-xl transition-all"
              :class="sizeClass"
            >
              <DialogTitle
                v-if="title"
                as="h3"
                class="text-lg font-medium leading-6 text-gray-900"
              >
                {{ title }}
              </DialogTitle>

              <div class="mt-2">
                <slot />
              </div>

              <div v-if="showActions" class="mt-4 flex justify-end space-x-2">
                <slot name="actions">
                  <button
                    v-if="showCancel"
                    type="button"
                    class="inline-flex justify-center rounded-md border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
                    @click="handleClose"
                  >
                    {{ cancelText }}
                  </button>
                  <button
                    v-if="showConfirm"
                    type="button"
                    class="inline-flex justify-center rounded-md border border-transparent bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
                    :class="confirmClass"
                    @click="$emit('confirm')"
                  >
                    {{ confirmText }}
                  </button>
                </slot>
              </div>
            </DialogPanel>
          </TransitionChild>
        </div>
      </div>
    </Dialog>
  </TransitionRoot>
</template>

<script setup>
import { computed } from 'vue';
import {
  Dialog,
  DialogPanel,
  DialogTitle,
  TransitionRoot,
  TransitionChild,
} from '@headlessui/vue';

const props = defineProps({
  isOpen: {
    type: Boolean,
    required: true,
  },
  title: {
    type: String,
    default: '',
  },
  size: {
    type: String,
    default: 'md',
    validator: (value) => ['sm', 'md', 'lg', 'xl'].includes(value),
  },
  showActions: {
    type: Boolean,
    default: true,
  },
  showCancel: {
    type: Boolean,
    default: true,
  },
  showConfirm: {
    type: Boolean,
    default: true,
  },
  cancelText: {
    type: String,
    default: 'Cancel',
  },
  confirmText: {
    type: String,
    default: 'Confirm',
  },
  confirmVariant: {
    type: String,
    default: 'primary',
    validator: (value) => ['primary', 'danger', 'success'].includes(value),
  },
});

const emit = defineEmits(['close', 'confirm']);

const sizeClass = computed(() => {
  const sizes = {
    sm: 'max-w-sm',
    md: 'max-w-md',
    lg: 'max-w-lg',
    xl: 'max-w-xl',
  };
  return sizes[props.size];
});

const confirmClass = computed(() => {
  const variants = {
    primary: 'bg-blue-600 hover:bg-blue-700',
    danger: 'bg-red-600 hover:bg-red-700',
    success: 'bg-green-600 hover:bg-green-700',
  };
  return variants[props.confirmVariant];
});

const handleClose = () => {
  emit('close');
};
</script>
