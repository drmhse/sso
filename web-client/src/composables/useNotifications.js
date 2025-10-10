import { ref } from 'vue';

const notifications = ref([]);
let nextId = 0;

/**
 * Composable for managing toast-style notifications.
 * Provides methods to show success, error, warning, and info messages.
 */
export function useNotifications() {
  const addNotification = (type, title, message, duration = 5000) => {
    const id = nextId++;
    const notification = { id, type, title, message };

    notifications.value.push(notification);

    if (duration > 0) {
      setTimeout(() => {
        removeNotification(id);
      }, duration);
    }

    return id;
  };

  const removeNotification = (id) => {
    const index = notifications.value.findIndex(n => n.id === id);
    if (index > -1) {
      notifications.value.splice(index, 1);
    }
  };

  const success = (title, message, duration) => {
    return addNotification('success', title, message, duration);
  };

  const error = (title, message, duration) => {
    return addNotification('error', title, message, duration);
  };

  const warning = (title, message, duration) => {
    return addNotification('warning', title, message, duration);
  };

  const info = (title, message, duration) => {
    return addNotification('info', title, message, duration);
  };

  const clear = () => {
    notifications.value = [];
  };

  return {
    notifications,
    addNotification,
    removeNotification,
    success,
    error,
    warning,
    info,
    clear,
  };
}
