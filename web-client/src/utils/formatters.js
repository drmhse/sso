/**
 * Formats a date string to a localized date.
 * @param {string} dateString - ISO date string
 * @returns {string} Formatted date
 */
export function formatDate(dateString) {
  if (!dateString) return '';
  const date = new Date(dateString);
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

/**
 * Formats a date string to a localized date and time.
 * @param {string} dateString - ISO date string
 * @returns {string} Formatted date and time
 */
export function formatDateTime(dateString) {
  if (!dateString) return '';
  const date = new Date(dateString);
  return date.toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  });
}

/**
 * Capitalizes the first letter of a string.
 * @param {string} str - String to capitalize
 * @returns {string} Capitalized string
 */
export function capitalize(str) {
  if (!str) return '';
  return str.charAt(0).toUpperCase() + str.slice(1);
}

/**
 * Formats a role string to be more readable.
 * @param {string} role - Role to format
 * @returns {string} Formatted role
 */
export function formatRole(role) {
  if (!role) return '';
  return role.split('_').map(capitalize).join(' ');
}
