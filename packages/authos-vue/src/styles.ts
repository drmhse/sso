/**
 * Built-in styles for AuthOS Vue components.
 * Provides polished default styling with CSS custom properties for theming.
 */

export const AUTHOS_STYLES = `
/* ==========================================================================
   AuthOS Component Styles
   CSS Variables + Default Theme
   ========================================================================== */

:root {
  /* Primary Colors */
  --authos-color-primary: #6366f1;
  --authos-color-primary-hover: #4f46e5;
  --authos-color-primary-foreground: #ffffff;
  
  /* Semantic Colors */
  --authos-color-danger: #ef4444;
  --authos-color-danger-foreground: #ffffff;
  --authos-color-success: #22c55e;
  --authos-color-warning: #f59e0b;
  
  /* Surface Colors */
  --authos-color-background: #ffffff;
  --authos-color-surface: #ffffff;
  --authos-color-foreground: #0f172a;
  --authos-color-muted: #64748b;
  --authos-color-muted-foreground: #64748b;
  
  /* Component Colors */
  --authos-color-border: #e2e8f0;
  --authos-color-input: #ffffff;
  --authos-color-input-border: #cbd5e1;
  --authos-color-input-focus: #6366f1;
  --authos-color-ring: rgba(99, 102, 241, 0.25);
  
  /* Typography */
  --authos-font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
  --authos-font-size-xs: 0.75rem;
  --authos-font-size-sm: 0.875rem;
  --authos-font-size-base: 1rem;
  --authos-font-size-lg: 1.125rem;
  
  /* Spacing & Shape */
  --authos-border-radius: 0.5rem;
  --authos-border-radius-sm: 0.375rem;
  --authos-border-radius-lg: 0.75rem;
  --authos-spacing-xs: 0.25rem;
  --authos-spacing-sm: 0.5rem;
  --authos-spacing-md: 1rem;
  --authos-spacing-lg: 1.5rem;
  
  /* Shadows */
  --authos-shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
  --authos-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px -1px rgba(0, 0, 0, 0.1);
  --authos-shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -4px rgba(0, 0, 0, 0.1);
  
  /* Transitions */
  --authos-transition: 150ms cubic-bezier(0.4, 0, 0.2, 1);
}

/* Dark Mode */
@media (prefers-color-scheme: dark) {
  :root {
    --authos-color-primary: #818cf8;
    --authos-color-primary-hover: #a5b4fc;
    
    --authos-color-background: #0f172a;
    --authos-color-surface: #1e293b;
    --authos-color-foreground: #f1f5f9;
    --authos-color-muted: #94a3b8;
    --authos-color-muted-foreground: #94a3b8;
    
    --authos-color-border: #334155;
    --authos-color-input: #1e293b;
    --authos-color-input-border: #475569;
    
    --authos-shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.3);
    --authos-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.4), 0 1px 2px -1px rgba(0, 0, 0, 0.3);
    --authos-shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.4), 0 4px 6px -4px rgba(0, 0, 0, 0.3);
  }
}

/* ==========================================================================
   Base Form Styles
   ========================================================================== */

/* ==========================================================================
   Base Form Styles (Card Layout)
   ========================================================================== */

[data-authos-signin],
[data-authos-signup],
[data-authos-magic-link],
[data-authos-passkey] {
  font-family: var(--authos-font-family);
  font-size: var(--authos-font-size-sm);
  color: var(--authos-color-foreground);
  
  /* Card Styling */
  background-color: var(--authos-color-surface);
  border: 1px solid var(--authos-color-border);
  border-radius: var(--authos-border-radius-lg);
  box-shadow: var(--authos-shadow);
  padding: 2rem;
  width: 100%;
  max-width: 25rem; /* 400px */
  margin: 0 auto;   /* Center horizontally */
}

/* Ensure forms inside take full width */
[data-authos-signin] form,
[data-authos-signup] form,
[data-authos-magic-link] form,
[data-authos-passkey] form {
  display: flex;
  flex-direction: column;
  gap: var(--authos-spacing-md);
  width: 100%;
}

/* ==========================================================================
   Field Styles
   ========================================================================== */

[data-authos-field] {
  display: flex;
  flex-direction: column;
  gap: var(--authos-spacing-xs);
}

[data-authos-field] label {
  font-size: var(--authos-font-size-sm);
  font-weight: 500;
  color: var(--authos-color-foreground);
}

[data-authos-field] input {
  width: 100%;
  padding: 0.625rem 0.875rem;
  font-size: var(--authos-font-size-sm);
  font-family: inherit;
  color: var(--authos-color-foreground);
  background-color: var(--authos-color-input);
  border: 1px solid var(--authos-color-input-border);
  border-radius: var(--authos-border-radius);
  outline: none;
  transition: border-color var(--authos-transition), box-shadow var(--authos-transition);
}

[data-authos-field] input::placeholder {
  color: var(--authos-color-muted);
}

[data-authos-field] input:focus {
  border-color: var(--authos-color-input-focus);
  box-shadow: 0 0 0 3px var(--authos-color-ring);
}

[data-authos-field] input:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

/* ==========================================================================
   Button Styles
   ========================================================================== */

[data-authos-submit] {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: var(--authos-spacing-sm);
  width: 100%;
  padding: 0.625rem 1rem;
  font-size: var(--authos-font-size-sm);
  font-weight: 500;
  font-family: inherit;
  color: var(--authos-color-primary-foreground);
  background-color: var(--authos-color-primary);
  border: none;
  border-radius: var(--authos-border-radius);
  cursor: pointer;
  outline: none;
  transition: background-color var(--authos-transition), box-shadow var(--authos-transition);
}

[data-authos-submit]:hover:not(:disabled) {
  background-color: var(--authos-color-primary-hover);
}

[data-authos-submit]:focus-visible {
  box-shadow: 0 0 0 3px var(--authos-color-ring);
}

[data-authos-submit]:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

[data-authos-back] {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 0.5rem 1rem;
  font-size: var(--authos-font-size-sm);
  font-weight: 500;
  font-family: inherit;
  color: var(--authos-color-muted);
  background: transparent;
  border: none;
  border-radius: var(--authos-border-radius);
  cursor: pointer;
  transition: color var(--authos-transition);
}

[data-authos-back]:hover {
  color: var(--authos-color-foreground);
}

/* ==========================================================================
   OAuth Button Styles
   ========================================================================== */

[data-authos-oauth] {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.75rem;
  width: 100%;
  padding: 0.625rem 1rem;
  font-size: var(--authos-font-size-sm);
  font-weight: 500;
  font-family: var(--authos-font-family);
  color: var(--authos-color-foreground);
  background-color: var(--authos-color-surface);
  border: 1px solid var(--authos-color-border);
  border-radius: var(--authos-border-radius);
  cursor: pointer;
  outline: none;
  transition: background-color var(--authos-transition), border-color var(--authos-transition), box-shadow var(--authos-transition);
}

[data-authos-oauth]:hover:not(:disabled) {
  background-color: var(--authos-color-background);
  border-color: var(--authos-color-input-border);
}

[data-authos-oauth]:focus-visible {
  box-shadow: 0 0 0 3px var(--authos-color-ring);
}

[data-authos-oauth]:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

[data-authos-oauth] svg {
  width: 1.25rem;
  height: 1.25rem;
  flex-shrink: 0;
}

/* ==========================================================================
   Divider Styles
   ========================================================================== */

[data-authos-divider] {
  display: flex;
  align-items: center;
  gap: var(--authos-spacing-md);
  margin: var(--authos-spacing-sm) 0;
}

[data-authos-divider]::before,
[data-authos-divider]::after {
  content: '';
  flex: 1;
  height: 1px;
  background-color: var(--authos-color-border);
}

[data-authos-divider] span {
  font-size: var(--authos-font-size-xs);
  color: var(--authos-color-muted);
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

/* ==========================================================================
   Error Styles
   ========================================================================== */

[data-authos-error] {
  display: flex;
  align-items: center;
  gap: var(--authos-spacing-sm);
  padding: 0.75rem 1rem;
  font-size: var(--authos-font-size-sm);
  color: var(--authos-color-danger);
  background-color: rgba(239, 68, 68, 0.1);
  border: 1px solid rgba(239, 68, 68, 0.2);
  border-radius: var(--authos-border-radius);
}

/* ==========================================================================
   Link Styles
   ========================================================================== */

[data-authos-link] {
  font-size: var(--authos-font-size-sm);
  color: var(--authos-color-primary);
  text-decoration: none;
  transition: color var(--authos-transition);
}

[data-authos-link]:hover {
  color: var(--authos-color-primary-hover);
  text-decoration: underline;
}

[data-authos-signup-prompt],
[data-authos-signin-prompt] {
  text-align: center;
  font-size: var(--authos-font-size-sm);
  color: var(--authos-color-muted);
  margin-top: var(--authos-spacing-sm);
}

/* ==========================================================================
   OAuth Section
   ========================================================================== */

[data-authos-oauth-section] {
  display: flex;
  flex-direction: column;
  gap: var(--authos-spacing-sm);
}

/* ==========================================================================
   User Button Styles
   ========================================================================== */

[data-authos-userbutton] {
  display: inline-flex;
  align-items: center;
  gap: var(--authos-spacing-sm);
  font-family: var(--authos-font-family);
  font-size: var(--authos-font-size-sm);
  color: var(--authos-color-foreground);
}

[data-authos-userbutton] [data-authos-avatar] {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 2rem;
  height: 2rem;
  font-size: var(--authos-font-size-xs);
  font-weight: 600;
  color: var(--authos-color-primary-foreground);
  background-color: var(--authos-color-primary);
  border-radius: 50%;
}

[data-authos-userbutton] [data-authos-email] {
  color: var(--authos-color-foreground);
}

[data-authos-userbutton] [data-authos-logout] {
  padding: 0.375rem 0.75rem;
  font-size: var(--authos-font-size-xs);
  font-weight: 500;
  font-family: inherit;
  color: var(--authos-color-muted);
  background: transparent;
  border: 1px solid var(--authos-color-border);
  border-radius: var(--authos-border-radius-sm);
  cursor: pointer;
  transition: color var(--authos-transition), border-color var(--authos-transition);
}

[data-authos-userbutton] [data-authos-logout]:hover:not(:disabled) {
  color: var(--authos-color-danger);
  border-color: var(--authos-color-danger);
}

/* ==========================================================================
   Organization Switcher Styles
   ========================================================================== */

[data-authos-orgswitcher] {
  font-family: var(--authos-font-family);
  font-size: var(--authos-font-size-sm);
}

[data-authos-orgswitcher] select {
  padding: 0.5rem 2rem 0.5rem 0.75rem;
  font-size: var(--authos-font-size-sm);
  font-family: inherit;
  color: var(--authos-color-foreground);
  background-color: var(--authos-color-input);
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%2364748b' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E");
  background-repeat: no-repeat;
  background-position: right 0.5rem center;
  border: 1px solid var(--authos-color-input-border);
  border-radius: var(--authos-border-radius);
  cursor: pointer;
  outline: none;
  appearance: none;
  -webkit-appearance: none;
  -moz-appearance: none;
  transition: border-color var(--authos-transition), box-shadow var(--authos-transition);
}

[data-authos-orgswitcher] select:focus {
  border-color: var(--authos-color-input-focus);
  box-shadow: 0 0 0 3px var(--authos-color-ring);
}

[data-authos-orgswitcher] select:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

/* ==========================================================================
   Loading State
   ========================================================================== */

[data-state="loading"] {
  opacity: 0.6;
}
`;

/**
 * Injects the AuthOS styles into the document head.
 * Only injects once, even if called multiple times.
 */
let stylesInjected = false;

export function injectStyles(): void {
  if (stylesInjected) return;
  if (typeof document === 'undefined') return;

  const styleElement = document.createElement('style');
  styleElement.setAttribute('data-authos-styles', '');
  styleElement.textContent = AUTHOS_STYLES;
  document.head.appendChild(styleElement);
  stylesInjected = true;
}

/**
 * Applies custom CSS variable overrides for theming.
 */
export function applyVariables(variables: Record<string, string>): void {
  if (typeof document === 'undefined') return;

  const root = document.documentElement;
  for (const [key, value] of Object.entries(variables)) {
    // Convert camelCase to kebab-case CSS variable name
    const cssVar = `--authos-${key.replace(/([A-Z])/g, '-$1').toLowerCase()}`;
    root.style.setProperty(cssVar, value);
  }
}
