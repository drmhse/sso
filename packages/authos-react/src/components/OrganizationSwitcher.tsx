import { useState, useEffect, useCallback } from 'react';
import type { Organization } from '@drmhse/sso-sdk';
import { useAuthOSContext } from '../context';
import { useOrganization } from '../hooks/useOrganization';
import type { OrganizationSwitcherProps } from '../types';

/**
 * Component for switching between organizations.
 *
 * @example
 * ```tsx
 * import { OrganizationSwitcher } from '@drmhse/authos-react';
 *
 * function Header() {
 *   return (
 *     <OrganizationSwitcher
 *       onSwitch={(org) => console.log('Switched to:', org.name)}
 *     />
 *   );
 * }
 * ```
 */
export function OrganizationSwitcher({ onSwitch, className, renderItem }: OrganizationSwitcherProps) {
  const { client, isAuthenticated } = useAuthOSContext();
  const { organization: currentOrg, switchOrganization } = useOrganization();

  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isOpen, setIsOpen] = useState(false);
  const [isSwitching, setIsSwitching] = useState(false);

  useEffect(() => {
    if (!isAuthenticated) {
      setOrganizations([]);
      setIsLoading(false);
      return;
    }

    const fetchOrganizations = async () => {
      try {
        // organizations.list() returns OrganizationResponse[] directly
        const orgResponses = await client.organizations.list();
        // Extract the organization from each response
        setOrganizations(orgResponses.map((r) => r.organization));
      } catch {
        setOrganizations([]);
      } finally {
        setIsLoading(false);
      }
    };

    fetchOrganizations();
  }, [client, isAuthenticated]);

  const handleSwitch = useCallback(
    async (org: Organization) => {
      if (org.slug === currentOrg?.slug) {
        setIsOpen(false);
        return;
      }

      setIsSwitching(true);
      try {
        await switchOrganization(org.slug);
        onSwitch?.(org);
        setIsOpen(false);
      } catch (err) {
        console.error('Failed to switch organization:', err);
      } finally {
        setIsSwitching(false);
      }
    },
    [currentOrg, switchOrganization, onSwitch]
  );

  if (!isAuthenticated) {
    return (
      <div className={className} data-authos-orgswitcher data-state="signed-out">
        <span data-authos-org-placeholder>Not signed in</span>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className={className} data-authos-orgswitcher data-state="loading">
        <span>Loading...</span>
      </div>
    );
  }

  if (organizations.length === 0) {
    return null;
  }

  return (
    <div className={className} data-authos-orgswitcher data-state={isOpen ? 'open' : 'closed'}>
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        disabled={isSwitching}
        data-authos-org-trigger
      >
        <span data-authos-org-name>{currentOrg?.name ?? 'Select Organization'}</span>
        <span data-authos-org-chevron aria-hidden="true">
          {isOpen ? '▲' : '▼'}
        </span>
      </button>

      {isOpen && (
        <ul data-authos-org-list role="listbox">
          {organizations.map((org) => {
            const isActive = org.slug === currentOrg?.slug;

            if (renderItem) {
              return (
                <li key={org.id} role="option" aria-selected={isActive}>
                  <button
                    type="button"
                    onClick={() => handleSwitch(org)}
                    disabled={isSwitching}
                  >
                    {renderItem(org, isActive)}
                  </button>
                </li>
              );
            }

            return (
              <li key={org.id} role="option" aria-selected={isActive}>
                <button
                  type="button"
                  onClick={() => handleSwitch(org)}
                  disabled={isSwitching}
                  data-authos-org-item
                  data-active={isActive}
                >
                  <span data-authos-org-item-name>{org.name}</span>
                  {isActive && <span data-authos-org-item-check>✓</span>}
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
