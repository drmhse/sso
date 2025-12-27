import { useCallback } from 'react';
import { useAuthOSContext } from '../context';
import type { Organization } from '@drmhse/sso-sdk';

interface UseOrganizationReturn {
  /** The current active organization */
  organization: Organization | null;
  /** Switch to a different organization by slug */
  switchOrganization: (slug: string) => Promise<void>;
}

/**
 * Hook to access the current organization context and switch between organizations.
 *
 * Note: Organization switching sets the local context. For full token-scoped
 * organization switching, users should re-authenticate through the OAuth flow
 * with the organization parameter.
 *
 * @returns The current organization and a function to switch organizations
 *
 * @example
 * ```tsx
 * function OrgSelector() {
 *   const { organization, switchOrganization } = useOrganization();
 *
 *   return (
 *     <div>
 *       <p>Current org: {organization?.name}</p>
 *       <button onClick={() => switchOrganization('other-org')}>
 *         Switch to Other Org
 *       </button>
 *     </div>
 *   );
 * }
 * ```
 */
export function useOrganization(): UseOrganizationReturn {
  const { client, organization, setOrganization, refreshUser } = useAuthOSContext();

  const switchOrganization = useCallback(
    async (slug: string) => {
      // Get the organization details
      const orgResponse = await client.organizations.get(slug);
      setOrganization(orgResponse.organization);

      // Refresh user to get context for the new org
      await refreshUser();
    },
    [client, setOrganization, refreshUser]
  );

  return { organization, switchOrganization };
}
