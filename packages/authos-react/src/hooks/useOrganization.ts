import { useCallback } from 'react';
import { useAuthOSContext } from '../context';
import type { Organization } from '@drmhse/sso-sdk';

interface UseOrganizationReturn {
  /** The current active organization */
  organization: Organization | null;
  /** Switch to a different organization by slug - issues new org-scoped tokens */
  switchOrganization: (slug: string) => Promise<void>;
}

/**
 * Hook to access the current organization context and switch between organizations.
 *
 * When switching organizations, this hook calls the backend to issue new JWT tokens
 * with the organization context, enabling seamless organization switching without
 * requiring re-authentication.
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
      // Call the backend to issue new org-scoped tokens
      const result = await client.organizations.select(slug);

      // Update the SDK session with the new tokens
      await client.setSession({
        access_token: result.access_token,
        refresh_token: result.refresh_token,
      });

      // Update the local organization state
      setOrganization(result.organization);

      // Refresh user to get context for the new org
      await refreshUser();
    },
    [client, setOrganization, refreshUser]
  );

  return { organization, switchOrganization };
}
