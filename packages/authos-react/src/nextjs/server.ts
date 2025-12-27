import { headers, cookies } from 'next/headers';

/**
 * User information extracted from the request in server components.
 */
export interface AuthUser {
  id: string;
  email: string;
  org?: string;
  permissions: string[];
}

/**
 * Authentication state for server components.
 */
export interface AuthState {
  userId: string | null;
  orgSlug: string | null;
  isAuthenticated: boolean;
}

/**
 * Get the current authenticated user in a React Server Component.
 * This reads from the headers set by the authMiddleware.
 *
 * @returns The current user or null if not authenticated
 *
 * @example
 * ```tsx
 * // app/dashboard/page.tsx
 * import { currentUser } from '@drmhse/authos-react/nextjs';
 *
 * export default async function DashboardPage() {
 *   const user = await currentUser();
 *
 *   if (!user) {
 *     redirect('/signin');
 *   }
 *
 *   return <div>Welcome, {user.email}!</div>;
 * }
 * ```
 */
export async function currentUser(): Promise<AuthUser | null> {
  const headersList = await headers();

  const userId = headersList.get('x-authos-user-id');
  const email = headersList.get('x-authos-user-email');

  if (!userId || !email) {
    return null;
  }

  const org = headersList.get('x-authos-org') ?? undefined;
  const permissionsHeader = headersList.get('x-authos-permissions');
  const permissions = permissionsHeader ? JSON.parse(permissionsHeader) : [];

  return {
    id: userId,
    email,
    org,
    permissions,
  };
}

/**
 * Get the current authentication state in a React Server Component.
 * Provides basic auth info without fetching full user details.
 *
 * @returns The current auth state
 *
 * @example
 * ```tsx
 * // app/layout.tsx
 * import { auth } from '@drmhse/authos-react/nextjs';
 *
 * export default async function RootLayout({ children }) {
 *   const { isAuthenticated, userId } = await auth();
 *
 *   return (
 *     <html>
 *       <body>
 *         <nav>
 *           {isAuthenticated ? (
 *             <UserMenu userId={userId} />
 *           ) : (
 *             <a href="/signin">Sign In</a>
 *           )}
 *         </nav>
 *         {children}
 *       </body>
 *     </html>
 *   );
 * }
 * ```
 */
export async function auth(): Promise<AuthState> {
  const headersList = await headers();

  const userId = headersList.get('x-authos-user-id');
  const orgSlug = headersList.get('x-authos-org');

  return {
    userId,
    orgSlug,
    isAuthenticated: !!userId,
  };
}

/**
 * Get the access token from cookies in a server component.
 * Useful when you need to make authenticated API calls from the server.
 *
 * @param cookieName - The name of the token cookie (default: 'authos_token')
 * @returns The access token or null
 *
 * @example
 * ```tsx
 * // app/api/data/route.ts
 * import { getToken } from '@drmhse/authos-react/nextjs';
 *
 * export async function GET() {
 *   const token = await getToken();
 *
 *   if (!token) {
 *     return Response.json({ error: 'Unauthorized' }, { status: 401 });
 *   }
 *
 *   // Use token for backend API calls
 *   const data = await fetchFromAPI(token);
 *   return Response.json(data);
 * }
 * ```
 */
export async function getToken(cookieName = 'authos_token'): Promise<string | null> {
  const cookieStore = await cookies();
  return cookieStore.get(cookieName)?.value ?? null;
}
