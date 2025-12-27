import { HttpClient } from '../http';

/**
 * Request body for creating a user
 */
export interface CreateUserRequest {
  email: string;
}

/**
 * Request body for updating a user
 */
export interface UpdateUserRequest {
  email?: string;
}

/**
 * Request body for creating a subscription
 */
export interface CreateSubscriptionRequest {
  user_id: string;
  plan_id: string;
  status?: string;
  current_period_end?: string;
}

/**
 * Request body for updating a subscription
 */
export interface UpdateSubscriptionRequest {
  status?: string;
  current_period_end?: string;
}

/**
 * Request body for updating service info
 */
export interface UpdateServiceInfoRequest {
  name?: string;
}

/**
 * Service API User response
 */
export interface ServiceApiUser {
  id: string;
  email: string;
  created_at: string;
}

/**
 * Service API Subscription response
 */
export interface ServiceApiSubscription {
  id: string;
  user_id: string;
  plan_id: string;
  plan_name: string;
  status: string;
  current_period_end: string;
}

/**
 * Service API info response
 */
export interface ServiceApiInfo {
  id: string;
  name: string;
  slug: string;
  service_type: string;
  created_at: string;
}

/**
 * Response for list users endpoint
 */
export interface ListUsersResponse {
  users: ServiceApiUser[];
  total: number;
}

/**
 * Response for list subscriptions endpoint
 */
export interface ListSubscriptionsResponse {
  subscriptions: ServiceApiSubscription[];
  total: number;
}

/**
 * Service analytics response
 */
export interface ServiceAnalytics {
  total_users: number;
  active_subscriptions: number;
  [key: string]: any;
}

/**
 * Service API module for API key-based service-to-service operations.
 * Provides operations for managing users, subscriptions, and service configuration.
 *
 * @example
 * ```typescript
 * const sso = new SsoClient({
 *   baseURL: 'https://sso.example.com',
 *   apiKey: 'sk_live_abcd1234...'
 * });
 *
 * // List users
 * const { users, total } = await sso.serviceApi.listUsers({ limit: 50 });
 *
 * // Create a user
 * const user = await sso.serviceApi.createUser({ email: 'user@example.com' });
 *
 * // Create a subscription
 * const subscription = await sso.serviceApi.createSubscription({
 *   user_id: user.id,
 *   plan_id: 'plan_123',
 *   status: 'active'
 * });
 *
 * // Update user
 * await sso.serviceApi.updateUser(user.id, { email: 'newemail@example.com' });
 * ```
 */
export class ServiceApiModule {
  constructor(private http: HttpClient) { }

  /**
   * List all users for the service
   * Requires 'read:users' permission on the API key
   *
   * @param params Optional pagination parameters
   * @returns List of users with total count
   */
  async listUsers(params?: { limit?: number; offset?: number }): Promise<ListUsersResponse> {
    const queryParams = new URLSearchParams();
    if (params?.limit) queryParams.set('limit', params.limit.toString());
    if (params?.offset) queryParams.set('offset', params.offset.toString());

    const query = queryParams.toString() ? `?${queryParams.toString()}` : '';
    const response = await this.http.get<ListUsersResponse>(`/api/service/users${query}`);
    return response.data;
  }

  /**
   * Get a specific user by ID
   * Requires 'read:users' permission on the API key
   *
   * @param userId User ID to retrieve
   * @returns User details
   */
  async getUser(userId: string): Promise<ServiceApiUser> {
    const response = await this.http.get<ServiceApiUser>(`/api/service/users/${userId}`);
    return response.data;
  }

  /**
   * List all subscriptions for the service
   * Requires 'read:subscriptions' permission on the API key
   *
   * @param params Optional pagination parameters
   * @returns List of subscriptions with total count
   */
  async listSubscriptions(params?: { limit?: number; offset?: number }): Promise<ListSubscriptionsResponse> {
    const queryParams = new URLSearchParams();
    if (params?.limit) queryParams.set('limit', params.limit.toString());
    if (params?.offset) queryParams.set('offset', params.offset.toString());

    const query = queryParams.toString() ? `?${queryParams.toString()}` : '';
    const response = await this.http.get<ListSubscriptionsResponse>(`/api/service/subscriptions${query}`);
    return response.data;
  }

  /**
   * Get subscription for a specific user
   * Requires 'read:subscriptions' permission on the API key
   *
   * @param userId User ID whose subscription to retrieve
   * @returns User's subscription
   */
  async getSubscription(userId: string): Promise<ServiceApiSubscription> {
    const response = await this.http.get<ServiceApiSubscription>(`/api/service/subscriptions/${userId}`);
    return response.data;
  }

  /**
   * Get analytics for the service
   * Requires 'read:analytics' permission on the API key
   *
   * @returns Service analytics data
   */
  async getAnalytics(): Promise<ServiceAnalytics> {
    const response = await this.http.get<ServiceAnalytics>('/api/service/analytics');
    return response.data;
  }

  /**
   * Get service information
   * Requires 'read:service' permission on the API key
   *
   * @returns Service information
   */
  async getServiceInfo(): Promise<ServiceApiInfo> {
    const response = await this.http.get<ServiceApiInfo>('/api/service/info');
    return response.data;
  }

  /**
   * Create a new user
   * Requires 'write:users' permission on the API key
   *
   * @param request User creation request
   * @returns Created user
   */
  async createUser(request: CreateUserRequest): Promise<ServiceApiUser> {
    const response = await this.http.post<ServiceApiUser>('/api/service/users', request);
    return response.data;
  }

  /**
   * Update user details
   * Requires 'write:users' permission on the API key
   *
   * @param userId User ID to update
   * @param request User update request
   * @returns Updated user
   */
  async updateUser(userId: string, request: UpdateUserRequest): Promise<ServiceApiUser> {
    const response = await this.http.patch<ServiceApiUser>(`/api/service/users/${userId}`, request);
    return response.data;
  }

  /**
   * Create a new subscription for a user
   * Requires 'write:subscriptions' permission on the API key
   *
   * @param request Subscription creation request
   * @returns Created subscription
   */
  async createSubscription(request: CreateSubscriptionRequest): Promise<ServiceApiSubscription> {
    const response = await this.http.post<ServiceApiSubscription>('/api/service/subscriptions', request);
    return response.data;
  }

  /**
   * Update a subscription for a user
   * Requires 'write:subscriptions' permission on the API key
   *
   * @param userId User ID whose subscription to update
   * @param request Subscription update request
   * @returns Updated subscription
   */
  async updateSubscription(userId: string, request: UpdateSubscriptionRequest): Promise<ServiceApiSubscription> {
    const response = await this.http.patch<ServiceApiSubscription>(`/api/service/subscriptions/${userId}`, request);
    return response.data;
  }

  /**
   * Update service configuration
   * Requires 'write:service' permission on the API key
   *
   * @param request Service update request
   * @returns Updated service info
   */
  async updateServiceInfo(request: UpdateServiceInfoRequest): Promise<ServiceApiInfo> {
    const response = await this.http.patch<ServiceApiInfo>('/api/service/info', request);
    return response.data;
  }

  /**
   * Delete a user
   * Requires 'delete:users' permission on the API key
   *
   * @param userId User ID to delete
   */
  async deleteUser(userId: string): Promise<void> {
    await this.http.delete(`/api/service/users/${userId}`);
  }

  /**
   * Delete a subscription for a user
   * Requires 'delete:subscriptions' permission on the API key
   *
   * @param userId User ID whose subscription to delete
   */
  async deleteSubscription(userId: string): Promise<void> {
    await this.http.delete(`/api/service/subscriptions/${userId}`);
  }
}
