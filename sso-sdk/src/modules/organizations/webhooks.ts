import { HttpClient } from '../../http';
import {
  WebhookResponse,
  WebhookListResponse,
  CreateWebhookRequest,
  UpdateWebhookRequest,
  WebhookDeliveryListResponse,
  WebhookDeliveryQueryParams,
  EventTypeInfo,
} from '../../types';

/**
 * Organization webhooks management methods
 */
export class WebhooksModule {
  constructor(private http: HttpClient) {}

  /**
   * Create a new webhook for an organization.
   * Requires 'owner' or 'admin' role.
   *
   * @param orgSlug Organization slug
   * @param webhook Webhook creation payload
   * @returns Created webhook details
   *
   * @example
   * ```typescript
   * const webhook = await sso.organizations.webhooks.create('acme-corp', {
   *   name: 'User Activity',
   *   url: 'https://api.example.com/webhooks',
   *   events: ['user.invited', 'user.joined', 'user.removed']
   * });
   * console.log('Created webhook:', webhook.id);
   * ```
   */
  public async create(
    orgSlug: string,
    webhook: CreateWebhookRequest
  ): Promise<WebhookResponse> {
    const response = await this.http.post<WebhookResponse>(
      `/api/organizations/${orgSlug}/webhooks`,
      webhook
    );
    return response.data;
  }

  /**
   * List all webhooks for an organization.
   * Requires 'owner' or 'admin' role.
   *
   * @param orgSlug Organization slug
   * @returns List of webhooks with total count
   *
   * @example
   * ```typescript
   * const { webhooks, total } = await sso.organizations.webhooks.list('acme-corp');
   * console.log(`Found ${total} webhooks`);
   * webhooks.forEach(w => console.log(w.name, w.is_active));
   * ```
   */
  public async list(orgSlug: string): Promise<WebhookListResponse> {
    const response = await this.http.get<WebhookListResponse>(
      `/api/organizations/${orgSlug}/webhooks`
    );
    return response.data;
  }

  /**
   * Get a specific webhook by ID.
   * Requires 'owner' or 'admin' role.
   *
   * @param orgSlug Organization slug
   * @param webhookId Webhook ID
   * @returns Webhook details
   *
   * @example
   * ```typescript
   * const webhook = await sso.organizations.webhooks.get('acme-corp', 'webhook-123');
   * console.log('Webhook URL:', webhook.url);
   * console.log('Subscribed events:', webhook.events);
   * ```
   */
  public async get(orgSlug: string, webhookId: string): Promise<WebhookResponse> {
    const response = await this.http.get<WebhookResponse>(
      `/api/organizations/${orgSlug}/webhooks/${webhookId}`
    );
    return response.data;
  }

  /**
   * Update an existing webhook.
   * Requires 'owner' or 'admin' role.
   *
   * @param orgSlug Organization slug
   * @param webhookId Webhook ID
   * @param updates Partial webhook update payload
   * @returns Updated webhook details
   *
   * @example
   * ```typescript
   * // Update webhook URL and add new events
   * const updated = await sso.organizations.webhooks.update('acme-corp', 'webhook-123', {
   *   url: 'https://api.example.com/webhooks/v2',
   *   events: ['user.invited', 'user.joined', 'user.removed', 'user.role_updated']
   * });
   *
   * // Deactivate webhook temporarily
   * await sso.organizations.webhooks.update('acme-corp', 'webhook-123', {
   *   is_active: false
   * });
   * ```
   */
  public async update(
    orgSlug: string,
    webhookId: string,
    updates: UpdateWebhookRequest
  ): Promise<WebhookResponse> {
    const response = await this.http.patch<WebhookResponse>(
      `/api/organizations/${orgSlug}/webhooks/${webhookId}`,
      updates
    );
    return response.data;
  }

  /**
   * Delete a webhook.
   * Requires 'owner' or 'admin' role.
   * This will also delete all delivery history for this webhook.
   *
   * @param orgSlug Organization slug
   * @param webhookId Webhook ID
   *
   * @example
   * ```typescript
   * await sso.organizations.webhooks.delete('acme-corp', 'webhook-123');
   * console.log('Webhook deleted successfully');
   * ```
   */
  public async delete(orgSlug: string, webhookId: string): Promise<void> {
    await this.http.delete(
      `/api/organizations/${orgSlug}/webhooks/${webhookId}`
    );
  }

  /**
   * Get delivery history for a specific webhook.
   * Requires 'owner' or 'admin' role.
   *
   * @param orgSlug Organization slug
   * @param webhookId Webhook ID
   * @param params Optional query parameters for filtering and pagination
   * @returns Paginated webhook delivery response
   *
   * @example
   * ```typescript
   * // Get all delivery attempts
   * const deliveries = await sso.organizations.webhooks.getDeliveries('acme-corp', 'webhook-123');
   *
   * // Get only failed deliveries
   * const failed = await sso.organizations.webhooks.getDeliveries('acme-corp', 'webhook-123', {
   *   delivered: false,
   *   page: 1,
   *   limit: 20
   * });
   *
   * // Get deliveries for specific event type
   * const userEvents = await sso.organizations.webhooks.getDeliveries('acme-corp', 'webhook-123', {
   *   event_type: 'user.invited'
   * });
   * ```
   */
  public async getDeliveries(
    orgSlug: string,
    webhookId: string,
    params?: WebhookDeliveryQueryParams
  ): Promise<WebhookDeliveryListResponse> {
    const response = await this.http.get<WebhookDeliveryListResponse>(
      `/api/organizations/${orgSlug}/webhooks/${webhookId}/deliveries`,
      { params }
    );
    return response.data;
  }

  /**
   * Get available webhook event types that can be subscribed to.
   * Requires 'owner' or 'admin' role.
   *
   * @param orgSlug Organization slug
   * @returns Array of available event types with categories
   *
   * @example
   * ```typescript
   * const eventTypes = await sso.organizations.webhooks.getEventTypes('acme-corp');
   *
   * // Group events by category for UI display
   * const byCategory = eventTypes.reduce((acc, event) => {
   *   if (!acc[event.category]) {
   *     acc[event.category] = [];
   *   }
   *   acc[event.category].push(event);
   *   return acc;
   * }, {});
   *
   * // Display available events
   * Object.entries(byCategory).forEach(([category, events]) => {
   *   console.log(`\n${category}:`);
   *   events.forEach(e => console.log(`  - ${e.label} (${e.value})`));
   * });
   * ```
   */
  public async getEventTypes(orgSlug: string): Promise<EventTypeInfo[]> {
    const response = await this.http.get<EventTypeInfo[]>(
      `/api/organizations/${orgSlug}/webhooks/event-types`
    );
    return response.data;
  }
}