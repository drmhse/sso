import { SsoApiError } from './errors';

/**
 * HTTP request options
 */
interface RequestOptions {
  method: string;
  headers?: Record<string, string>;
  body?: any;
  params?: Record<string, any>;
  timeout?: number;
}

/**
 * HTTP response wrapper
 */
interface HttpResponse<T = any> {
  data: T;
  status: number;
  headers: Headers;
}

/**
 * HTTP client defaults
 */
interface HttpDefaults {
  baseURL: string;
  headers: {
    common: Record<string, string>;
  };
  timeout: number;
}

/**
 * Custom HTTP client using native fetch API.
 * Provides an interface similar to Axios for easy migration.
 */
export class HttpClient {
  public defaults: HttpDefaults;

  constructor(baseURL: string) {
    this.defaults = {
      baseURL,
      headers: {
        common: {
          'Content-Type': 'application/json',
        },
      },
      timeout: 30000,
    };
  }

  /**
   * Build query string from params object
   */
  private buildQueryString(params?: Record<string, any>): string {
    if (!params) return '';

    const searchParams = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        searchParams.append(key, String(value));
      }
    });

    const queryString = searchParams.toString();
    return queryString ? `?${queryString}` : '';
  }

  /**
   * Build full URL from path and params
   */
  private buildUrl(path: string, params?: Record<string, any>): string {
    const baseUrl = this.defaults.baseURL.replace(/\/$/, '');
    const cleanPath = path.startsWith('/') ? path : `/${path}`;
    const queryString = this.buildQueryString(params);
    return `${baseUrl}${cleanPath}${queryString}`;
  }

  /**
   * Make HTTP request with timeout support
   */
  private async request<T = any>(path: string, options: RequestOptions): Promise<HttpResponse<T>> {
    const url = this.buildUrl(path, options.params);
    const timeout = options.timeout ?? this.defaults.timeout;

    // Merge headers
    const headers = {
      ...this.defaults.headers.common,
      ...options.headers,
    };

    // Setup abort controller for timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      const response = await fetch(url, {
        method: options.method,
        headers,
        body: options.body ? JSON.stringify(options.body) : undefined,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      // Parse response body
      let data: any;
      const contentType = response.headers.get('content-type');

      if (contentType?.includes('application/json')) {
        data = await response.json();
      } else {
        const text = await response.text();
        data = text || undefined;
      }

      // Handle error responses
      if (!response.ok) {
        if (data && data.error_code && data.error && data.timestamp) {
          throw new SsoApiError(data.error, response.status, data.error_code, data.timestamp);
        }

        // Fallback error
        throw new SsoApiError(
          data?.message || `HTTP ${response.status}: ${response.statusText}`,
          response.status,
          'UNKNOWN_ERROR',
          new Date().toISOString()
        );
      }

      return {
        data,
        status: response.status,
        headers: response.headers,
      };
    } catch (error: any) {
      clearTimeout(timeoutId);

      // Handle timeout
      if (error.name === 'AbortError') {
        throw new SsoApiError('Request timeout', 408, 'TIMEOUT', new Date().toISOString());
      }

      // Handle network errors
      if (error instanceof TypeError && error.message.includes('fetch')) {
        throw new SsoApiError(
          'Network error - unable to reach the server',
          0,
          'NETWORK_ERROR',
          new Date().toISOString()
        );
      }

      // Re-throw SsoApiError
      if (error instanceof SsoApiError) {
        throw error;
      }

      // Wrap any other errors
      throw new SsoApiError(
        error.message || 'An unexpected error occurred',
        500,
        'UNKNOWN_ERROR',
        new Date().toISOString()
      );
    }
  }

  /**
   * GET request
   */
  public async get<T = any>(
    path: string,
    config?: { params?: Record<string, any>; headers?: Record<string, string> }
  ): Promise<HttpResponse<T>> {
    return this.request<T>(path, {
      method: 'GET',
      params: config?.params,
      headers: config?.headers,
    });
  }

  /**
   * POST request
   */
  public async post<T = any>(
    path: string,
    data?: any,
    config?: { headers?: Record<string, string> }
  ): Promise<HttpResponse<T>> {
    return this.request<T>(path, {
      method: 'POST',
      body: data,
      headers: config?.headers,
    });
  }

  /**
   * PATCH request
   */
  public async patch<T = any>(
    path: string,
    data?: any,
    config?: { headers?: Record<string, string> }
  ): Promise<HttpResponse<T>> {
    return this.request<T>(path, {
      method: 'PATCH',
      body: data,
      headers: config?.headers,
    });
  }

  /**
   * DELETE request
   */
  public async delete<T = any>(
    path: string,
    config?: { headers?: Record<string, string> }
  ): Promise<HttpResponse<T>> {
    return this.request<T>(path, {
      method: 'DELETE',
      headers: config?.headers,
    });
  }
}

/**
 * Creates a configured HTTP client instance.
 * @param baseURL The base URL of the SSO API service
 * @returns Configured HTTP client instance
 */
export function createHttpAgent(baseURL: string): HttpClient {
  return new HttpClient(baseURL);
}
