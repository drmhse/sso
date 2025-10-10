export interface LoginTrendPoint {
  date: string;
  count: number;
}

export interface LoginsByService {
  service_id: string;
  service_name: string;
  count: number;
}

export interface LoginsByProvider {
  provider: 'github' | 'google' | 'microsoft';
  count: number;
}

export interface RecentLogin {
  id: string;
  user_id: string;
  service_id: string;
  provider: string;
  created_at: string;
}

export interface AnalyticsQuery {
  start_date?: string;
  end_date?: string;
  limit?: number;
}
