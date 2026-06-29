export interface Client {
  id: number;
  uuid: string;
  name: string;
  description?: string;
  created_at: string;
}

export interface Engagement {
  id: number;
  uuid: string;
  client: number;
  name: string;
  start_date: string;
  end_date: string;
  status: 'planned' | 'in_progress' | 'on_hold' | 'completed' | 'cancelled';
}

export interface Assessment {
  id: number;
  uuid: string;
  engagement: number;
  name: string;
  assessment_type: string;
  status: 'planned' | 'in_progress' | 'on_hold' | 'completed' | 'cancelled';
  start_date: string;
  end_date: string;
}
