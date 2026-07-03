export interface EvidenceEvent {
  id: number;
  event_type: 'Created' | 'Updated' | 'Verified' | 'Downloaded' | 'Annotated' | 'Archived' | 'Purged';
  actor_username: string | null;
  note: string | null;
  hash_at_event: string | null;
  timestamp: string;
  ip_address: string | null;
}

export interface EvidenceAnnotation {
  id: number;
  annotation_type: 'Note' | 'Tag' | 'Highlight';
  content: string;
  region: object | null;
  author_username: string | null;
  created_at: string;
  updated_at: string;
}

export interface Evidence {
  uuid: string;
  collection: number;
  evidence_type: 'Screenshot' | 'NetworkCapture' | 'RequestResponse' | 'CommandOutput' | 'Log' | 'Report' | 'Other';
  title: string;
  description: string | null;
  file_name: string | null;
  file_size: number;
  file_size_mb: number;
  mime_type: string | null;
  sha256_hash: string | null;
  status: 'Draft' | 'Active' | 'Archived' | 'Purged';
  collected_at: string;
  collected_by_username: string | null;
  created_at: string;
  updated_at: string;
  download_url: string;
  vulnerability_ids: number[];
  events: EvidenceEvent[];
  annotations: EvidenceAnnotation[];
}

export interface EvidenceRetentionPolicy {
  id: number;
  archive_after_days: number;
  purge_after_days: number;
  purge_files: boolean;
  last_enforced_at: string | null;
  next_action_at: string | null;
}

export interface EvidenceCollection {
  uuid: string;
  assessment: number;
  scan_history: number | null;
  name: string;
  status: 'Draft' | 'Active' | 'Archived' | 'Purged';
  item_count: number;
  retention_policy: EvidenceRetentionPolicy | null;
  created_at: string;
  updated_at: string;
}
