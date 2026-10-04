export interface Engine {
  id: number;
  engine_name: string;
  yaml_configuration: string;
  default_engine: boolean;
  tasks: string[];
  /** The tasks a subscan can run; `tasks` also lists settings-only YAML sections. */
  subscan_tasks?: string[];
}

/** Row of `GET /api/listConfigurations/` (`ConfigurationSerializer`, all `Configuration` fields). */
export interface Configuration {
  id: number;
  name: string;
  short_name: string;
  content: string;
}

export interface Wordlist {
  id: number;
  name: string;
  short_name: string;
  count: number;
}

export interface HardwareProfile {
  id: number;
  name: string;
  description?: string;
  threads: number;
  rate_limit: number;
  timeout: number;
  delay: number;
  retries: number;
  profile_type: 'builtin' | 'custom';
  is_active: boolean;
  is_default: boolean;
}
