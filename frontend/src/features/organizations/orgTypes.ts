export type Organization = {
  id: number;
  name: string;
  description: string | null;
  insert_date: string;
  domains: number[];
  /** Project id (`OrganizationSerializer` returns the FK id). */
  project: number | null;
  targets_count?: number;
};

/** Body of `POST /api/createOrganization/`; the project is resolved from `slug`. */
export type CreateOrganizationDTO = {
  name: string;
  description?: string;
  domains: number[];
  slug: string;
};

export type UpdateOrganizationDTO = {
  id: number;
  name?: string;
  description?: string;
  domains?: number[];
  project?: number;
};
