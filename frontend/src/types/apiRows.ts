/**
 * openapi-typescript marks read-only and defaulted serializer fields optional, because a request
 * body may omit them. A response row always carries them; `WithRequired` restores that for `K`.
 */
export type WithRequired<T, K extends keyof T> = Omit<T, K> & Required<Pick<T, K>>;
