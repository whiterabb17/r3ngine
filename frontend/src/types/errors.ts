/**
 * Structural view of a value caught from an API call: a plain `Error`, or an
 * axios-style error whose `response.data` carries the backend's message.
 * `catch` bindings are `unknown`; cast to this and read every field optionally.
 */
export type ApiErrorLike = {
  message?: string;
  response?: {
    status?: number;
    data?: {
      error?: string;
      message?: string;
      detail?: string;
    };
  };
} | null | undefined;
