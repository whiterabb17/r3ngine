import { useMutation } from '@tanstack/react-query';
import axios from 'axios';
import { getCsrfToken } from '../../../api/axiosConfig';
import type { LoginResponse } from '../types';

export const useLogin = () => {
  return useMutation({
    mutationFn: async (data: FormData) => {
      const response = await axios.post('/login/', data, {
        headers: {
          'X-CSRFToken': getCsrfToken(),
          'Content-Type': 'multipart/form-data',
          'Accept': 'application/json'
        },
      });
      return response.data as LoginResponse;
    },
  });
};

export interface OnboardingData {
  project_name: string;
  create_username?: string;
  create_password?: string;
  create_user_role?: string;
  key_openai?: string;
  key_netlas?: string;
  key_chaos?: string;
  key_hackerone?: string;
  username_hackerone?: string;
  key_shodan?: string;
  key_censys?: string;
  bug_bounty_mode: boolean;
}

export const useOnboarding = () => {
  return useMutation({
    mutationFn: async (data: OnboardingData) => {
      const formData = new FormData();
      Object.entries(data).forEach(([key, value]) => {
        if (value !== undefined) {
          if (typeof value === 'boolean') {
            if (value) formData.append(key, 'on');
          } else {
            formData.append(key, value);
          }
        }
      });

      const response = await axios.post('/onboarding/', formData, {
        headers: {
          'X-CSRFToken': getCsrfToken(),
          'Content-Type': 'multipart/form-data',
          'Accept': 'application/json'
        },
      });
      return response.data;
    },
  });
};

export interface CurrentUser {
  id: number;
  username: string;
  email: string;
  role: string;
}

/** Body of `/api/users/me/`; callers treat an explicit `status: false` as signed out. */
export type CurrentUserResponse = CurrentUser & { status?: boolean };

export const fetchCurrentUser = async (): Promise<CurrentUserResponse | null> => {
  const response = await axios.get<CurrentUserResponse | null>('/api/users/me/', {
    headers: { 'Accept': 'application/json' }
  });
  return response.data;
};

export const logoutSession = async (): Promise<void> => {
  await axios.post('/logout/', {}, {
    headers: {
      'X-CSRFToken': document.cookie.split('; ').find(row => row.startsWith('csrftoken='))?.split('=')[1]
    }
  });
};

export interface PasswordChangeData {
  old_password: string;
  new_password1: string;
  new_password2: string;
}

/** Posts to the Django password-change form view; resolves to whether it accepted the change. */
export const changePassword = async (projectSlug: string, data: PasswordChangeData): Promise<boolean> => {
  const form = new FormData();
  form.append('old_password', data.old_password);
  form.append('new_password1', data.new_password1);
  form.append('new_password2', data.new_password2);

  const csrfToken = document.cookie
    .split('; ')
    .find(row => row.startsWith('csrftoken='))
    ?.split('=')[1];

  const response = await fetch(`/${projectSlug}/profile/`, {
    method: 'POST',
    headers: {
      'X-CSRFToken': csrfToken || '',
    },
    body: form,
  });
  return response.ok;
};
