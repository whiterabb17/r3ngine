import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import type { Engine, Configuration, Wordlist, HardwareProfile } from '../types';

export const useEngines = () => {
  return useQuery<Engine[]>({
    queryKey: ['engines'],
    queryFn: async () => {
      const response = await fetch('/api/listEngines/', {
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      const data = await response.json();
      return data.engines;
    },
  });
};

export const useConfigurations = () => {
  return useQuery<Configuration[]>({
    queryKey: ['configurations'],
    queryFn: async () => {
      const response = await fetch('/api/listConfigurations/', {
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      const data = await response.json();
      return data.configurations;
    },
  });
};

export const useWordlists = () => {
  return useQuery<Wordlist[]>({
    queryKey: ['wordlists'],
    queryFn: async () => {
      const response = await fetch('/api/listWordlists/', {
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      const data = await response.json();
      return data.wordlists;
    },
  });
};

export const useDeleteEngine = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (id: number) => {
      const response = await fetch('/api/action/rows/delete/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': document.cookie.split('; ').find(row => row.startsWith('csrftoken='))?.split('=')[1] || ''
        },
        body: JSON.stringify({
          type: 'scan_engine',
          rows: [id]
        }),
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Failed to delete engine');
      }
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['engines'] });
    },
  });
};

export const useDeleteWordlist = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (id: number) => {
      const response = await fetch('/api/action/rows/delete/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': document.cookie.split('; ').find(row => row.startsWith('csrftoken='))?.split('=')[1] || ''
        },
        body: JSON.stringify({
          type: 'wordlist',
          rows: [id]
        }),
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Failed to delete wordlist');
      }
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['wordlists'] });
    },
  });
};

export const useCreateEngine = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (data: { engine_name: string; yaml_configuration: string }) => {
      const response = await fetch('/api/action/engine/create/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': document.cookie.split('; ').find(row => row.startsWith('csrftoken='))?.split('=')[1] || ''
        },
        body: JSON.stringify(data),
        credentials: 'include'
      });
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Failed to create engine');
      }
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['engines'] });
    },
  });
};

export const useUploadWordlist = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (formData: FormData) => {
      const response = await fetch('/api/action/wordlist/upload/', {
        method: 'POST',
        headers: {
          'X-CSRFToken': document.cookie.split('; ').find(row => row.startsWith('csrftoken='))?.split('=')[1] || ''
        },
        body: formData,
        credentials: 'include'
      });
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Failed to upload wordlist');
      }
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['wordlists'] });
    },
  });
};

export const fetchWordlistContent = async (id: number) => {
  const response = await fetch(`/api/action/wordlist/read/?wordlist_id=${id}`, {
    credentials: 'include'
  });
  if (!response.ok) {
    throw new Error('Failed to fetch wordlist content');
  }
  return response.json();
};

export const fetchEngineDetails = async (id: number) => {
  const response = await fetch(`/api/action/engine/get/?engine_id=${id}`, {
    credentials: 'include'
  });
  if (!response.ok) {
    throw new Error('Failed to fetch engine details');
  }
  return response.json();
};

export const useUpdateEngine = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (data: { engine_id: number; engine_name: string; yaml_configuration: string }) => {
      const response = await fetch('/api/action/engine/update/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': document.cookie.split('; ').find(row => row.startsWith('csrftoken='))?.split('=')[1] || ''
        },
        body: JSON.stringify(data),
        credentials: 'include'
      });
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Failed to update engine');
      }
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['engines'] });
    },
  });
};
export const useFullYamlConfig = () => {
  return useQuery({
    queryKey: ['fullYamlConfig'],
    queryFn: async () => {
      const response = await fetch('/scanEngine/default/get_full_yaml_config/', {
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Failed to fetch full YAML config');
      }
      const data = await response.json();
      return data.content;
    },
  });
};export const useHardwareProfiles = () => {
  return useQuery<HardwareProfile[]>({
    queryKey: ['hardwareProfiles'],
    queryFn: async () => {
      const response = await fetch('/api/hardwareProfiles/', {
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      const data = await response.json();
      return Array.isArray(data) ? data : (data.results || []);
    },
  });
};

export function useYamlConfigReference() {
  return useQuery<string>({
    queryKey: ['yaml_config_reference'],
    queryFn: async () => {
      const response = await fetch('/scanEngine/default/yaml_config_reference/', {
        credentials: 'include',
      });
      if (!response.ok) throw new Error('Failed to fetch YAML config reference');
      const json = await response.json();
      return json.content as string;
    },
    staleTime: Infinity,
  });
}
