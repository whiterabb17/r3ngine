import { create } from 'zustand';

export type ToolKey = 'hunter' | 'harvester' | 'phonebook' | 'pattern' | 'crawled';
export type ToolStatus = 'pending' | 'running' | 'done' | 'error' | 'cancelled';

export interface ToolState {
  status: ToolStatus;
  found: number;
  message: string;
}

const DEFAULT_TOOLS: Record<ToolKey, ToolState> = {
  hunter:    { status: 'pending', found: 0, message: '' },
  harvester: { status: 'pending', found: 0, message: '' },
  phonebook: { status: 'pending', found: 0, message: '' },
  pattern:   { status: 'pending', found: 0, message: '' },
  crawled:   { status: 'pending', found: 0, message: '' },
};

interface EmailDiscoveryStore {
  jobId: string | null;
  running: boolean;
  complete: boolean;
  tools: Record<ToolKey, ToolState>;
  totalFound: number;
  // actions
  startJob: (jobId: string) => void;
  handleProgressEvent: (event: {
    job_id: string; tool: ToolKey; status: ToolStatus; found: number; message: string;
  }) => void;
  handleCompleteEvent: (event: {
    job_id: string; total_found: number; sources: Record<string, number>;
  }) => void;
  replayEvents: (events: object[]) => void;
  reset: () => void;
}

export const useEmailDiscoveryStore = create<EmailDiscoveryStore>((set, get) => ({
  jobId: null,
  running: false,
  complete: false,
  tools: { ...DEFAULT_TOOLS },
  totalFound: 0,

  startJob: (jobId) => set({
    jobId,
    running: true,
    complete: false,
    tools: { ...DEFAULT_TOOLS },
    totalFound: 0,
  }),

  handleProgressEvent: (event) => {
    if (event.job_id !== get().jobId) return;
    set((state) => ({
      tools: {
        ...state.tools,
        [event.tool]: {
          status: event.status,
          found: event.found,
          message: event.message,
        },
      },
    }));
  },

  handleCompleteEvent: (event) => {
    if (event.job_id !== get().jobId) return;
    set({ running: false, complete: true, totalFound: event.total_found });
  },

  replayEvents: (events) => {
    const store = get();
    for (const ev of events) {
      const e = ev as Record<string, unknown>;
      if (e['type'] === 'email_discovery_progress') {
        store.handleProgressEvent(e as Parameters<typeof store.handleProgressEvent>[0]);
      } else if (e['type'] === 'email_discovery_complete') {
        store.handleCompleteEvent(e as Parameters<typeof store.handleCompleteEvent>[0]);
      }
    }
  },

  reset: () => set({
    jobId: null,
    running: false,
    complete: false,
    tools: { ...DEFAULT_TOOLS },
    totalFound: 0,
  }),
}));
