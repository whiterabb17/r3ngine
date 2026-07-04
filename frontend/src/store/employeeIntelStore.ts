import { create } from 'zustand';

export type EmployeeToolKey = 'theharvester' | 'linkedint' | 'hunter';
export type ToolStatus = 'pending' | 'running' | 'done' | 'error' | 'cancelled';

export interface ToolState {
  status: ToolStatus;
  found: number;
  message: string;
}

const DEFAULT_TOOLS: Record<EmployeeToolKey, ToolState> = {
  theharvester: { status: 'pending', found: 0, message: '' },
  linkedint:    { status: 'pending', found: 0, message: '' },
  hunter:       { status: 'pending', found: 0, message: '' },
};

interface EmployeeIntelStore {
  jobId: string | null;
  running: boolean;
  complete: boolean;
  tools: Record<EmployeeToolKey, ToolState>;
  totalFound: number;
  startJob: (jobId: string) => void;
  handleProgressEvent: (event: {
    job_id: string; tool: EmployeeToolKey; status: ToolStatus; found: number; message: string;
  }) => void;
  handleCompleteEvent: (event: {
    job_id: string; total_found: number; sources: Record<string, number>;
  }) => void;
  replayEvents: (events: object[]) => void;
  reset: () => void;
}

export const useEmployeeIntelStore = create<EmployeeIntelStore>((set, get) => ({
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
        [event.tool]: { status: event.status, found: event.found, message: event.message },
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
      if (e['type'] === 'employee_intel_progress') {
        store.handleProgressEvent(e as Parameters<typeof store.handleProgressEvent>[0]);
      } else if (e['type'] === 'employee_intel_complete') {
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
