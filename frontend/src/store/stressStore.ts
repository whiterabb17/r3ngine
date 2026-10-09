import { create } from 'zustand';

export interface TelemetryPoint {
  timestamp: number;
  tool: string;
  endpoint: string;
  latency?: number;
  avg_latency?: number;
  p95_latency?: number;
  throughput_rps?: number;
  error_rate?: number;
  type?: 'command' | 'log' | 'metric';
  command?: string;
  line?: string;
  [key: string]: unknown;
}

interface StressState {
  selectedEndpoint: string | null;
  selectedTimeRange: [number, number] | null;
  selectedMetric: "latency" | "errors" | "throughput";
  isScanning: boolean;
  wsStatus: 'connecting' | 'connected' | 'disconnected' | 'error';
  telemetryData: TelemetryPoint[];
  
  setSelectedEndpoint: (endpoint: string | null) => void;
  setSelectedTimeRange: (range: [number, number] | null) => void;
  setSelectedMetric: (metric: "latency" | "errors" | "throughput") => void;
  setScanning: (isScanning: boolean) => void;
  setWsStatus: (status: 'connecting' | 'connected' | 'disconnected' | 'error') => void;
  addTelemetryPoint: (point: TelemetryPoint) => void;
  clearTelemetry: () => void;
  resetSelections: () => void;
}

export const useStressStore = create<StressState>((set) => ({
  selectedEndpoint: null,
  selectedTimeRange: null,
  selectedMetric: "latency",
  isScanning: false,
  wsStatus: 'disconnected',
  telemetryData: [],
  
  setSelectedEndpoint: (endpoint) => set({ selectedEndpoint: endpoint }),
  setSelectedTimeRange: (range) => set({ selectedTimeRange: range }),
  setSelectedMetric: (metric) => set({ selectedMetric: metric }),
  setScanning: (isScanning) => set({ isScanning }),
  setWsStatus: (status) => set({ wsStatus: status }),
  
  addTelemetryPoint: (point) => set((state) => {
    // Basic validation
    if (!point || typeof point.timestamp !== 'number' || isNaN(point.timestamp)) {
      console.warn("Discarding malformed telemetry point:", point);
      return state;
    }
    
    // Keep last 5000 points to avoid memory issues
    const newData = [...state.telemetryData, point];
    if (newData.length > 5000) {
      newData.shift();
    }
    return { telemetryData: newData };
  }),
  
  clearTelemetry: () => set({ telemetryData: [] }),
  
  resetSelections: () => set({ 
    selectedEndpoint: null, 
    selectedTimeRange: null, 
    selectedMetric: "latency" 
  }),
}));
