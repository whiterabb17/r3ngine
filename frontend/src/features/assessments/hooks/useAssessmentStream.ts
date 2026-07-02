import { useState, useEffect, useCallback } from 'react';

export interface AssessmentStreamEvent {
  event_type: string;
  data: any;
  timestamp: string;
}

export const useAssessmentStream = (assessmentId: string) => {
  const [events, setEvents] = useState<AssessmentStreamEvent[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!assessmentId) return;

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/assessments/${assessmentId}/`;
    
    let ws: WebSocket | null = null;
    let reconnectTimeout: ReturnType<typeof setTimeout>;

    const connect = () => {
      try {
        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
          setIsConnected(true);
          setError(null);
        };

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data) as AssessmentStreamEvent;
            setEvents((prev) => [...prev, data]);
          } catch (e) {
            console.error('Failed to parse websocket message:', e);
          }
        };

        ws.onclose = () => {
          setIsConnected(false);
          // Try to reconnect after 5 seconds
          reconnectTimeout = setTimeout(connect, 5000);
        };

        ws.onerror = (e) => {
          console.error('WebSocket error:', e);
          setError('Failed to connect to assessment stream');
          ws?.close();
        };
      } catch (e) {
        console.error('Error creating WebSocket:', e);
        setError('Failed to connect to assessment stream');
      }
    };

    connect();

    return () => {
      clearTimeout(reconnectTimeout);
      if (ws) {
        ws.close();
      }
    };
  }, [assessmentId]);

  const clearEvents = useCallback(() => {
    setEvents([]);
  }, []);

  return {
    events,
    isConnected,
    error,
    clearEvents,
  };
};
