import { useState, useEffect, useCallback } from 'react';

/**
 * Payload of an `AssessmentEventConsumer` message: `assessment_progress` (state machine
 * transitions and the snapshot sent on connect) or `evidence_created`.
 */
export interface AssessmentStreamPayload {
  assessment_id?: string;
  /** Workflow stage, e.g. `Discovery`. */
  stage?: string;
  /** Percentage, 0-100. */
  progress?: number;
  timestamp?: string;
  evidence_uuid?: string;
  collection_uuid?: string;
  evidence_type?: string;
  title?: string;
  [key: string]: unknown;
}

/** A message as the consumer sends it (`{ type, data }`), stamped with its arrival time. */
export interface AssessmentStreamEvent {
  /** Event name, e.g. `assessment_progress`. */
  type: string;
  data: AssessmentStreamPayload;
  /** ISO time the browser received the message; the server does not stamp every event. */
  receivedAt: string;
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
            const message = JSON.parse(event.data) as Omit<AssessmentStreamEvent, 'receivedAt'>;
            setEvents((prev) => [...prev, { ...message, receivedAt: new Date().toISOString() }]);
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
