import React, { useState, useEffect } from 'react';
import { TimelineEvent } from '../types';
import {
  Play,
  Pause,
  RotateCcw,
  User,
  Cpu,
  Terminal,
  Shield,
  Activity,
  ChevronRight,
} from 'lucide-react';

interface TimelineProps {
  events: TimelineEvent[];
  onSelectEvent?: (event: TimelineEvent) => void;
}

export const Timeline: React.FC<TimelineProps> = ({ events, onSelectEvent }) => {
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentIndex, setCurrentIndex] = useState(Math.max(0, events.length - 1));
  const [speed, setSpeed] = useState(1);

  // Sync index when events array updates
  useEffect(() => {
    setCurrentIndex(Math.max(0, events.length - 1));
  }, [events.length]);

  // Playback timer
  useEffect(() => {
    let timer: ReturnType<typeof setInterval> | undefined;
    if (isPlaying && events.length > 0) {
      timer = setInterval(() => {
        setCurrentIndex((prev) => {
          if (prev >= events.length - 1) {
            setIsPlaying(false);
            return prev;
          }
          return prev + 1;
        });
      }, 1000 / speed);
    }
    return () => {
      if (timer) clearInterval(timer);
    };
  }, [isPlaying, events.length, speed]);

  // Group events by actor lane
  const actors = Array.from(new Set(events.map((e) => e.actor_id)));

  const getActorIcon = (actorId: string) => {
    if (actorId.includes('user')) return <User size={14} color="#ffffff" />;
    if (actorId.includes('codex') || actorId.includes('claude') || actorId.includes('copilot') || actorId.includes('agent'))
      return <Cpu size={14} color="#ffffff" />;
    if (actorId.includes('terminal') || actorId.includes('process'))
      return <Terminal size={14} color="#ffffff" />;
    return <Shield size={14} color="#ffffff" />;
  };

  const safeIndex = events.length > 0 ? Math.min(currentIndex, events.length - 1) : 0;
  const visibleEvents = events.slice(0, safeIndex + 1);

  if (events.length === 0) {
    return (
      <div className="glass-panel" style={{ margin: '0 16px 16px 16px', height: 'calc(100vh - 120px)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: '12px', color: 'var(--text-dim)' }}>
        <Activity size={36} color="var(--border-dim)" />
        <h3 className="font-heading" style={{ fontSize: '15px', color: 'var(--text-muted)' }}>
          No Events Ingested in Current Session
        </h3>
        <p style={{ fontSize: '12px' }}>
          Execute commands or start an agent audit to capture hash-chained events.
        </p>
      </div>
    );
  }

  return (
    <div className="glass-panel" style={{ margin: '0 16px 16px 16px', display: 'flex', flexDirection: 'column', height: 'calc(100vh - 120px)', overflow: 'hidden' }}>
      {/* Playback Controls Header */}
      <div style={{ padding: '10px 18px', borderBottom: '1px solid var(--border-dim)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '14px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <button
            onClick={() => setIsPlaying(!isPlaying)}
            className="btn btn-primary"
            style={{ padding: '5px 12px', fontSize: '11px' }}
            aria-label={isPlaying ? 'Pause timeline playback' : 'Play timeline'}
          >
            {isPlaying ? <Pause size={13} /> : <Play size={13} />}
            {isPlaying ? 'Pause' : 'Play Timeline'}
          </button>

          <button
            onClick={() => {
              setIsPlaying(false);
              setCurrentIndex(0);
            }}
            className="btn btn-secondary"
            title="Reset to beginning"
            style={{ padding: '5px 8px' }}
            aria-label="Reset timeline to start"
          >
            <RotateCcw size={13} />
          </button>

          <div style={{ display: 'flex', alignItems: 'center', gap: '3px', background: 'var(--bg-input)', padding: '2px 5px', borderRadius: '4px', border: '1px solid var(--border-dim)' }}>
            <span style={{ fontSize: '10.5px', color: 'var(--text-muted)' }}>Speed:</span>
            {[1, 2, 4].map((s) => (
              <button
                key={s}
                onClick={() => setSpeed(s)}
                style={{
                  background: speed === s ? '#ffffff' : 'transparent',
                  color: speed === s ? '#000000' : 'var(--text-main)',
                  border: 'none',
                  borderRadius: '3px',
                  padding: '2px 5px',
                  fontSize: '10.5px',
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                {s}x
              </button>
            ))}
          </div>
        </div>

        {/* Timeline Scrubber */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flex: 1, maxWidth: '440px' }}>
          <span className="font-mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            Step {safeIndex + 1} / {events.length}
          </span>
          <input
            type="range"
            min="0"
            max={Math.max(0, events.length - 1)}
            value={safeIndex}
            aria-label="Timeline step scrubber"
            onChange={(e) => {
              setIsPlaying(false);
              setCurrentIndex(parseInt(e.target.value, 10));
            }}
            style={{
              flex: 1,
              accentColor: '#ffffff',
              cursor: 'pointer',
            }}
          />
        </div>
      </div>

      {/* Actor Lanes & Events */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '16px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
        {actors.map((actor) => {
          const actorEvents = visibleEvents.filter((e) => e.actor_id === actor);
          if (actorEvents.length === 0) return null;

          return (
            <div key={actor} style={{ background: '#09090b', padding: '14px', borderRadius: '8px', border: '1px solid var(--border-dim)' }}>
              {/* Actor Header */}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  {getActorIcon(actor)}
                  <span className="font-heading" style={{ fontSize: '13px', fontWeight: 600, color: '#ffffff' }}>
                    {actor}
                  </span>
                </div>
                <span className="badge badge-medium" style={{ fontSize: '9px' }}>
                  {actorEvents.length} events
                </span>
              </div>

              {/* Event Cards in Lane */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(270px, 1fr))', gap: '8px' }}>
                {actorEvents.map((evt) => (
                  <div
                    key={evt.event_id}
                    onClick={() => onSelectEvent && onSelectEvent(evt)}
                    tabIndex={0}
                    role="button"
                    aria-label={`Timeline event: ${evt.event_type}`}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        onSelectEvent && onSelectEvent(evt);
                      }
                    }}
                    style={{
                      background: 'var(--bg-card)',
                      border: '1px solid var(--border-dim)',
                      borderRadius: '6px',
                      padding: '8px 10px',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '4px',
                      cursor: 'pointer',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <span className="font-mono" style={{ fontSize: '10px', color: '#ffffff', fontWeight: 600 }}>
                        {evt.event_type.toUpperCase()}
                      </span>
                      <span style={{ fontSize: '10px', color: 'var(--text-dim)' }}>
                        {new Date(evt.timestamp).toLocaleTimeString()}
                      </span>
                    </div>

                    <div className="font-mono" style={{ fontSize: '10px', color: 'var(--text-muted)', wordBreak: 'break-all' }}>
                      Hash: {evt.event_hash.slice(0, 16)}...
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '2px' }}>
                      <span className="badge badge-high" style={{ fontSize: '8px', padding: '1px 4px' }}>
                        Seq #{evt.seq}
                      </span>
                      <span style={{ fontSize: '9.5px', color: 'var(--text-dim)' }}>
                        {evt.source_adapter}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
