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
} from 'lucide-react';

interface TimelineProps {
  events: TimelineEvent[];
  onSelectEvent?: (event: TimelineEvent) => void;
}

export const Timeline: React.FC<TimelineProps> = ({ events, onSelectEvent }) => {
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentIndex, setCurrentIndex] = useState(events.length - 1);
  const [speed, setSpeed] = useState(1);

  // Playback timer
  useEffect(() => {
    let timer: any;
    if (isPlaying) {
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
    return () => clearInterval(timer);
  }, [isPlaying, events.length, speed]);

  // Group events by actor lane
  const actors = Array.from(new Set(events.map((e) => e.actor_id)));

  const getActorIcon = (actorId: string) => {
    if (actorId.includes('user')) return <User size={14} color="#06b6d4" />;
    if (actorId.includes('codex') || actorId.includes('claude') || actorId.includes('copilot'))
      return <Cpu size={14} color="#a855f7" />;
    if (actorId.includes('terminal') || actorId.includes('process'))
      return <Terminal size={14} color="#3b82f6" />;
    return <Shield size={14} color="#10b981" />;
  };

  const visibleEvents = events.slice(0, currentIndex + 1);

  return (
    <div className="glass-panel" style={{ margin: '0 16px 16px 16px', display: 'flex', flexDirection: 'column', height: 'calc(100vh - 120px)', overflow: 'hidden' }}>
      {/* Playback Controls Header */}
      <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border-dim)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <button
            onClick={() => setIsPlaying(!isPlaying)}
            className="btn btn-primary"
            style={{ padding: '6px 14px' }}
          >
            {isPlaying ? <Pause size={14} /> : <Play size={14} />}
            {isPlaying ? 'Pause' : 'Play Timeline'}
          </button>

          <button
            onClick={() => {
              setIsPlaying(false);
              setCurrentIndex(0);
            }}
            className="btn btn-secondary"
            title="Reset"
          >
            <RotateCcw size={14} />
          </button>

          <div style={{ display: 'flex', alignItems: 'center', gap: '4px', background: 'var(--bg-input)', padding: '2px 6px', borderRadius: '6px', border: '1px solid var(--border-dim)' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Speed:</span>
            {[1, 2, 4].map((s) => (
              <button
                key={s}
                onClick={() => setSpeed(s)}
                style={{
                  background: speed === s ? 'var(--accent-cyan)' : 'transparent',
                  color: speed === s ? '#000' : 'var(--text-main)',
                  border: 'none',
                  borderRadius: '4px',
                  padding: '2px 6px',
                  fontSize: '11px',
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
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: 1, maxWidth: '480px' }}>
          <span className="font-mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            Step {currentIndex + 1} / {events.length}
          </span>
          <input
            type="range"
            min="0"
            max={events.length - 1}
            value={currentIndex}
            onChange={(e) => {
              setIsPlaying(false);
              setCurrentIndex(parseInt(e.target.value, 10));
            }}
            style={{
              flex: 1,
              accentColor: 'var(--accent-cyan)',
              cursor: 'pointer',
            }}
          />
        </div>
      </div>

      {/* Actor Lanes & Events */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '20px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
        {actors.map((actor) => {
          const actorEvents = visibleEvents.filter((e) => e.actor_id === actor);
          if (actorEvents.length === 0) return null;

          return (
            <div key={actor} style={{ background: 'rgba(0,0,0,0.2)', padding: '16px', borderRadius: '10px', border: '1px solid var(--border-dim)' }}>
              {/* Actor Header */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
                {getActorIcon(actor)}
                <span className="font-heading" style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-main)' }}>
                  {actor}
                </span>
                <span className="badge badge-high" style={{ fontSize: '9px' }}>
                  {actorEvents.length} events
                </span>
              </div>

              {/* Event Cards in Lane */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '10px' }}>
                {actorEvents.map((evt) => (
                  <div
                    key={evt.event_id}
                    onClick={() => onSelectEvent && onSelectEvent(evt)}
                    style={{
                      background: 'var(--bg-card)',
                      border: '1px solid var(--border-dim)',
                      borderRadius: '8px',
                      padding: '10px 12px',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '4px',
                      cursor: 'pointer',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <span className="font-mono" style={{ fontSize: '10px', color: 'var(--accent-cyan)', fontWeight: 600 }}>
                        {evt.event_type.toUpperCase()}
                      </span>
                      <span style={{ fontSize: '10px', color: 'var(--text-dim)' }}>
                        {new Date(evt.timestamp).toLocaleTimeString()}
                      </span>
                    </div>

                    <div className="font-mono" style={{ fontSize: '11px', color: 'var(--text-muted)', wordBreak: 'break-all' }}>
                      Hash: {evt.event_hash.slice(0, 16)}...
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '4px', marginTop: '2px' }}>
                      <span className="badge badge-high" style={{ fontSize: '8px', padding: '1px 4px' }}>
                        Seq #{evt.seq}
                      </span>
                      <span style={{ fontSize: '10px', color: 'var(--text-dim)' }}>
                        Adapter: {evt.source_adapter}
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
