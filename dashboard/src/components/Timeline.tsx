import React, { useState, useEffect, useMemo } from 'react';
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
  FileEdit,
  Globe,
  AlertTriangle,
  CheckCircle2,
  GitCommit,
} from 'lucide-react';

interface TimelineProps {
  events: TimelineEvent[];
  onSelectEvent?: (event: TimelineEvent) => void;
}

const getEventIcon = (eventType: string) => {
  const t = eventType.toLowerCase();
  if (t.includes('invocation') || t.includes('session')) return <Cpu size={12} color="#ffffff" />;
  if (t.includes('tool')) return <Activity size={12} color="#ffffff" />;
  if (t.includes('command') || t.includes('process')) return <Terminal size={12} color="#ffffff" />;
  if (t.includes('file') || t.includes('mutation') || t.includes('git')) return <FileEdit size={12} color="#ffffff" />;
  if (t.includes('network')) return <Globe size={12} color="#ffffff" />;
  if (t.includes('finding') || t.includes('incident')) return <AlertTriangle size={12} color="#ffffff" />;
  if (t.includes('test') || t.includes('build')) return <CheckCircle2 size={12} color="#ffffff" />;
  if (t.includes('approval')) return <Shield size={12} color="#ffffff" />;
  return <GitCommit size={12} color="#a1a1aa" />;
};

const getActorIcon = (actorId: string) => {
  if (actorId.toLowerCase().includes('user')) return <User size={14} color="#ffffff" />;
  if (/(codex|claude|copilot|agent)/i.test(actorId)) return <Cpu size={14} color="#ffffff" />;
  if (/(terminal|process)/i.test(actorId)) return <Terminal size={14} color="#ffffff" />;
  return <Shield size={14} color="#ffffff" />;
};

export const Timeline: React.FC<TimelineProps> = ({ events, onSelectEvent }) => {
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentIndex, setCurrentIndex] = useState(0);
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
  const actors = useMemo(() => Array.from(new Set(events.map((e) => e.actor_id))), [events]);

  const safeIndex = events.length > 0 ? Math.min(currentIndex, events.length - 1) : 0;
  const visibleEvents = events.slice(0, safeIndex + 1);
  const progress = events.length > 0 ? ((safeIndex + 1) / events.length) * 100 : 0;

  if (events.length === 0) {
    return (
      <div className="glass-panel" style={{ margin: '0 16px 16px 16px', height: 'calc(100vh - 120px)' }}>
        <div className="empty-state">
          <Activity size={36} color="var(--border-medium)" />
          <h3 className="font-heading" style={{ fontSize: '15px', color: 'var(--text-muted)' }}>
            No Events Ingested in Current Session
          </h3>
          <p style={{ fontSize: '12px' }}>
            Execute commands or start an agent audit to capture hash-chained events.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="glass-panel" style={{ margin: '0 16px 16px 16px', display: 'flex', flexDirection: 'column', height: 'calc(100vh - 120px)', overflow: 'hidden' }}>
      {/* Playback Controls Header */}
      <div className="panel-header" style={{ flexWrap: 'wrap' }}>
        <div className="flex" style={{ gap: '10px' }}>
          <button
            onClick={() => setIsPlaying(!isPlaying)}
            className="btn btn-primary btn-sm"
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
            className="btn btn-secondary btn-icon"
            title="Reset to beginning"
            aria-label="Reset timeline to start"
          >
            <RotateCcw size={13} />
          </button>

          <div className="seg">
            <span className="flex" style={{ gap: '3px', padding: '0 4px', fontSize: '10.5px', color: 'var(--text-muted)' }}>
              Speed
            </span>
            {[1, 2, 4].map((s) => (
              <button
                key={s}
                onClick={() => setSpeed(s)}
                className={`seg-btn ${speed === s ? 'seg-btn--active' : ''}`}
                aria-pressed={speed === s}
              >
                {s}x
              </button>
            ))}
          </div>
        </div>

        {/* Timeline Scrubber */}
        <div className="flex" style={{ gap: '10px', flex: 1, maxWidth: '460px', minWidth: '220px' }}>
          <span className="font-mono" style={{ fontSize: '11px', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
            {safeIndex + 1} / {events.length}
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
            style={{ flex: 1, ['--range-progress' as string]: `${progress}%` }}
          />
        </div>
      </div>

      {/* Actor Lanes & Events */}
      <div className="scroll-thin" style={{ flex: 1, overflowY: 'auto', padding: '16px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
        {actors.map((actor) => {
          const actorEvents = visibleEvents.filter((e) => e.actor_id === actor);
          if (actorEvents.length === 0) return null;

          return (
            <div key={actor} style={{ background: 'var(--bg-card-solid)', padding: '14px', borderRadius: '10px', border: '1px solid var(--border-dim)' }}>
              {/* Actor Header */}
              <div className="flex-between" style={{ marginBottom: '10px' }}>
                <div className="flex" style={{ gap: '8px' }}>
                  {getActorIcon(actor)}
                  <span className="font-heading" style={{ fontSize: '13px', fontWeight: 650, color: '#ffffff' }}>
                    {actor}
                  </span>
                </div>
                <span className="chip">{actorEvents.length} events</span>
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
                    className="card card--clickable"
                    style={{ padding: '9px 11px', display: 'flex', flexDirection: 'column', gap: '5px' }}
                  >
                    <div className="flex-between">
                      <span className="flex" style={{ gap: '6px' }}>
                        {getEventIcon(evt.event_type)}
                        <span className="font-mono" style={{ fontSize: '9.5px', color: '#ffffff', fontWeight: 650 }}>
                          {evt.event_type.toUpperCase()}
                        </span>
                      </span>
                      <span style={{ fontSize: '9.5px', color: 'var(--text-dim)', fontVariantNumeric: 'tabular-nums' }}>
                        {new Date(evt.timestamp).toLocaleTimeString()}
                      </span>
                    </div>

                    <div className="font-mono" style={{ fontSize: '9.5px', color: 'var(--text-muted)', wordBreak: 'break-all' }}>
                      {evt.event_hash.slice(0, 16)}…
                    </div>

                    <div className="flex-between" style={{ marginTop: '2px' }}>
                      <span className="badge badge-high" style={{ fontSize: '7.5px', padding: '1px 5px' }}>
                        Seq #{evt.seq}
                      </span>
                      <span style={{ fontSize: '9px', color: 'var(--text-dim)' }}>{evt.source_adapter}</span>
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
