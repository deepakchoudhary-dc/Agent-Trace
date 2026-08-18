import { Component, ErrorInfo, ReactNode } from 'react';

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  error: Error | null;
}

/**
 * Catches render errors so a crashed view never blanks the dashboard or
 * hides the fact that data could not be displayed.
 */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    console.error('[AgentTrace] Render error:', error, errorInfo);
  }

  render(): ReactNode {
    if (this.state.error) {
      return (
        <div
          style={{
            margin: '16px',
            padding: '20px',
            border: '1px solid var(--border-medium)',
            borderRadius: '10px',
            background: 'var(--bg-card-solid)',
          }}
          role="alert"
        >
          <h3 className="font-heading" style={{ fontSize: '13px', fontWeight: 650 }}>
            View failed to render
          </h3>
          <p style={{ fontSize: '11.5px', color: 'var(--text-muted)', marginTop: '6px' }}>
            {this.state.error.message}
          </p>
          <p style={{ fontSize: '11px', color: 'var(--text-dim)', marginTop: '8px' }}>
            This does not affect the sealed audit ledger — restart the view or refresh to
            retry.
          </p>
        </div>
      );
    }
    return this.props.children;
  }
}