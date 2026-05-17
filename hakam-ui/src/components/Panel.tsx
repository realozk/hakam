import React from 'react';

interface Props {
  label: string;
  tag?: string;
  /** Optional buttons rendered on the right side of the header. */
  actions?: React.ReactNode;
  children: React.ReactNode;
  /** Set true if children should scroll when they overflow vertically. */
  scrollable?: boolean;
  className?: string;
  style?: React.CSSProperties;
}

export const Panel: React.FC<Props> = ({
  label, tag, actions, children, scrollable, className = '', style,
}) => {
  return (
    <div className={`hk-panel ${className}`} style={style}>
      <div className="hk-panel-label">
        <span>{label}</span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-2)' }}>
          {tag && (
            <span style={{ color: 'var(--accent)', fontSize: 8, letterSpacing: '0.14em' }}>
              {tag}
            </span>
          )}
          {actions}
        </div>
      </div>
      <div className={`hk-panel-content ${scrollable ? 'is-scrollable' : ''}`}>
        {children}
      </div>
    </div>
  );
};
