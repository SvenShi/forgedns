import React, {type ReactNode, useEffect, useRef, useState} from 'react';

type ReleaseCardProps = {
  version: string;
  badge: string;
  date: string;
  defaultOpen?: boolean;
  children: ReactNode;
};

export default function ReleaseCard({
  version,
  badge,
  date,
  defaultOpen = false,
  children,
}: ReleaseCardProps) {
  const [open, setOpen] = useState(defaultOpen);
  const [contentHeight, setContentHeight] = useState(defaultOpen ? 'none' : '0px');
  const contentRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const node = contentRef.current;
    if (!node) return;

    if (open) {
      const nextHeight = `${node.scrollHeight}px`;
      setContentHeight(nextHeight);
      const timer = window.setTimeout(() => {
        setContentHeight('none');
      }, 420);
      return () => window.clearTimeout(timer);
    }

    if (contentHeight === 'none') {
      const currentHeight = `${node.scrollHeight}px`;
      setContentHeight(currentHeight);
      requestAnimationFrame(() => setContentHeight('0px'));
      return;
    }

    setContentHeight('0px');
  }, [open]);

  return (
    <div className={`release-card${open ? ' release-card--open' : ''}`}>
      <h3 className="release-anchor">{version}</h3>
      <button
        type="button"
        className="release-card__header"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        aria-controls={`${version}-panel`}
      >
        <span className="release-card__main">
          <span className="release-card__version">{version}</span>
          <span className="release-card__badge">{badge}</span>
        </span>
        <span className="release-card__date">{date}</span>
        <span className="release-card__chevron" aria-hidden="true" />
      </button>
      <div
        id={`${version}-panel`}
        className="release-card__panel"
        style={{maxHeight: contentHeight}}
      >
        <div ref={contentRef} className="release-card__body">
          {children}
        </div>
      </div>
    </div>
  );
}
