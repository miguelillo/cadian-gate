import { useEffect, useRef, useState, type PointerEvent as ReactPointerEvent } from 'react';
import { dotsBetween } from '../services/pattern';
import styles from './PatternPad.module.css';

interface Props {
  size?: number;                       // grid dimension (default 6 → 6×6)
  onChange: (sequence: number[]) => void;
  disabled?: boolean;
}

// Phone-unlock-style pattern input. The user drags across dots on a size×size
// grid; the ordered list of visited dot indices is emitted (0-based, row-major).
export default function PatternPad({ size = 6, onChange, disabled }: Props) {
  const [seq, setSeq] = useState<number[]>([]);
  const [drawing, setDrawing] = useState(false);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const cb = useRef(onChange);
  cb.current = onChange;

  const N = size * size;
  const cell = 100 / size;
  const pos = (i: number) => ({ x: (i % size + 0.5) * cell, y: (Math.floor(i / size) + 0.5) * cell });

  useEffect(() => { cb.current(seq); }, [seq]);

  // iOS Safari ignores touch-action on SVG and hijacks the drag for page
  // scrolling (firing pointercancel mid-stroke). Blocking the native touch
  // events non-passively is the only reliable way to keep the gesture —
  // React's own onTouch* handlers are passive, so it must be done here.
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    const block = (e: TouchEvent) => e.preventDefault();
    svg.addEventListener('touchstart', block, { passive: false });
    svg.addEventListener('touchmove', block, { passive: false });
    return () => {
      svg.removeEventListener('touchstart', block);
      svg.removeEventListener('touchmove', block);
    };
  }, []);

  function nodeAt(clientX: number, clientY: number): number | null {
    const svg = svgRef.current;
    if (!svg) return null;
    const r = svg.getBoundingClientRect();
    const x = ((clientX - r.left) / r.width) * 100;
    const y = ((clientY - r.top) / r.height) * 100;
    const hit = cell * 0.42;
    for (let i = 0; i < N; i++) {
      const p = pos(i);
      if (Math.hypot(p.x - x, p.y - y) <= hit) return i;
    }
    return null;
  }

  function down(e: ReactPointerEvent<SVGSVGElement>) {
    if (disabled) return;
    e.preventDefault();
    // Capture can throw / silently fail on SVG in some WebKit versions;
    // the touch-event blocking above keeps the stroke alive regardless.
    try { svgRef.current?.setPointerCapture(e.pointerId); } catch { /* ignore */ }
    setDrawing(true);
    const n = nodeAt(e.clientX, e.clientY);
    setSeq(n === null ? [] : [n]);
  }
  function move(e: ReactPointerEvent<SVGSVGElement>) {
    if (!drawing) return;
    const n = nodeAt(e.clientX, e.clientY);
    if (n === null) return;
    setSeq(prev => {
      if (prev.includes(n)) return prev;
      const last = prev[prev.length - 1];
      const mids = last === undefined ? [] : dotsBetween(size, last, n).filter(m => !prev.includes(m));
      return [...prev, ...mids, n];
    });
  }
  function up() { setDrawing(false); }

  // If pointer capture failed (WebKit/SVG), a finger lifted outside the pad
  // never delivers pointerup to the SVG — catch it at the window instead.
  useEffect(() => {
    if (!drawing) return;
    const end = () => setDrawing(false);
    window.addEventListener('pointerup', end);
    window.addEventListener('pointercancel', end);
    return () => {
      window.removeEventListener('pointerup', end);
      window.removeEventListener('pointercancel', end);
    };
  }, [drawing]);

  const line = seq.map(i => { const p = pos(i); return `${p.x},${p.y}`; }).join(' ');
  const last = seq.length ? pos(seq[seq.length - 1]) : null;

  return (
    <div className={styles.wrap}>
      <svg
        ref={svgRef}
        viewBox="0 0 100 100"
        className={`${styles.pad}${disabled ? ` ${styles.disabled}` : ''}`}
        onPointerDown={down}
        onPointerMove={move}
        onPointerUp={up}
        onPointerCancel={up}
        role="application"
        aria-label={`${size} by ${size} unlock pattern`}
      >
        {seq.length > 1 && <polyline className={styles.trail} points={line} />}
        {Array.from({ length: N }, (_, i) => {
          const p = pos(i);
          const order = seq.indexOf(i);
          const on = order !== -1;
          return (
            <g key={i}>
              <circle cx={p.x} cy={p.y} r={cell * 0.14} className={`${styles.dot}${on ? ` ${styles.dotOn}` : ''}`} />
              {on && <circle cx={p.x} cy={p.y} r={cell * 0.3} className={styles.halo} />}
            </g>
          );
        })}
        {last && (
          <>
            <circle cx={last.x} cy={last.y} r={cell * 0.3} className={styles.ring} />
            <circle cx={last.x} cy={last.y} r={cell * 0.06} className={styles.head} />
          </>
        )}
      </svg>
      <div className={styles.meta}>
        <span>{seq.length === 0 ? 'DRAW YOUR PATTERN' : `${seq.length} DOT${seq.length === 1 ? '' : 'S'}`}</span>
        {seq.length > 0 && !disabled && (
          <button type="button" className={styles.clear} onClick={() => setSeq([])}>CLEAR</button>
        )}
      </div>
    </div>
  );
}
