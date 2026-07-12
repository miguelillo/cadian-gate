function gcd(a: number, b: number): number { return b === 0 ? a : gcd(b, a % b); }

// Grid dots lying exactly on the straight segment between two dots (exclusive
// of the endpoints), in order from `a` to `b`. This is the Android-style rule
// that makes pattern capture reproducible: dragging from A to B always includes
// the dots the line crosses, regardless of how fast the pointer moved.
//
// Dots are row-major indices on a `size`×`size` grid (index = row*size + col).
export function dotsBetween(size: number, a: number, b: number): number[] {
  const ax = a % size, ay = Math.floor(a / size);
  const bx = b % size, by = Math.floor(b / size);
  const dx = bx - ax, dy = by - ay;
  const g = gcd(Math.abs(dx), Math.abs(dy));
  if (g <= 1) return []; // adjacent or knight-style move — no dot exactly on the line
  const sx = dx / g, sy = dy / g;
  const out: number[] = [];
  for (let i = 1; i < g; i++) out.push((ay + sy * i) * size + (ax + sx * i));
  return out;
}
