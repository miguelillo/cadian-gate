import { describe, expect, it } from 'vitest';
import { dotsBetween } from './pattern';

// 6×6 grid, row-major indices (index = row*6 + col).
describe('dotsBetween (pattern interpolation)', () => {
  it('returns nothing for adjacent dots', () => {
    expect(dotsBetween(6, 0, 1)).toEqual([]);   // same row, next col
    expect(dotsBetween(6, 0, 6)).toEqual([]);   // next row, same col
    expect(dotsBetween(6, 0, 7)).toEqual([]);   // adjacent diagonal
  });

  it('includes the dot between two horizontally-separated dots', () => {
    expect(dotsBetween(6, 0, 2)).toEqual([1]);
    expect(dotsBetween(6, 0, 5)).toEqual([1, 2, 3, 4]); // whole top row
  });

  it('includes the dot between two vertically-separated dots', () => {
    expect(dotsBetween(6, 0, 12)).toEqual([6]);  // (0,0)→(0,2) crosses (0,1)=6
  });

  it('includes the dot on a diagonal', () => {
    expect(dotsBetween(6, 0, 14)).toEqual([7]);  // (0,0)→(2,2) crosses (1,1)=7
  });

  it('returns nothing for a knight-style move (no dot exactly on the line)', () => {
    expect(dotsBetween(6, 0, 13)).toEqual([]);   // (0,0)→(1,2)
  });

  it('is symmetric in order', () => {
    expect(dotsBetween(6, 2, 0)).toEqual([1]);
    expect(dotsBetween(6, 5, 0)).toEqual([4, 3, 2, 1]);
  });
});
