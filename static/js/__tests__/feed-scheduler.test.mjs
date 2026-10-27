import test from 'node:test';
import assert from 'node:assert/strict';
import { intervalFor, isActive } from '../feed-scheduler.js';

test('intervalFor returns 6000ms when reduced motion is preferred', () => {
  assert.equal(intervalFor(true), 6000);
});

test('intervalFor returns 2400ms under standard motion conditions', () => {
  assert.equal(intervalFor(false), 2400);
});

test('isActive returns false when document visibilityState is hidden', () => {
  const fakeDoc = { visibilityState: 'hidden' };
  const fakeEl = { offsetParent: {} };
  assert.equal(isActive(fakeEl, fakeDoc), false);
});

test('isActive returns false when element is hidden with display: none (offsetParent is null)', () => {
  const fakeDoc = { visibilityState: 'visible' };
  const fakeEl = { offsetParent: null };
  assert.equal(isActive(fakeEl, fakeDoc), false);
});

test('isActive returns true when document is visible and element is rendered', () => {
  const fakeDoc = { visibilityState: 'visible' };
  const fakeEl = { offsetParent: {} };
  assert.equal(isActive(fakeEl, fakeDoc), true);
});
