/**
 * Standard Data Source Provenance Contract.
 * Every response explicitly declares its source:
 * - 'live' : Direct physical measurement or real-time API call
 * - 'cache': In-memory or database cached real measurement
 * - 'unavailable': Provider could not be contacted or measurement impossible
 * - 'unsupported': Feature not supported on the current operating system / environment
 */
export type Provenance = 'live' | 'cache' | 'unavailable' | 'unsupported';

export interface Sourced<T> {
  source: Provenance;
  provider?: string;
  fetchedAt: string;
  data: T | null;
  reason?: string;
  simulated?: boolean;
}

export const ok = <T>(data: T, provider: string, source: Provenance = 'live'): Sourced<T> => ({
  source,
  provider,
  fetchedAt: new Date().toISOString(),
  data,
  simulated: process.env.DEMO_MODE === 'true',
});

export const none = (reason: string, source: Provenance = 'unavailable'): Sourced<null> => ({
  source,
  fetchedAt: new Date().toISOString(),
  data: null,
  reason,
  simulated: process.env.DEMO_MODE === 'true',
});
