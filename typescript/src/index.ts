/**
 * @algovoi/journey-ref — content-addressed journey references (commercial, unpublished).
 *
 *   journeyRef = "sha256:" + SHA-256(JCS({ delegations, hops, journey_outcome }))
 *
 * A journey_ref binds a whole multi-agent task into one reference: every hop's execution plus the
 * delegations between them, with a closed outcome. hops and delegations are ordered lists of
 * "sha256:"-prefixed refs.
 *
 * Construction only; the end-to-end PROOF (continuity, scope never widened, nothing under a revoked
 * grant, no hop omitted) is the private AlgoVoi Orchestrator. Byte-identical to algovoi-journey-ref
 * (Python). Commercial AlgoVoi licence, not published.
 */
import canonicalize from 'canonicalize';
import { createHash } from 'node:crypto';

export const SHA256_PREFIX = 'sha256:' as const;
export const OUTCOMES = ['COMPLETE', 'PARTIAL', 'ABORTED'] as const;
const REF_RE = /^sha256:[0-9a-f]{64}$/;

export class JourneyRefError extends Error {}

export interface JourneyEnvelope {
  hops: string[];
  delegations?: string[];
  journey_outcome: (typeof OUTCOMES)[number];
}

function reflist(val: unknown, name: string, allowEmpty: boolean): string[] {
  if (!Array.isArray(val)) throw new JourneyRefError(`${name} must be a list of refs`);
  if (!allowEmpty && val.length === 0) throw new JourneyRefError(`${name} must be non-empty`);
  for (const r of val) {
    if (typeof r !== 'string' || !REF_RE.test(r)) throw new JourneyRefError(`${name} entries must be "sha256:"-prefixed 64-hex refs`);
  }
  return val as string[];
}

export function journeyRef(env: Record<string, unknown>): string {
  const hops = reflist(env.hops, 'hops', false);
  const delegations = reflist(env.delegations ?? [], 'delegations', true);
  const outcome = env.journey_outcome;
  if (typeof outcome !== 'string' || !OUTCOMES.includes(outcome as never)) throw new JourneyRefError(`journey_outcome must be one of ${OUTCOMES.join(', ')}`);
  const s = canonicalize({ delegations, hops, journey_outcome: outcome });
  if (s === undefined) throw new JourneyRefError('envelope is not JCS-canonicalisable');
  return SHA256_PREFIX + createHash('sha256').update(s).digest('hex');
}

export function tamperDetected(claimedRef: string, env: Record<string, unknown>): boolean {
  try { return journeyRef(env) !== claimedRef; } catch { return true; }
}
