/**
 * Pending redemptions (docs/account.md, "Confirmed on this PC"): a code redeemed on a PC with screen proof admits
 * nobody. The device names its key first; only then does the PC make a challenge, so the key cannot be chosen to show
 * a wanted fingerprint. The device proves the key over that challenge once, and waits in memory until the PC's screen
 * approves that one key by its fingerprint, declines it, or it runs out. A restart ends them all.
 */
import { randomBytes } from "node:crypto";
import { pairChallenge, pairFingerprint, verifyPairProof } from "../../shared/pair-fingerprint.ts";

export const PENDING_MS = 5 * 60_000;
export const PENDING_PER_CODE = 5;
export const PENDING_TOTAL = 8;

/** How the redeemer reached the PC: through the relay, or at this PC's own address. */
export type PendingVia = "relay" | "address";

export interface PendingRedemption {
  readonly id: string;
  readonly code: string;
  readonly label: string;
  readonly key: string;
  readonly fingerprint: string;
  readonly via: PendingVia;
  readonly redeemedAt: number;
}

interface Named { code: string; label: string; key: string; via: PendingVia; at: number }

export class PendingLimitError extends Error {}

export class PendingRedemptions {
  readonly #serverId: string;
  readonly #now: () => number;
  readonly #journalDrop: (entry: { key: string; label: string; reason: string }) => void;
  /** challenges sent and not yet answered, each for the one key named before it was made */
  readonly #named = new Map<string, Named>();
  readonly #waiting = new Map<string, PendingRedemption>();

  constructor(options: { serverId: string; now?: () => number; journalDrop(entry: { key: string; label: string; reason: string }): void }) {
    this.#serverId = options.serverId;
    this.#now = options.now ?? Date.now;
    this.#journalDrop = options.journalDrop;
  }

  /**
   * A device named its key for `code`: a fresh challenge for that key alone. Naming a key again (`previous`) spends the
   * challenge it had, so a key changed after a challenge was seen starts over with a new one.
   */
  name(code: string, label: string, key: string, via: PendingVia, previous?: string): { challenge: string } {
    this.#sweep();
    if (previous !== undefined) this.#named.delete(previous);
    const forCode = [...this.#waiting.values(), ...this.#named.values()].filter((entry) => entry.code === code).length;
    if (forCode >= PENDING_PER_CODE) throw new PendingLimitError("This code has as many devices waiting as it may");
    if (this.#waiting.size + this.#named.size >= PENDING_TOTAL) throw new PendingLimitError("As many devices wait for this PC's screen as may");
    const challenge = pairChallenge();
    this.#named.set(challenge, { code, label, key, via, at: this.#now() });
    return { challenge };
  }

  /** The device's proof over its challenge; the challenge is spent by any answer, right or wrong. */
  async prove(challenge: string, signature: string): Promise<PendingRedemption | null> {
    this.#sweep();
    const named = this.#named.get(challenge);
    this.#named.delete(challenge);
    if (named === undefined || !await verifyPairProof(this.#serverId, challenge, named.key, signature)) return null;
    const entry: PendingRedemption = Object.freeze({
      id: randomBytes(16).toString("hex"), code: named.code, label: named.label, key: named.key, via: named.via, redeemedAt: this.#now(),
      fingerprint: await pairFingerprint(this.#serverId, challenge, named.key),
    });
    this.#waiting.set(entry.id, entry);
    return entry;
  }

  list(): PendingRedemption[] {
    this.#sweep();
    return [...this.#waiting.values()];
  }

  /** The screen's approval of `id` by the fingerprint it showed: the redemption, taken out, or null. */
  take(id: string, fingerprint: string): PendingRedemption | null {
    this.#sweep();
    const entry = this.#waiting.get(id);
    if (entry === undefined || entry.fingerprint !== fingerprint) return null;
    this.#waiting.delete(id);
    return entry;
  }

  decline(id: string): void {
    this.#drop((entry) => entry.id === id, "declined");
  }

  /** A removal, block or Revoke of `key` drops what waits for it. */
  dropKey(key: string, reason: string): void {
    this.#drop((entry) => entry.key === key, reason);
  }

  dropCode(code: string): void {
    for (const [challenge, named] of this.#named) if (named.code === code) this.#named.delete(challenge);
    this.#drop((entry) => entry.code === code, "code_ended");
  }

  #drop(which: (entry: PendingRedemption) => boolean, reason: string): void {
    for (const entry of [...this.#waiting.values()]) {
      if (!which(entry)) continue;
      this.#waiting.delete(entry.id);
      this.#journalDrop({ key: entry.key, label: entry.label, reason });
    }
  }

  #sweep(): void {
    const now = this.#now();
    for (const [challenge, named] of this.#named) if (now - named.at >= PENDING_MS) this.#named.delete(challenge);
    this.#drop((entry) => now - entry.redeemedAt >= PENDING_MS, "expired");
  }
}
