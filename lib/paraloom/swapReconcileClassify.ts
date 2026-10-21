// Pure classification for the swap reconciler, split out so it carries no heavy
// imports (prover / wasm) and can be unit-tested in isolation. See
// swapReconcile.ts for how each verdict is acted on.

// A swap younger than this may still be in flight; do not touch it. Matches the
// page-side swap timeout budget with headroom.
export const RESUME_GRACE_MS = 120_000
// Minimum SOL balance required at a fresh address to route a Jupiter swap leg
// (mirrors SWAP_OVERHEAD_LAMPORTS in privateSwap).
export const RESUME_MIN_LAMPORTS = 6_000_000n
export const SWAP_OVERHEAD_LAMPORTS = 6_000_000n
// Lamports reserved at a fresh address to pay the deposit_note transaction fee
// when sweeping SOL back into the shielded pool (well above the 890,880-lamport
// rent-exempt floor).
export const RESHIELD_FEE_RESERVE_LAMPORTS = 1_000_000n
// Protocol withdrawal fee (25 bps = 0.25%) deducted on-chain by transact withdraw.
export const WITHDRAWAL_FEE_BPS = 25n
// Smallest gross SOL withdrawal (6,015,038 lamports = 0.006015038 SOL) whose net
// payout after the 25 bps protocol withdrawal fee (6,000,001 lamports) strictly
// exceeds SWAP_OVERHEAD_LAMPORTS (6,000,000 lamports).
export const MIN_SOL_SWAP_WITHDRAW_LAMPORTS = 6_015_038n

/** Net lamports delivered to the fresh address after the on-chain 25 bps
 *  protocol withdrawal fee (`fee = (amount * 25) / 10_000`). */
export function expectedNetWithdrawLamports(amountLamports: bigint): bigint {
  if (amountLamports <= 0n) return 0n
  const fee = (amountLamports * WITHDRAWAL_FEE_BPS) / 10_000n
  return amountLamports - fee
}

/** True when a stranded fresh address holds too little SOL to execute a swap leg
 *  (`<= RESUME_MIN_LAMPORTS`) and no output token (`tokenAmount === 0n`), but
 *  holds enough SOL above `RESHIELD_FEE_RESERVE_LAMPORTS` (`1_000_000n`) to be
 *  swept back into the user's shielded pool via `depositV3`. */
export function isSubReserveRecoverableSol(
  solLamports: bigint,
  tokenAmount: bigint
): boolean {
  return (
    tokenAmount === 0n &&
    solLamports > RESHIELD_FEE_RESERVE_LAMPORTS &&
    solLamports <= RESUME_MIN_LAMPORTS
  )
}

/** Wrapped-SOL mint. The swaps app sends this as `outputMint` for a SOL output
 *  (not the literal "SOL"), and Jupiter unwraps it to native SOL on the way out.
 *  Both spellings must count as native SOL so a token->SOL round trip re-shields
 *  a native note (and displays as SOL) instead of mis-handling it as an SPL. */
export const WSOL_MINT = "So11111111111111111111111111111111111111112"

/** True when `outputMint` denotes native SOL (the literal "SOL" or the wrapped
 *  mint). Kept here (no heavy imports) so it is unit-testable. */
export function isNativeSolOutput(mint: string): boolean {
  return mint === "SOL" || mint === WSOL_MINT
}

export type StrandAction = "skip" | "resume" | "landed" | "unresolved"

/// Decide what to do with a stranded swap row from its on-chain footprint.
///  - skip:       already recorded, or still inside the in-flight grace window.
///  - resume:     the fresh address holds swappable SOL → finish the swap leg.
///  - landed:     SOL is gone but the bought token sits there → record it done.
///  - unresolved: nothing recoverable → leave for the user to dismiss manually.
export function classifyStrand(args: {
  hasSignature: boolean
  ageMs: number
  solLamports: bigint
  tokenAmount: bigint
}): StrandAction {
  if (args.hasSignature) return "skip"
  if (args.ageMs < RESUME_GRACE_MS) return "skip"
  if (args.solLamports > RESUME_MIN_LAMPORTS) return "resume"
  if (args.tokenAmount > 0n) return "landed"
  return "unresolved"
}
