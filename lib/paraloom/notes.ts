// Local record of the shielded notes this wallet has deposited. Until the
// extension can scan the pool for its own notes (a viewing-key feature), the
// shielded balance is tracked here: the sum of unspent deposits. Each note
// keeps the randomness needed to spend it in a later withdrawal.

export type NoteNetwork = "mainnet-beta" | "devnet"

export const DEFAULT_NOTE_NETWORK: NoteNetwork = "mainnet-beta"

// Spend-key note (circuit v2, #293). The note is bound to the account's spend
// public key (derived from the account seed, not stored here); to spend it the
// wallet supplies that account spend privkey plus this note's `blinding`. The
// nullifier is a signature over the commitment — no per-note secret.
export interface ShieldedNote {
  amount: string // lamports, bigint serialized
  blinding: string // hex, 32 bytes (per-note randomizer)
  assetId: string // hex, 32 bytes (all-zero = native SOL)
  // The SPL mint (base58) for a shielded-token note (#779). Absent for native
  // SOL. Kept alongside `assetId` because assetId = mint_to_asset(mint) is a
  // one-way hash, and spending the note must send the mint to the ingress.
  mint?: string
  signature: string // deposit transaction (empty for discovered transfer notes)
  createdAt: number
  spent: boolean
  // Set for notes discovered by scanning transfer ciphertexts (#196). The
  // commitment is the stable identity for received notes (which have no
  // deposit signature) and the de-dup key when re-scanning.
  commitment?: string
  source?: "deposit" | "transfer"
  // Circuit v3 (#350): the note's position in the on-chain incremental tree,
  // recorded at deposit (from DepositNoteEvent) or located by commitment for
  // received notes. Spending needs it for the membership path.
  leafIndex?: number
  // Solana cluster whose on-chain incremental Merkle tree holds this note.
  // Legacy notes stored before cluster tagging default to "mainnet-beta".
  network?: NoteNetwork
}

export function noteNetwork(note: Pick<ShieldedNote, "network">): NoteNetwork {
  return note.network ?? DEFAULT_NOTE_NETWORK
}

const NOTES_KEY = "paraloom_notes"

type NotesByAccount = Record<string, ShieldedNote[]>

async function readAll(): Promise<NotesByAccount> {
  const stored = await chrome.storage.local.get(NOTES_KEY)
  return (stored[NOTES_KEY] as NotesByAccount) ?? {}
}

async function writeAll(all: NotesByAccount): Promise<void> {
  await chrome.storage.local.set({ [NOTES_KEY]: all })
}

export async function getNotes(
  account: string,
  network: NoteNetwork = DEFAULT_NOTE_NETWORK
): Promise<ShieldedNote[]> {
  const all = await readAll()
  return (all[account] ?? []).filter((n) => noteNetwork(n) === network)
}

export async function addNote(
  account: string,
  note: ShieldedNote,
  network?: NoteNetwork
): Promise<void> {
  const all = await readAll()
  const existing = all[account] ?? []
  const net = network ?? noteNetwork(note)
  const stored = network && !note.network ? { ...note, network } : note
  // Idempotent by (non-empty) deposit signature within the same cluster: the
  // same shielded note can be persisted more than once — the early on-submit
  // persist AND the end-of-flow persist AND the recovery scan all target the
  // same deposit — so dedupe here rather than double-counting the balance.
  if (
    stored.signature &&
    existing.some((n) => noteNetwork(n) === net && n.signature === stored.signature)
  ) {
    return
  }
  all[account] = [...existing, stored]
  await writeAll(all)
}

// Mark the note with this deposit signature as spent (after a withdrawal
// settles), so it no longer counts toward the shielded balance.
export async function markNoteSpent(
  account: string,
  signature: string,
  network: NoteNetwork = DEFAULT_NOTE_NETWORK
): Promise<void> {
  const all = await readAll()
  const notes = all[account] ?? []
  all[account] = notes.map((n) =>
    noteNetwork(n) === network && n.signature === signature ? { ...n, spent: true } : n
  )
  await writeAll(all)
}

// Add a note discovered by scanning transfer ciphertexts (#196), de-duplicated
// by commitment within the same cluster so re-scanning is idempotent.
export async function addDiscoveredNote(
  account: string,
  note: ShieldedNote,
  network?: NoteNetwork
): Promise<void> {
  const all = await readAll()
  const notes = all[account] ?? []
  const net = network ?? noteNetwork(note)
  const stored = network && !note.network ? { ...note, network } : note
  if (
    notes.some(
      (n) => noteNetwork(n) === net && n.commitment && n.commitment === stored.commitment
    )
  ) {
    return
  }
  all[account] = [...notes, stored]
  await writeAll(all)
}

// Fill in a deposit note's on-chain leaf index once it is known. The note is
// persisted at submit time (before the index can be resolved) so its blinding is
// never orphaned (#791); this finalizes it by commitment. A no-op if the note is
// gone. Only writes when the index actually changes, to avoid a redundant store.
export async function setNoteLeafIndex(
  account: string,
  commitment: string,
  leafIndex: number,
  network: NoteNetwork = DEFAULT_NOTE_NETWORK
): Promise<void> {
  const all = await readAll()
  const notes = all[account] ?? []
  let changed = false
  all[account] = notes.map((n) => {
    if (noteNetwork(n) === network && n.commitment === commitment && n.leafIndex !== leafIndex) {
      changed = true
      return { ...n, leafIndex }
    }
    return n
  })
  if (changed) await writeAll(all)
}

// Mark a note spent by its commitment (used for transfer inputs/outputs, which
// are identified by commitment rather than a deposit signature).
export async function markNoteSpentByCommitment(
  account: string,
  commitment: string,
  network: NoteNetwork = DEFAULT_NOTE_NETWORK
): Promise<void> {
  const all = await readAll()
  const notes = all[account] ?? []
  all[account] = notes.map((n) =>
    noteNetwork(n) === network && n.commitment === commitment ? { ...n, spent: true } : n
  )
  await writeAll(all)
}

// Mark exactly the given note spent, by whichever identity is unique to it
// (#718). Deposit notes carry a non-empty `signature` and no `commitment`;
// received and change notes carry a `commitment` and an empty `signature`.
// Matching on `signature` alone flips every empty-signature note at once —
// received and change notes vanish from the balance and re-scan does not bring
// them back — so prefer the commitment, and never match on an empty string.
export async function markNoteSpentByIdentity(
  account: string,
  note: ShieldedNote,
  network?: NoteNetwork
): Promise<void> {
  const net = network ?? noteNetwork(note)
  if (note.commitment) {
    await markNoteSpentByCommitment(account, note.commitment, net)
  } else if (note.signature) {
    await markNoteSpent(account, note.signature, net)
  }
  // A note with neither identity cannot be addressed; leaving it is safe (the
  // on-chain nullifier set is the authoritative double-spend gate) and is not
  // reachable from the current note-creation paths, which always set one.
}

// Native SOL shielded balance, in lamports. SPL notes (#779) are EXCLUDED:
// their `amount` is in the token's own base units (e.g. 6-decimal USDC), so
// summing them as lamports would corrupt the SOL figure. A note is native iff
// it carries no `mint`. Use shieldedTokenBalances() for the SPL side.
export async function shieldedBalance(
  account: string,
  network: NoteNetwork = DEFAULT_NOTE_NETWORK
): Promise<bigint> {
  const notes = await getNotes(account, network)
  return notes
    .filter((n) => !n.spent && !n.mint)
    .reduce((sum, n) => sum + BigInt(n.amount), 0n)
}

// Unspent shielded SPL balances keyed by base58 mint (#779). Each amount is in
// that mint's own base units, kept separate from the native lamports sum.
export async function shieldedTokenBalances(
  account: string,
  network: NoteNetwork = DEFAULT_NOTE_NETWORK
): Promise<Record<string, bigint>> {
  const notes = await getNotes(account, network)
  const byMint: Record<string, bigint> = {}
  for (const n of notes) {
    if (n.spent || !n.mint) continue
    byMint[n.mint] = (byMint[n.mint] ?? 0n) + BigInt(n.amount)
  }
  return byMint
}
