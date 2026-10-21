// Recipient discovery is the one place the wallet stores a note it did not
// create, from a payload a stranger can produce: the box public key that gates
// decryption is the public half of the shielded address, so anyone who knows an
// address can seal a ciphertext to it claiming any amount. #196 is the defence
// — recompute the commitment under OUR spend key and drop the note unless it
// matches the leaf it was delivered with.
//
// Every rejection path here is a silent `continue`, and that is correct: a
// stranger's note and a crafted note both have to look like "nothing for you".
// It also means a regression is silent — the balance is simply wrong, and
// #196's phantom notes were unspendable, so the wallet would brick on the next
// transfer with nothing pointing back at the scan.
//
// The prover is mocked because the wasm binary is a build input that is not in
// the repo. These tests therefore pin the control flow — that the commitment is
// recomputed, that it is recomputed under this wallet's own spend key, and that
// a mismatch drops the note — and not Poseidon itself. A test that the real
// hash is correct would need the prover artifacts.

import { PublicKey } from "@solana/web3.js"
import { encryptNote } from "~lib/paraloom/noteCrypto"
import {
  getNotes,
  markNoteSpentByIdentity,
  shieldedBalance,
  shieldedTokenBalances
} from "~lib/paraloom/notes"
import { scanForNotes } from "~lib/paraloom/scan"
import * as nacl from "tweetnacl"
import { beforeEach, describe, expect, it, vi } from "vitest"
import { installFakeChrome } from "./support/chromeStorage"

// Deterministic stand-ins for the circuit hashes, in `vi.hoisted` so they exist
// before the hoisted `vi.mock` factory runs. They depend on all of their
// inputs, so a note whose amount, blinding or asset does not match its
// commitment is a mismatch here for the same reason it would be under Poseidon.
const {
  assetIdForMint,
  fakeAssetCommitment,
  fakeCommitment,
  fakeAssetIdForMint,
  v3NoteCommitment,
  v3NoteCommitmentAsset,
  v3NotePubkey
} = vi.hoisted(() => {
  const fakeCommitment = (amount: bigint, pubkeyHex: string, blindingHex: string) =>
    `c${amount.toString(16)}_${pubkeyHex.slice(0, 8)}_${blindingHex.slice(0, 8)}`
  // A DIFFERENT function, not the native one with an extra argument, so a note
  // verified with the wrong one never matches.
  const fakeAssetCommitment = (
    amount: bigint,
    pubkeyHex: string,
    blindingHex: string,
    assetIdHex: string
  ) => `${fakeCommitment(amount, pubkeyHex, blindingHex)}@${assetIdHex.slice(0, 8)}`
  // `mint_to_asset` is one-way; this stand-in is too, and it keeps the 32-byte
  // hex shape the note plaintext requires.
  const fakeAssetIdForMint = (mintHex: string) =>
    (mintHex.match(/../g) ?? [])
      .map((b) => (parseInt(b, 16) ^ 0x5a).toString(16).padStart(2, "0"))
      .join("")

  return {
    fakeCommitment,
    fakeAssetCommitment,
    fakeAssetIdForMint,
    v3NoteCommitment: vi.fn(async (a: bigint, p: string, b: string) => fakeCommitment(a, p, b)),
    v3NoteCommitmentAsset: vi.fn(async (a: bigint, p: string, b: string, s: string) =>
      fakeAssetCommitment(a, p, b, s)
    ),
    v3NotePubkey: vi.fn(async (privkeyHex: string) => `pub_${privkeyHex}`),
    // Throws the way the real one does. `assetIdForMint` reaches wasm `hex32`,
    // which returns Err — a thrown JsValue — rather than a wrong answer, and the
    // mint it is handed comes from the node. A mock that quietly hashes anything
    // cannot tell us what happens when a malformed one arrives.
    assetIdForMint: vi.fn(async (mintHex: string) => {
      if (!/^[0-9a-fA-F]*$/.test(mintHex.trim())) throw new Error("bad hex")
      if (mintHex.trim().length !== 64) throw new Error("expected 32-byte hex")
      return fakeAssetIdForMint(mintHex)
    })
  }
})

vi.mock("~lib/prover", () => ({
  v3NoteCommitment,
  v3NoteCommitmentAsset,
  v3NotePubkey,
  assetIdForMint,
  NATIVE_ASSET_HEX: "00".repeat(32)
}))

const ACCOUNT = "paraloom1" + "11".repeat(64)
const SPEND_PRIVKEY = "ab".repeat(32)
const OUR_SPEND_PUB = `pub_${SPEND_PRIVKEY}`
const BLINDING = "cc".repeat(32)
const ASSET = "00".repeat(32)

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex")

let ourBox: nacl.BoxKeyPair

/** A delivered note sealed to us, with a commitment that binds it correctly. */
function honest(amount: bigint, blindingHex = BLINDING) {
  return {
    output_commitment: fakeCommitment(amount, OUR_SPEND_PUB, blindingHex),
    ciphertext: encryptNote(hex(ourBox.publicKey), {
      amount,
      blindingHex,
      assetIdHex: ASSET
    })
  }
}

/**
 * The #196 attack: sealed to us so it decrypts, but the commitment does not
 * bind the decrypted values under our spend key. Storing it inflates the
 * balance with a note that can never be found in the on-chain tree.
 */
function phantom(claimedAmount: bigint) {
  return {
    output_commitment: "deadbeef_not_a_real_leaf",
    ciphertext: encryptNote(hex(ourBox.publicKey), {
      amount: claimedAmount,
      blindingHex: BLINDING,
      assetIdHex: ASSET
    })
  }
}

/**
 * A phantom note that also supplies the material to verify itself. The delivered
 * payload is entirely attacker-controlled, so no field in it may be used for
 * verification — only the wallet's own spend key. The extra keys below are
 * plausible names a hollowed-out implementation might reach for.
 */
function phantomWithSelfServedKey(claimedAmount: bigint) {
  const attackerPub = "pub_attacker"
  return {
    output_commitment: fakeCommitment(claimedAmount, attackerPub, BLINDING),
    spend_pubkey: attackerPub,
    pubkey: attackerPub,
    note_pubkey: attackerPub,
    ciphertext: encryptNote(hex(ourBox.publicKey), {
      amount: claimedAmount,
      blindingHex: BLINDING,
      assetIdHex: ASSET
    })
  }
}

/** Sealed to somebody else — the ordinary case, indistinguishable at the wire. */
function forSomeoneElse(amount: bigint) {
  const stranger = nacl.box.keyPair()
  return {
    output_commitment: fakeCommitment(amount, "pub_stranger", BLINDING),
    ciphertext: encryptNote(hex(stranger.publicKey), {
      amount,
      blindingHex: BLINDING,
      assetIdHex: ASSET
    })
  }
}

// The wire carries hex and storage carries base58; keeping both spellings in
// the test is the point, since conflating them is invisible until a spend.
const MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
const MINT_HEX = new PublicKey(MINT).toBuffer().toString("hex")
const MINT_ASSET = fakeAssetIdForMint(MINT_HEX)

/** A received SPL note: asset-aware commitment, with the mint delivered beside it. */
function splNote(amount: bigint, mint: string | null = MINT_HEX, assetIdHex = MINT_ASSET) {
  return {
    output_commitment: fakeAssetCommitment(amount, OUR_SPEND_PUB, BLINDING, assetIdHex),
    mint,
    ciphertext: encryptNote(hex(ourBox.publicKey), {
      amount,
      blindingHex: BLINDING,
      assetIdHex
    })
  }
}

function respondWith(delivered: unknown[], ok = true, status = 200) {
  const fetchMock = vi.fn(async () => ({
    ok,
    status,
    json: async () => delivered
  }))
  vi.stubGlobal("fetch", fetchMock)
  return fetchMock
}

const scan = () => scanForNotes(ACCOUNT, ourBox.secretKey, SPEND_PRIVKEY)

beforeEach(() => {
  installFakeChrome()
  ourBox = nacl.box.keyPair()
  v3NoteCommitment.mockClear()
  v3NoteCommitmentAsset.mockClear()
  v3NotePubkey.mockClear()
  assetIdForMint.mockClear()
})

describe("phantom note rejection (#196)", () => {
  it("drops a note whose commitment does not bind the decrypted values", async () => {
    respondWith([phantom(1_000_000n)])
    expect(await scan()).toBe(0)
    expect(await getNotes(ACCOUNT)).toEqual([])
  })

  it("does not let a phantom note inflate the balance", async () => {
    // The number the user acts on, not just the flag — this is what #196
    // actually broke.
    respondWith([honest(100n), phantom(1_000_000n)])
    await scan()
    expect(await shieldedBalance(ACCOUNT)).toBe(100n)
  })

  it("recomputes the commitment under our own spend key", async () => {
    // The defence rests entirely on the pubkey being derived from OUR private
    // key rather than taken from the delivered payload. If that ever changes,
    // a crafted note verifies against itself and the check becomes decoration.
    respondWith([honest(100n)])
    await scan()

    expect(v3NotePubkey).toHaveBeenCalledWith(SPEND_PRIVKEY)
    // Named explicitly rather than looped over the recorded calls: a loop over
    // an empty call list passes, so it would go green on an implementation
    // that skipped the recomputation entirely.
    expect(v3NoteCommitment).toHaveBeenCalledOnce()
    expect(v3NoteCommitment).toHaveBeenCalledWith(100n, OUR_SPEND_PUB, BLINDING)
  })

  it("ignores verification material supplied by the delivered payload", async () => {
    // The behavioural form of the check above, and the one that survives a
    // refactor: a note that carries a commitment binding under a key it also
    // supplies must still be dropped. Asserting the call arguments alone
    // passes when the implementation falls back to our key for payloads that
    // happen not to carry one.
    respondWith([phantomWithSelfServedKey(1_000_000n)])
    expect(await scan()).toBe(0)
    expect(await shieldedBalance(ACCOUNT)).toBe(0n)
  })

  it("drops a note whose amount was altered after sealing", async () => {
    // Same commitment, different claimed amount: the recomputation moves and
    // the match fails. Pinned separately from the arbitrary-commitment case
    // because this is the version that looks well-formed.
    const good = honest(100n)
    respondWith([{ ...good, ciphertext: honest(999n).ciphertext }])
    expect(await scan()).toBe(0)
  })

  it("drops a note whose blinding was altered after sealing", async () => {
    const good = honest(100n)
    respondWith([{ ...good, ciphertext: honest(100n, "dd".repeat(32)).ciphertext }])
    expect(await scan()).toBe(0)
  })

  it("keeps scanning after a rejected note", async () => {
    // A `continue`, not a throw: one crafted note in the feed must not stop
    // the wallet from finding the real ones behind it. A griefer who can post
    // one ciphertext could otherwise suppress discovery entirely.
    respondWith([phantom(1n), honest(100n), phantom(2n), honest(200n)])
    expect(await scan()).toBe(2)
    expect(await shieldedBalance(ACCOUNT)).toBe(300n)
  })
})

describe("received SPL notes (#23)", () => {
  it("lands an SPL note in the token balances and not in the native one", async () => {
    // The regression that would be silent in the way #196 was: a token balance
    // counted as SOL is a wrong number the user acts on. `shieldedBalance`
    // filters on `!n.mint`, so this only holds because the mint is stored.
    respondWith([splNote(500n)])
    expect(await scan()).toBe(1)

    expect(await shieldedBalance(ACCOUNT)).toBe(0n)
    expect(await shieldedTokenBalances(ACCOUNT)).toEqual({ [MINT]: 500n })
  })

  it("stores the mint as base58, not the hex it arrived as", async () => {
    // `ShieldedNote.mint` is base58: the spend path feeds it to `new
    // PublicKey`, and token metadata is keyed by it. Storing the wire form
    // yields a note that can be discovered but never spent, and nothing before
    // the spend would say so.
    respondWith([splNote(500n)])
    await scan()

    const [note] = await getNotes(ACCOUNT)
    expect(note.mint).toBe(MINT)
    expect(note.mint).not.toBe(MINT_HEX)
    expect(() => new PublicKey(note.mint!)).not.toThrow()
  })

  it("verifies an SPL note with the asset-aware hash", async () => {
    // A native-only recomputation never matches an SPL leaf, which is what
    // dropped every received token note before this.
    respondWith([splNote(500n)])
    await scan()

    expect(v3NoteCommitmentAsset).toHaveBeenCalledWith(500n, OUR_SPEND_PUB, BLINDING, MINT_ASSET)
    expect(v3NoteCommitment).not.toHaveBeenCalled()
  })

  it("drops an SPL note whose delivered mint does not hash to its assetId", async () => {
    // The mint arrives from the node, so it is attacker-influenced exactly as
    // `output_commitment` is. The note itself is genuine and its commitment
    // verifies, so nothing downstream would catch a lie here — it would just
    // file a real balance under the wrong token.
    respondWith([{ ...splNote(500n), mint: "99".repeat(32) }])

    expect(await scan()).toBe(0)
    expect(await shieldedTokenBalances(ACCOUNT)).toEqual({})
    expect(await shieldedBalance(ACCOUNT)).toBe(0n)
  })

  it.each([
    [
      "the field absent",
      () => {
        const { mint, ...rest } = splNote(500n)
        return rest
      }
    ],
    ["the field null", () => splNote(500n, null)]
  ])("drops an SPL note delivered with no mint (%s)", async (_label, build) => {
    // What a node that has not shipped #23 yet produces. Storing it mintless
    // would put the tokens in the native balance, so dropping is both the safe
    // answer and today's behaviour.
    respondWith([build()])

    expect(await scan()).toBe(0)
    expect(await shieldedBalance(ACCOUNT)).toBe(0n)
  })

  it("accepts a native note whose mint field is null", async () => {
    // A Rust `Option<String>` serializes None as null unless the field is also
    // skipped, so `null` has to mean absent. Reading it as a contradiction
    // would drop every native note against such a node.
    respondWith([{ ...honest(100n), mint: null }])

    expect(await scan()).toBe(1)
    expect(await shieldedBalance(ACCOUNT)).toBe(100n)
  })

  it("drops a native note that arrives carrying a mint", async () => {
    // The commitment binds the all-zero asset, so the mint contradicts it.
    respondWith([{ ...honest(100n), mint: MINT }])
    expect(await scan()).toBe(0)
  })

  it.each([
    ["non-hex", "not-a-mint-at-all"],
    ["wrong length", "aabb"]
  ])("drops an SPL note with a malformed mint (%s) instead of throwing", async (_l, mint) => {
    // `assetIdForMint` throws on anything that is not 32-byte hex, so this has
    // to be caught and turned into a rejection. Escaping, it would leave
    // `scanForNotes` altogether.
    respondWith([{ ...splNote(500n), mint }])

    await expect(scan()).resolves.toBe(0)
    expect(await shieldedTokenBalances(ACCOUNT)).toEqual({})
  })

  it("still finds a later note when an earlier one has a malformed mint", async () => {
    // The one that matters. `/transact/scan` serves the whole feed in arrival
    // order and the loop walks it, so a throw does not drop one note — it drops
    // every note behind it, for every wallet, until the node restarts. Both call
    // sites swallow the exception, so the loss is silent.
    respondWith([{ ...splNote(500n), mint: "aabb" }, honest(100n)])

    await expect(scan()).resolves.toBe(1)
    expect(await shieldedBalance(ACCOUNT)).toBe(100n)
  })

  it("keeps native and SPL notes on their own sides in one scan", async () => {
    respondWith([honest(100n), splNote(500n)])
    expect(await scan()).toBe(2)

    expect(await shieldedBalance(ACCOUNT)).toBe(100n)
    expect(await shieldedTokenBalances(ACCOUNT)).toEqual({ [MINT]: 500n })
  })
})

describe("ordinary scanning", () => {
  it("stores a note that decrypts and verifies", async () => {
    respondWith([honest(4_200n)])
    expect(await scan()).toBe(1)

    const notes = await getNotes(ACCOUNT)
    expect(notes).toHaveLength(1)
    expect(notes[0]).toMatchObject({
      amount: "4200",
      blinding: BLINDING,
      assetId: ASSET,
      spent: false,
      source: "transfer",
      commitment: fakeCommitment(4_200n, OUR_SPEND_PUB, BLINDING)
    })
  })

  it("ignores a note sealed to someone else without trying to verify it", async () => {
    respondWith([forSomeoneElse(500n)])
    expect(await scan()).toBe(0)
    // Cheap check first: a failed decrypt should not reach the circuit hash at
    // all, since the feed carries every recipient's notes.
    expect(v3NoteCommitment).not.toHaveBeenCalled()
  })

  it("is idempotent across rescans", async () => {
    respondWith([honest(100n)])
    expect(await scan()).toBe(1)
    expect(await scan()).toBe(0)
    expect(await getNotes(ACCOUNT)).toHaveLength(1)
  })

  it("does not resurrect a note that was already spent", async () => {
    // The ingress keeps delivering it after it is spent, so the known-set has
    // to cover spent notes too. Re-storing one puts spent money back in the
    // balance.
    respondWith([honest(100n)])
    await scan()
    await markNoteSpentByIdentity(ACCOUNT, (await getNotes(ACCOUNT))[0])

    expect(await scan()).toBe(0)
    expect(await getNotes(ACCOUNT)).toHaveLength(1)
    expect(await shieldedBalance(ACCOUNT)).toBe(0n)
  })

  it("counts a note delivered twice in one response only once", async () => {
    // `known` is a snapshot from before the loop, so without adding each
    // stored commitment to it a repeated delivery is stored once and counted
    // twice. The node dedupes by (commitment, ciphertext), not by commitment
    // alone, so one commitment with two ciphertexts is representable in a
    // single response by construction — the wallet does not trust the node's
    // `output_commitment`, and should not trust its de-duplication either.
    const note = honest(100n)
    respondWith([note, note])

    expect(await scan()).toBe(1)
    expect(await getNotes(ACCOUNT)).toHaveLength(1)
  })

  it("counts only newly discovered notes", async () => {
    respondWith([honest(1n), honest(2n), honest(3n)])
    expect(await scan()).toBe(3)
    expect(await scan()).toBe(0)
  })

  it("throws when the ingress responds with an error", async () => {
    // Distinct from an empty feed: silently returning 0 would look like
    // "no notes for you" and hide an outage behind a plausible answer.
    respondWith([], false, 503)
    await expect(scan()).rejects.toThrow(/503/)
  })

  it("handles an empty feed", async () => {
    respondWith([])
    expect(await scan()).toBe(0)
  })

  it("isolates scanned notes per cluster (mainnet-beta vs devnet)", async () => {
    respondWith([honest(750n)])
    expect(await scanForNotes(ACCOUNT, ourBox.secretKey, SPEND_PRIVKEY, "devnet")).toBe(1)

    expect(await shieldedBalance(ACCOUNT, "devnet")).toBe(750n)
    expect(await shieldedBalance(ACCOUNT, "mainnet-beta")).toBe(0n)
    expect((await getNotes(ACCOUNT, "devnet"))[0].network).toBe("devnet")
  })
})
