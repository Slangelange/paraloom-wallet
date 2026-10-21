// `fetchV3Leaves` rebuilds the on-chain incremental tree from public event
// logs. Every failure mode here is silent at the point it happens and only
// surfaces much later as "prover root not recognized" — a wallet that cannot
// spend, with nothing pointing at the leaf list as the cause. That is what
// makes these worth pinning.

import { sha256 } from "@noble/hashes/sha256"
import type { Connection } from "@solana/web3.js"
import {
  DEPOSIT_NOTE_EVENT_DISCRIMINATOR,
  DEPOSIT_NOTE_SPL_EVENT_DISCRIMINATOR,
  PROGRAM_ID,
  TRANSACT_EVENT_DISCRIMINATOR
} from "~lib/paraloom/constants"
import { fetchV3Leaves } from "~lib/paraloom/transact"
import { describe, expect, it, vi } from "vitest"

// transact.ts now reaches ~lib/prover through bridge.ts, and the wasm module
// cannot load under vitest. Nothing in fetchV3Leaves uses it.
vi.mock("~lib/prover", () => ({ NATIVE_ASSET_HEX: "00".repeat(32) }))

const OTHER_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"

/**
 * `Program data:` payload for a DepositNoteEvent at `leafIndex`.
 *
 * The full on-chain event, not just the prefix the parser reads:
 * depositor(32) amount(8) commitment(32) leaf_index(8) timestamp(8) = 88.
 * Mirroring the whole body keeps the fixtures at realistic payload lengths
 * rather than parser-shaped prefixes. It does not detect a field added
 * upstream — the fixture is hand-written, so it would need updating by hand
 * too.
 */
function depositEvent(commitmentByte: number, leafIndex: number): string {
  const body = new Uint8Array(88)
  body.fill(commitmentByte, 40, 72)
  const view = new DataView(body.buffer)
  view.setBigUint64(72, BigInt(leafIndex), true)
  view.setBigInt64(80, 1_700_000_000n, true) // timestamp, unread by the wallet
  return payload(DEPOSIT_NOTE_EVENT_DISCRIMINATOR, body)
}

/**
 * `Program data:` payload for a DepositNoteSplEvent at `leafIndex` (#779).
 *
 * An SPL deposit appends to the SAME tree as a native one, but its body carries
 * an extra `mint` before the amount, so every field after it shifts by 32:
 * depositor(32) mint(32) amount(8) commitment(32) leaf_index(8) timestamp(8).
 * Reusing the native offsets here would read the tail of the mint as the
 * commitment and still produce a plausible-looking leaf.
 *
 * Hand-written from the current layout, not generated from core, so it will not
 * notice a field added upstream. Catching schema drift needs a golden payload
 * from core; this only keeps the wallet honest about the layout as it stands.
 */
function depositSplEvent(commitmentByte: number, leafIndex: number): string {
  const body = new Uint8Array(120)
  body.fill(0x5e, 32, 64) // mint, unread by the wallet's leaf rebuild
  body.fill(commitmentByte, 72, 104)
  const view = new DataView(body.buffer)
  view.setBigUint64(104, BigInt(leafIndex), true)
  view.setBigInt64(112, 1_700_000_000n, true)
  return payload(DEPOSIT_NOTE_SPL_EVENT_DISCRIMINATOR, body)
}

/** `Program data:` payload for a TransactEvent with two output commitments. */
function transactEvent(oc0Byte: number, oc1Byte: number): string {
  const body = new Uint8Array(224)
  body.fill(oc0Byte, 64, 96)
  body.fill(oc1Byte, 96, 128)
  return payload(TRANSACT_EVENT_DISCRIMINATOR, body)
}

function payload(discriminator: Uint8Array, body: Uint8Array): string {
  const out = new Uint8Array(8 + body.length)
  out.set(discriminator, 0)
  out.set(body, 8)
  return Buffer.from(out).toString("base64")
}

/** Logs for one program emitting `events` inside its own invoke frame. */
function emittedBy(programId: string, ...events: string[]): string[] {
  return [
    `Program ${programId} invoke [1]`,
    ...events.map((e) => `Program data: ${e}`),
    `Program ${programId} success`
  ]
}

interface FakeTx {
  logs?: string[]
  err?: unknown
  /** Number of leading getTransaction calls that return null. */
  nullFor?: number
}

function fakeConnection(txs: FakeTx[]) {
  const calls = { signatures: [] as (string | undefined)[], getTransaction: 0 }
  // Newest-first, as the RPC returns them.
  const order = txs.map((_, i) => `sig${i}`).reverse()
  const nullsLeft = new Map<string, number>()
  txs.forEach((t, i) => nullsLeft.set(`sig${i}`, t.nullFor ?? 0))

  const connection = {
    async getSignaturesForAddress(_addr: unknown, opts: { limit: number; before?: string }) {
      calls.signatures.push(opts.before)
      const start = opts.before ? order.indexOf(opts.before) + 1 : 0
      return order.slice(start, start + opts.limit).map((signature) => ({
        signature,
        err: txs[Number(signature.slice(3))].err ?? null
      }))
    },
    async getTransaction(signature: string) {
      calls.getTransaction++
      const remaining = nullsLeft.get(signature) ?? 0
      if (remaining > 0) {
        nullsLeft.set(signature, remaining - 1)
        return null
      }
      return { meta: { logMessages: txs[Number(signature.slice(3))].logs ?? [] } }
    }
  }
  return { connection: connection as unknown as Connection, calls }
}

describe("event discriminators", () => {
  // The fixtures below build events from the production constants, so a
  // constant that is wrong in the same way as the fixture would go unnoticed.
  // Anchor derives these as `sha256("event:<Name>")[..8]`, so derive them here
  // instead of trusting the constant.
  it.each([
    ["DepositNoteEvent", DEPOSIT_NOTE_EVENT_DISCRIMINATOR],
    ["DepositNoteSplEvent", DEPOSIT_NOTE_SPL_EVENT_DISCRIMINATOR],
    ["TransactEvent", TRANSACT_EVENT_DISCRIMINATOR]
  ])('%s matches sha256("event:<Name>")[..8]', (name, constant) => {
    const expected = sha256(new TextEncoder().encode(`event:${name}`)).slice(0, 8)
    expect(Array.from(constant)).toEqual(Array.from(expected))
  })
})

describe("event attribution", () => {
  it("collects the leaves our program emitted", async () => {
    const { connection } = fakeConnection([
      { logs: emittedBy(PROGRAM_ID, depositEvent(0xa0, 0)) },
      { logs: emittedBy(PROGRAM_ID, depositEvent(0xa1, 1)) }
    ])
    const leaves = await fetchV3Leaves(connection)
    expect(leaves.map((l) => l.index)).toEqual([0, 1])
    expect(leaves[0].commitmentHex).toBe("a0".repeat(32))
  })

  it("ignores a byte-identical event emitted by a different program", async () => {
    // Event discriminators are `sha256("event:<Name>")[..8]` — public, and
    // anyone can emit the same bytes. `getSignaturesForAddress` selects the
    // transaction, not the emitter, so without the invoke/success stack this
    // forged leaf lands in the tree and every later spend fails.
    const { connection } = fakeConnection([
      { logs: emittedBy(PROGRAM_ID, depositEvent(0xa0, 0)) },
      { logs: emittedBy(OTHER_PROGRAM, depositEvent(0xff, 1)) }
    ])
    const leaves = await fetchV3Leaves(connection)
    expect(leaves).toHaveLength(1)
    expect(leaves[0].commitmentHex).toBe("a0".repeat(32))
  })

  it("ignores an event emitted by a CPI callee inside our own frame", async () => {
    // The stack is what distinguishes this from the case above: our program is
    // on the stack, but it is not the frame that emitted.
    const { connection } = fakeConnection([
      {
        logs: [
          `Program ${PROGRAM_ID} invoke [1]`,
          `Program ${OTHER_PROGRAM} invoke [2]`,
          `Program data: ${depositEvent(0xff, 0)}`,
          `Program ${OTHER_PROGRAM} success`,
          `Program data: ${depositEvent(0xa0, 0)}`,
          `Program ${PROGRAM_ID} success`
        ]
      }
    ])
    const leaves = await fetchV3Leaves(connection)
    expect(leaves).toHaveLength(1)
    expect(leaves[0].commitmentHex).toBe("a0".repeat(32))
  })

  it("keeps events our program emits when it is itself the CPI callee", async () => {
    const { connection } = fakeConnection([
      {
        logs: [
          `Program ${OTHER_PROGRAM} invoke [1]`,
          `Program ${PROGRAM_ID} invoke [2]`,
          `Program data: ${depositEvent(0xa0, 0)}`,
          `Program ${PROGRAM_ID} success`,
          `Program ${OTHER_PROGRAM} success`
        ]
      }
    ])
    expect(await fetchV3Leaves(connection)).toHaveLength(1)
  })

  it("skips failed transactions", async () => {
    const { connection } = fakeConnection([
      { logs: emittedBy(PROGRAM_ID, depositEvent(0xa0, 0)) },
      { logs: emittedBy(PROGRAM_ID, depositEvent(0xff, 1)), err: { InstructionError: [0, "X"] } }
    ])
    expect(await fetchV3Leaves(connection)).toHaveLength(1)
  })
  it("ignores events emitted inside an inner CPI frame that subsequently fails or is truncated", async () => {
    const { connection } = fakeConnection([
      {
        logs: [
          `Program ${OTHER_PROGRAM} invoke [1]`,
          `Program ${PROGRAM_ID} invoke [2]`,
          `Program data: ${depositEvent(0xff, 1)}`,
          `Program ${PROGRAM_ID} failed: custom program error: 0x1`,
          `Program ${OTHER_PROGRAM} success`
        ]
      },
      { logs: emittedBy(PROGRAM_ID, depositEvent(0xa0, 0)) }
    ])
    const leaves = await fetchV3Leaves(connection)
    expect(leaves).toHaveLength(1)
    expect(leaves[0].commitmentHex).toBe("a0".repeat(32))
  })

  it("does not pop our program frame on a spoofed or mismatched exit log line", async () => {
    const { connection } = fakeConnection([
      {
        logs: [
          `Program ${PROGRAM_ID} invoke [1]`,
          `Program ${OTHER_PROGRAM} invoke [2]`,
          `Program ${PROGRAM_ID} success`,
          `Program data: ${depositEvent(0xff, 1)}`,
          `Program ${OTHER_PROGRAM} success`,
          `Program data: ${depositEvent(0xa0, 0)}`,
          `Program ${PROGRAM_ID} success`
        ]
      }
    ])
    const leaves = await fetchV3Leaves(connection)
    expect(leaves).toHaveLength(1)
    expect(leaves[0].commitmentHex).toBe("a0".repeat(32))
  })

})

describe("SPL deposits share the tree (#779)", () => {
  it("reads the commitment and leaf index from the shifted offsets", () => {
    // Pinned against the field positions directly, so a fixture built with the
    // native layout cannot pass by accident.
    const { connection } = fakeConnection([
      { logs: emittedBy(PROGRAM_ID, depositSplEvent(0xd0, 0)) }
    ])
    return expect(fetchV3Leaves(connection)).resolves.toEqual([
      { index: 0, commitmentHex: "d0".repeat(32) }
    ])
  })

  it("interleaves SPL and native leaves in index order", async () => {
    const { connection } = fakeConnection([
      { logs: emittedBy(PROGRAM_ID, depositEvent(0xa0, 0)) },
      { logs: emittedBy(PROGRAM_ID, depositSplEvent(0xd0, 1)) },
      { logs: emittedBy(PROGRAM_ID, depositEvent(0xa2, 2)) }
    ])
    const leaves = await fetchV3Leaves(connection)
    expect(leaves.map((l) => [l.index, l.commitmentHex.slice(0, 2)])).toEqual([
      [0, "a0"],
      [1, "d0"],
      [2, "a2"]
    ])
  })

  it("leaves a gap if SPL leaves are skipped", async () => {
    // The failure this guards: dropping SPL events rebuilds a shorter tree
    // whose root the program rejects, freezing NATIVE spends too. Contiguity
    // turns that into an error at the rebuild instead.
    const { connection } = fakeConnection([
      { logs: emittedBy(PROGRAM_ID, depositEvent(0xa0, 0)) },
      { logs: emittedBy(PROGRAM_ID, depositEvent(0xa2, 2)) }
    ])
    await expect(fetchV3Leaves(connection)).rejects.toThrow(/not contiguous/)
  })

  it("advances the transact cursor past an SPL deposit", async () => {
    // A transact output takes its index from the cursor, so the SPL branch has
    // to advance it like the native one does. Native LAST would hide a missing
    // update, because the native branch would move the cursor on its way past;
    // native -> SPL -> transact puts the SPL deposit in charge of the number
    // the transact outputs are numbered from.
    const { connection } = fakeConnection([
      { logs: emittedBy(PROGRAM_ID, depositEvent(0xa0, 0)) },
      { logs: emittedBy(PROGRAM_ID, depositSplEvent(0xd0, 1)) },
      { logs: emittedBy(PROGRAM_ID, transactEvent(0xb0, 0xb1)) }
    ])
    const leaves = await fetchV3Leaves(connection)
    expect(leaves.map((l) => [l.index, l.commitmentHex.slice(0, 2)])).toEqual([
      [0, "a0"],
      [1, "d0"],
      [2, "b0"],
      [3, "b1"]
    ])
  })

  it("ignores an SPL event emitted by a different program", async () => {
    const { connection } = fakeConnection([
      { logs: emittedBy(PROGRAM_ID, depositSplEvent(0xd0, 0)) },
      { logs: emittedBy(OTHER_PROGRAM, depositSplEvent(0xff, 1)) }
    ])
    expect(await fetchV3Leaves(connection)).toHaveLength(1)
  })

})

describe("transact outputs", () => {
  it("appends both output commitments at consecutive indices after the deposits", async () => {
    const { connection } = fakeConnection([
      { logs: emittedBy(PROGRAM_ID, depositEvent(0xa0, 0)) },
      { logs: emittedBy(PROGRAM_ID, transactEvent(0xb0, 0xb1)) }
    ])
    const leaves = await fetchV3Leaves(connection)
    expect(leaves.map((l) => [l.index, l.commitmentHex.slice(0, 2)])).toEqual([
      [0, "a0"],
      [1, "b0"],
      [2, "b1"]
    ])
  })

  it("numbers transact outputs in append order across transactions", async () => {
    const { connection } = fakeConnection([
      { logs: emittedBy(PROGRAM_ID, transactEvent(0xb0, 0xb1)) },
      { logs: emittedBy(PROGRAM_ID, transactEvent(0xb2, 0xb3)) }
    ])
    const leaves = await fetchV3Leaves(connection)
    expect(leaves.map((l) => l.commitmentHex.slice(0, 2))).toEqual(["b0", "b1", "b2", "b3"])
  })
})

describe("signature history", () => {
  it("pages past the 1000-signature RPC cap", async () => {
    // A single unpaginated fetch saw only the newest 1000 signatures, so once
    // the program passed that the wallet rebuilt a tree missing its OLDEST
    // leaves — a root the program's `is_known_root` rejects.
    const txs: FakeTx[] = []
    for (let i = 0; i < 1200; i++) {
      txs.push({ logs: emittedBy(PROGRAM_ID, depositEvent(0xa0, i)) })
    }
    const { connection, calls } = fakeConnection(txs)

    const leaves = await fetchV3Leaves(connection)

    expect(leaves).toHaveLength(1200)
    expect(leaves[0].index).toBe(0)
    // First call unfiltered, then `before` the oldest signature of page 1.
    expect(calls.signatures[0]).toBeUndefined()
    expect(calls.signatures[1]).toBe("sig200")
  })

  it("stops paging on a short page", async () => {
    const { connection, calls } = fakeConnection([
      { logs: emittedBy(PROGRAM_ID, depositEvent(0xa0, 0)) }
    ])
    await fetchV3Leaves(connection)
    expect(calls.signatures).toHaveLength(1)
  })
})

describe("refusing an unsafe tree", () => {
  it("throws on a gap in the leaf indices", async () => {
    // Callers fold by array position, so a gap folds to a wrong root. Failing
    // here names the cause; failing later does not.
    const { connection } = fakeConnection([
      { logs: emittedBy(PROGRAM_ID, depositEvent(0xa0, 0)) },
      { logs: emittedBy(PROGRAM_ID, depositEvent(0xa2, 2)) }
    ])
    await expect(fetchV3Leaves(connection)).rejects.toThrow(/not contiguous/)
  })

  it("throws on a duplicated leaf index", async () => {
    const { connection } = fakeConnection([
      { logs: emittedBy(PROGRAM_ID, depositEvent(0xa0, 0)) },
      { logs: emittedBy(PROGRAM_ID, depositEvent(0xa1, 0)) }
    ])
    await expect(fetchV3Leaves(connection)).rejects.toThrow(/not contiguous/)
  })

  it("retries a transient null getTransaction rather than dropping the leaf", async () => {
    const { connection, calls } = fakeConnection([
      { logs: emittedBy(PROGRAM_ID, depositEvent(0xa0, 0)), nullFor: 2 },
      { logs: emittedBy(PROGRAM_ID, depositEvent(0xa1, 1)) }
    ])
    expect(await fetchV3Leaves(connection)).toHaveLength(2)
    expect(calls.getTransaction).toBe(4) // 3 for the flaky one, 1 for the other
  })

  it("throws rather than silently skipping a transaction it cannot read", async () => {
    // A dropped TRAILING leaf is invisible to the contiguity check, so the
    // throw is the only backstop.
    const { connection } = fakeConnection([
      { logs: emittedBy(PROGRAM_ID, depositEvent(0xa0, 0)), nullFor: Infinity }
    ])
    await expect(fetchV3Leaves(connection)).rejects.toThrow(/leaf history may be incomplete/)
  })
})
