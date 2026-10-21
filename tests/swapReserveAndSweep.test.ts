import { Connection, Keypair, PublicKey, VersionedTransaction, MessageV0 } from "@solana/web3.js"
import { beforeEach, describe, expect, it, vi } from "vitest"

const mocks = vi.hoisted(() => ({
  spendV3: vi.fn(),
  depositV3: vi.fn(),
  depositSpl: vi.fn(),
  createTokenAccount: vi.fn(),
  associatedTokenAddress: vi.fn(),
  assetIdForMint: vi.fn(),
  saveSwapOutput: vi.fn(),
  listSwapOutputs: vi.fn(),
  persistReshieldedNote: vi.fn()
}))

vi.mock("~lib/paraloom/transactFlow", () => ({
  spendV3: mocks.spendV3,
  depositV3: mocks.depositV3
}))

vi.mock("../lib/paraloom/transactFlow", () => ({
  spendV3: mocks.spendV3,
  depositV3: mocks.depositV3
}))

vi.mock("~lib/paraloom/bridge", () => ({
  associatedTokenAddress: mocks.associatedTokenAddress,
  createTokenAccount: mocks.createTokenAccount,
  depositSpl: mocks.depositSpl
}))

vi.mock("../lib/paraloom/bridge", () => ({
  associatedTokenAddress: mocks.associatedTokenAddress,
  createTokenAccount: mocks.createTokenAccount,
  depositSpl: mocks.depositSpl
}))

vi.mock("~lib/prover", () => ({
  assetIdForMint: mocks.assetIdForMint
}))

vi.mock("../lib/prover", () => ({
  assetIdForMint: mocks.assetIdForMint
}))

vi.mock("~lib/paraloom/swapOutputs", () => ({
  saveSwapOutput: mocks.saveSwapOutput,
  listSwapOutputs: mocks.listSwapOutputs
}))

vi.mock("../lib/paraloom/swapOutputs", () => ({
  saveSwapOutput: mocks.saveSwapOutput,
  listSwapOutputs: mocks.listSwapOutputs
}))

vi.mock("~lib/paraloom/reshieldRecovery", () => ({
  persistReshieldedNote: mocks.persistReshieldedNote
}))

vi.mock("../lib/paraloom/reshieldRecovery", () => ({
  persistReshieldedNote: mocks.persistReshieldedNote
}))

import {
  MIN_SOL_SWAP_WITHDRAW_LAMPORTS,
  RESHIELD_FEE_RESERVE_LAMPORTS,
  expectedNetWithdrawLamports,
  privateSwap,
  resumeSwapAtFreshAddress,
  WSOL_MINT
} from "../lib/paraloom/privateSwap"
import {
  reconcileSwapOutputs,
  RESUME_GRACE_MS,
  RESUME_MIN_LAMPORTS
} from "../lib/paraloom/swapReconcile"
import {
  isSubReserveRecoverableSol,
  SWAP_OVERHEAD_LAMPORTS
} from "../lib/paraloom/swapReconcileClassify"

const USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"

function dummySwapTransactionBase64(payer: PublicKey): string {
  const msg = new MessageV0({
    header: {
      numRequiredSignatures: 1,
      numReadonlySignedAccounts: 0,
      numReadonlyUnsignedAccounts: 0
    },
    staticAccountKeys: [payer],
    recentBlockhash: "11111111111111111111111111111111",
    compiledInstructions: [],
    addressTableLookups: []
  })
  const tx = new VersionedTransaction(msg)
  return Buffer.from(tx.serialize()).toString("base64")
}

describe("privateSwap & resumeSwapAtFreshAddress reserve floor and residual SOL sweep", () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mocks.associatedTokenAddress.mockImplementation((owner: PublicKey) => owner)
    mocks.assetIdForMint.mockResolvedValue("11".repeat(32))
    mocks.depositSpl.mockResolvedValue({
      blinding: new Uint8Array(32).fill(7),
      signature: "dep-spl-sig"
    })
    mocks.depositV3.mockResolvedValue({
      signature: "dep-v3-sweep-sig",
      leafIndex: 0
    })
    mocks.saveSwapOutput.mockResolvedValue(undefined)
    mocks.persistReshieldedNote.mockResolvedValue(undefined)
  })

  it("computes exact 25 bps protocol withdrawal fee boundary and sub-reserve SOL classification", () => {
    expect(expectedNetWithdrawLamports(6_000_000n)).toBe(5_985_000n)
    expect(expectedNetWithdrawLamports(MIN_SOL_SWAP_WITHDRAW_LAMPORTS - 1n)).toBe(
      SWAP_OVERHEAD_LAMPORTS
    )
    expect(expectedNetWithdrawLamports(MIN_SOL_SWAP_WITHDRAW_LAMPORTS)).toBe(
      SWAP_OVERHEAD_LAMPORTS + 1n
    )
    // Rent dust (890,880 lamports) or exactly RESHIELD_FEE_RESERVE (1,000,000) is not swept
    expect(isSubReserveRecoverableSol(890_880n, 0n)).toBe(false)
    expect(isSubReserveRecoverableSol(RESHIELD_FEE_RESERVE_LAMPORTS, 0n)).toBe(false)
    // Sub-reserve withdrawn SOL (1,000,001 .. 6,000,000) with no output token is recoverable
    expect(isSubReserveRecoverableSol(RESHIELD_FEE_RESERVE_LAMPORTS + 1n, 0n)).toBe(true)
    expect(isSubReserveRecoverableSol(RESUME_MIN_LAMPORTS, 0n)).toBe(true)
    expect(isSubReserveRecoverableSol(RESUME_MIN_LAMPORTS + 1n, 0n)).toBe(false)
    expect(isSubReserveRecoverableSol(5_985_000n, 100n)).toBe(false)
  })

  it("rejects sub-reserve SOL swap amounts (<= 6,015,037 lamports gross / <= 6,000,000 net after 25 bps fee) BEFORE calling spendV3", async () => {
    const conn = {} as unknown as Connection
    // 6,000,000 lamports gross nets 5,985,000 lamports after the 25 bps withdrawal fee,
    // which is below SWAP_OVERHEAD_LAMPORTS (6,000,000).
    await expect(
      privateSwap(
        conn,
        "paraloom1test",
        "aa".repeat(32),
        "bb".repeat(32),
        [
          {
            amount: "10000000",
            blinding: "cc".repeat(32),
            assetId: "00".repeat(32),
            signature: "sig-in",
            createdAt: 1,
            spent: false
          }
        ],
        {
          outputMint: USDC_MINT,
          amountLamports: 6_000_000n,
          reshield: true
        }
      )
    ).rejects.toThrow(/swap overhead reserve/i)

    // Exact boundary: 6,015,037 gross -> fee = 15,037 -> net = 6,000,000 (0 swappable lamports)
    await expect(
      privateSwap(
        conn,
        "paraloom1test",
        "aa".repeat(32),
        "bb".repeat(32),
        [
          {
            amount: "10000000",
            blinding: "cc".repeat(32),
            assetId: "00".repeat(32),
            signature: "sig-in",
            createdAt: 1,
            spent: false
          }
        ],
        {
          outputMint: USDC_MINT,
          amountLamports: 6_015_037n,
          reshield: true
        }
      )
    ).rejects.toThrow(/swap overhead reserve/i)

    expect(mocks.spendV3).not.toHaveBeenCalled()
    expect(mocks.saveSwapOutput).not.toHaveBeenCalled()
  })

  it("rejects native SOL outputMint ('SOL' or WSOL_MINT) in privateSwap before calling spendV3", async () => {
    const conn = {} as unknown as Connection
    for (const mint of ["SOL", WSOL_MINT]) {
      await expect(
        privateSwap(
          conn,
          "paraloom1test",
          "aa".repeat(32),
          "bb".repeat(32),
          [
            {
              amount: "20000000",
              blinding: "cc".repeat(32),
              assetId: "00".repeat(32),
              signature: "sig-in",
              createdAt: 1,
              spent: false
            }
          ],
          {
            outputMint: mint,
            amountLamports: 15_000_000n,
            reshield: false
          }
        )
      ).rejects.toThrow(/native SOL/i)
    }
    expect(mocks.spendV3).not.toHaveBeenCalled()
    expect(mocks.saveSwapOutput).not.toHaveBeenCalled()
  })

  it("sweeps unused SWAP_OVERHEAD_LAMPORTS SOL back into the shielded pool after reshieldToken in privateSwap", async () => {
    let fundedChecked = false
    const conn = {
      getBalance: vi.fn(async () => {
        if (!fundedChecked) {
          fundedChecked = true
          return 15_000_000 // funded after withdraw
        }
        return 4_500_000 // remaining overhead SOL after ATA rent + swap + reshield tx fees
      }),
      sendRawTransaction: vi.fn(async () => "swap-tx-sig"),
      getSignatureStatus: vi.fn(async () => ({
        value: { confirmationStatus: "confirmed", err: null }
      })),
      getTokenAccountBalance: vi.fn(async () => ({
        value: { amount: "2500000" }
      }))
    } as unknown as Connection

    mocks.spendV3.mockImplementation(
      async (
        _c: unknown,
        _a: unknown,
        _sp: unknown,
        _bp: unknown,
        _in: unknown,
        _amt: unknown,
        _dest: unknown,
        opts: { confirmSettled: () => Promise<boolean> }
      ) => {
        await opts.confirmSettled()
        return { requestId: "req-1", changeLamports: 0n, settled: true }
      }
    )

    const origFetch = globalThis.fetch
    globalThis.fetch = vi.fn(async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? "{}"))
      const userPk = new PublicKey(body.user_public_key)
      return new Response(
        JSON.stringify({
          out_amount: 2_500_000,
          swap_transaction: dummySwapTransactionBase64(userPk)
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      )
    }) as typeof fetch

    try {
      const res = await privateSwap(
        conn,
        "paraloom1test",
        "aa".repeat(32),
        "bb".repeat(32),
        [
          {
            amount: "20000000",
            blinding: "cc".repeat(32),
            assetId: "00".repeat(32),
            signature: "sig-in",
            createdAt: 1,
            spent: false
          }
        ],
        {
          outputMint: USDC_MINT,
          amountLamports: 16_000_000n,
          reshield: true
        }
      )

      expect(res.reshielded).toBeDefined()
      expect(mocks.depositSpl).toHaveBeenCalledTimes(1)
      // 4,500,000 remaining SOL minus 1,000,000 RESHIELD_FEE_RESERVE = 3,500,000 lamports swept back
      expect(mocks.depositV3).toHaveBeenCalledTimes(1)
      expect(mocks.depositV3.mock.calls[0][4]).toBe(3_500_000n)
    } finally {
      globalThis.fetch = origFetch
    }
  })

  it("sweeps unused SWAP_OVERHEAD_LAMPORTS SOL back into the shielded pool after reshieldToken in resumeSwapAtFreshAddress", async () => {
    const fresh = Keypair.generate()
    const freshSecretKeyHex = Buffer.from(fresh.secretKey).toString("hex")
    let balanceCall = 0
    const conn = {
      getBalance: vi.fn(async () => {
        balanceCall++
        return balanceCall === 1 ? 12_000_000 : 3_950_000
      }),
      sendRawTransaction: vi.fn(async () => "resumed-swap-sig"),
      getSignatureStatus: vi.fn(async () => ({
        value: { confirmationStatus: "confirmed", err: null }
      })),
      getTokenAccountBalance: vi.fn(async () => ({
        value: { amount: "1800000" }
      }))
    } as unknown as Connection

    const origFetch = globalThis.fetch
    globalThis.fetch = vi.fn(async () => {
      return new Response(
        JSON.stringify({
          out_amount: 1_800_000,
          swap_transaction: dummySwapTransactionBase64(fresh.publicKey)
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      )
    }) as typeof fetch

    try {
      const res = await resumeSwapAtFreshAddress(
        conn,
        "paraloom1test",
        freshSecretKeyHex,
        USDC_MINT,
        true,
        undefined,
        "aa".repeat(32)
      )

      expect(res.reshielded).toBeDefined()
      expect(mocks.depositSpl).toHaveBeenCalledTimes(1)
      // 3,950,000 remaining SOL minus 1,000,000 RESHIELD_FEE_RESERVE = 2,950,000 lamports swept back
      expect(mocks.depositV3).toHaveBeenCalledTimes(1)
      expect(mocks.depositV3.mock.calls[0][4]).toBe(2_950_000n)
    } finally {
      globalThis.fetch = origFetch
    }
  })

  it("reconcileSwapOutputs sweeps sub-reserve stranded SOL (RESHIELD_FEE_RESERVE < solLamports <= RESUME_MIN_LAMPORTS) back into the shielded pool", async () => {
    const fresh = Keypair.generate()
    const freshSecretKeyHex = Buffer.from(fresh.secretKey).toString("hex")
    mocks.listSwapOutputs.mockResolvedValue([
      {
        freshAddress: fresh.publicKey.toBase58(),
        freshSecretKeyHex,
        outputMint: USDC_MINT,
        outAmount: 0,
        swapSignature: "",
        reshield: true,
        createdAt: Date.now() - (RESUME_GRACE_MS + 10_000)
      }
    ])

    const conn = {
      getBalance: vi.fn(async () => Number(RESUME_MIN_LAMPORTS) - 15_000), // 5,985,000 lamports (<= RESUME_MIN_LAMPORTS, > 1,000,000 reserve)
      getParsedTokenAccountsByOwner: vi.fn(async () => ({ value: [] }))
    } as unknown as Connection

    const resolved = await reconcileSwapOutputs(
      conn,
      "paraloom1test",
      "aa".repeat(32)
    )

    expect(resolved).toBe(1)
    expect(mocks.depositV3).toHaveBeenCalledTimes(1)
    expect(mocks.depositV3.mock.calls[0][4]).toBe(4_985_000n)
    expect(mocks.saveSwapOutput).toHaveBeenCalledWith(
      expect.objectContaining({
        freshAddress: fresh.publicKey.toBase58(),
        swapSignature: "dep-v3-sweep-sig"
      })
    )
  })
})
