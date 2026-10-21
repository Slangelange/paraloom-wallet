import {
  Connection,
  Keypair,
  MessageV0,
  PublicKey,
  VersionedTransaction
} from "@solana/web3.js"
import { beforeEach, describe, expect, it, vi } from "vitest"

import { getNotes, type ShieldedNote } from "~lib/paraloom/notes"
import {
  GAS_LAMPORTS,
  privateSwap,
  privateSwapFromToken,
  WSOL_MINT
} from "~lib/paraloom/privateSwap"
import {
  persistReshieldedNote,
  recoverReshields
} from "~lib/paraloom/reshieldRecovery"
import { listSwapOutputs, saveSwapOutput } from "~lib/paraloom/swapOutputs"
import { reconcileSwapOutputs, RESUME_GRACE_MS } from "~lib/paraloom/swapReconcile"

import { installFakeChrome } from "./support/chromeStorage"

const {
  createTokenAccountMock,
  depositSplMock,
  recoverReshieldedNoteMock,
  depositV3Mock,
  spendV3Mock
} = vi.hoisted(() => ({
  createTokenAccountMock: vi.fn(),
  depositSplMock: vi.fn(),
  recoverReshieldedNoteMock: vi.fn(),
  depositV3Mock: vi.fn(),
  spendV3Mock: vi.fn()
}))

vi.mock("~lib/prover", () => ({
  NATIVE_ASSET_HEX: "00".repeat(32),
  assetIdForMint: vi.fn(async () => "11".repeat(32))
}))

vi.mock("~lib/paraloom/bridge", async (importOriginal) => {
  const actual = await importOriginal<typeof import("~lib/paraloom/bridge")>()
  return {
    ...actual,
    createTokenAccount: createTokenAccountMock,
    depositSpl: depositSplMock,
    recoverReshieldedNote: recoverReshieldedNoteMock
  }
})

vi.mock("~lib/paraloom/transactFlow", () => ({
  depositV3: depositV3Mock,
  spendV3: spendV3Mock
}))

const ACCOUNT = "paraloom1" + "aa".repeat(64)
const SPEND_PRIV = "01".repeat(32)
const BOX_PUB = "02".repeat(32)
const USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
const BONK_MINT = "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263"

function makeUnsignedSwapTxBase64(payer: PublicKey): string {
  const msg = MessageV0.compile({
    payerKey: payer,
    instructions: [],
    recentBlockhash: Keypair.generate().publicKey.toBase58()
  })
  const tx = new VersionedTransaction(msg)
  return Buffer.from(tx.serialize()).toString("base64")
}

function makeNote(overrides: Partial<ShieldedNote> = {}): ShieldedNote {
  return {
    amount: "10000000",
    blinding: "bb".repeat(32),
    assetId: "00".repeat(32),
    signature: "sig-note",
    createdAt: 1,
    spent: false,
    source: "deposit",
    ...overrides
  }
}

describe("privateSwapFromToken gas rollback & recoverReshields race protection", () => {
  beforeEach(() => {
    installFakeChrome()
    vi.clearAllMocks()
  })

  it("sweeps self-funded gas SOL back into the shielded pool and dismisses the aborted SwapOutput when Step 2 (createTokenAccount) fails", async () => {
    // Step 1 gas withdraw (9,000,000 lamports) settles at fresh (~8,977,500 after 25 bps fee).
    spendV3Mock.mockResolvedValueOnce({
      requestId: "req-gas-1",
      changeLamports: 1_000_000n,
      settled: true
    })
    createTokenAccountMock.mockRejectedValueOnce(
      new Error("ATA creation did not confirm after retries")
    )
    depositV3Mock.mockResolvedValueOnce({
      signature: "sig-gas-refund-1",
      leafIndex: 7
    })

    const connection = {
      getBalance: vi.fn(async () => 8_977_500)
    } as unknown as Connection

    const tokenInput = makeNote({
      amount: "5000000",
      assetId: "11".repeat(32),
      mint: USDC_MINT
    })
    const gasInput = makeNote({
      amount: GAS_LAMPORTS.toString(),
      assetId: "00".repeat(32)
    })

    await expect(
      privateSwapFromToken(
        connection,
        ACCOUNT,
        SPEND_PRIV,
        BOX_PUB,
        [tokenInput],
        [gasInput],
        {
          inputMint: USDC_MINT,
          amountTokenUnits: 5_000_000n,
          outputMint: BONK_MINT,
          reshield: true
        }
      )
    ).rejects.toThrow("ATA creation did not confirm after retries")

    // Must sweep solBal - RESHIELD_FEE_RESERVE (8,977,500 - 1,000,000 = 7,977,500) back via depositV3
    expect(depositV3Mock).toHaveBeenCalledTimes(1)
    expect(depositV3Mock.mock.calls[0][2]).toBe(ACCOUNT)
    expect(depositV3Mock.mock.calls[0][4]).toBe(7_977_500n)

    // Aborted SwapOutput row must be dismissed once gas SOL is swept back so
    // reconcileSwapOutputs cannot misclassify it as a stranded SOL swap.
    expect(await listSwapOutputs()).toEqual([])
  })

  it("sweeps remaining self-funded gas SOL back into the shielded pool when Step 3 (token withdraw spendV3) fails before settlement, while preserving the key if the refund deposit fails", async () => {
    // First attempt: Step 1 gas withdraw settles, Step 2 ATA creation succeeds
    // (~6,933,220 lamports left), Step 3 token withdraw fails to settle.
    spendV3Mock
      .mockResolvedValueOnce({
        requestId: "req-gas-2",
        changeLamports: 0n,
        settled: true
      })
      .mockResolvedValueOnce({
        requestId: "req-tok-2",
        changeLamports: 0n,
        settled: false
      })
    createTokenAccountMock.mockResolvedValueOnce(Keypair.generate().publicKey)
    depositV3Mock.mockResolvedValueOnce({
      signature: "sig-gas-refund-2",
      leafIndex: 8
    })

    const connection = {
      getBalance: vi.fn(async () => 6_933_220)
    } as unknown as Connection

    const tokenInput = makeNote({
      amount: "5000000",
      assetId: "11".repeat(32),
      mint: USDC_MINT
    })
    const gasInput = makeNote({
      amount: GAS_LAMPORTS.toString(),
      assetId: "00".repeat(32)
    })

    await expect(
      privateSwapFromToken(
        connection,
        ACCOUNT,
        SPEND_PRIV,
        BOX_PUB,
        [tokenInput],
        [gasInput],
        {
          inputMint: USDC_MINT,
          amountTokenUnits: 5_000_000n,
          outputMint: WSOL_MINT,
          reshield: true
        }
      )
    ).rejects.toThrow("token withdraw did not settle in time")

    expect(depositV3Mock).toHaveBeenCalledTimes(1)
    expect(depositV3Mock.mock.calls[0][4]).toBe(5_933_220n)
    expect(await listSwapOutputs()).toEqual([])

    // Second attempt: if depositV3 throws during the gas rollback, the saved
    // SwapOutput row (with freshSecretKeyHex) must NOT be dismissed.
    spendV3Mock
      .mockResolvedValueOnce({
        requestId: "req-gas-3",
        changeLamports: 0n,
        settled: true
      })
      .mockRejectedValueOnce(new Error("Ingress rejected the transact (503)"))
    createTokenAccountMock.mockResolvedValueOnce(Keypair.generate().publicKey)
    depositV3Mock.mockRejectedValueOnce(new Error("RPC unreachable"))

    await expect(
      privateSwapFromToken(
        connection,
        ACCOUNT,
        SPEND_PRIV,
        BOX_PUB,
        [tokenInput],
        [gasInput],
        {
          inputMint: USDC_MINT,
          amountTokenUnits: 5_000_000n,
          outputMint: BONK_MINT,
          reshield: true
        }
      )
    ).rejects.toThrow("Ingress rejected the transact (503)")

    const remaining = await listSwapOutputs()
    expect(remaining).toHaveLength(1)
    expect(remaining[0].freshSecretKeyHex).toHaveLength(128)
  })

  it("skips in-flight swap rows younger than RESUME_GRACE_MS in recoverReshields so it cannot race an active swap's reshieldToken and double-book a phantom SPL note", async () => {
    const fresh = Keypair.generate()
    // Simulate a swap row right after privateSwap submitted swapSignature
    // (while waitForSwapConfirmation / reshieldToken is still in flight).
    await saveSwapOutput({
      freshAddress: fresh.publicKey.toBase58(),
      freshSecretKeyHex: Buffer.from(fresh.secretKey).toString("hex"),
      outputMint: USDC_MINT,
      outAmount: 2_500_000,
      swapSignature: "sig-swap-inflight",
      reshield: true,
      createdAt: Date.now() - (RESUME_GRACE_MS - 10_000)
    })

    recoverReshieldedNoteMock.mockResolvedValue(null)
    depositSplMock.mockImplementation(
      async (
        _conn: unknown,
        _dep: unknown,
        _addr: unknown,
        _mint: unknown,
        amount: bigint,
        assetId: string,
        _prog: unknown,
        onSubmitted?: (r: {
          signature: string
          blinding: Uint8Array
          assetId: string
          amount: bigint
        }) => Promise<void>
      ) => {
        const res = {
          signature: "sig-competing-deposit-spl",
          blinding: new Uint8Array(32).fill(9),
          assetId,
          amount
        }
        if (onSubmitted) await onSubmitted(res)
        return res
      }
    )

    const connection = {
      getTokenAccountBalance: vi.fn(async () => ({
        value: { amount: "2500000" }
      }))
    } as unknown as Connection

    const recovered = await recoverReshields(connection, ACCOUNT)
    expect(recovered).toBe(0)
    expect(depositSplMock).not.toHaveBeenCalled()
    expect(await getNotes(ACCOUNT)).toHaveLength(0)
  })

  it("persists reshieldRecovered: true when re-shielding succeeds in privateSwap, privateSwapFromToken, and reconcileSwapOutputs so subsequent recoverReshields runs do not re-scan or duplicate deposits", async () => {
    // 1. Normal privateSwap (SOL -> USDC with reshield: true)
    spendV3Mock.mockImplementationOnce(
      async (
        _conn: unknown,
        _addr: unknown,
        _priv: unknown,
        _box: unknown,
        _inputs: unknown,
        _amt: unknown,
        _dest: unknown,
        opts?: { confirmSettled?: () => Promise<boolean> }
      ) => {
        if (opts?.confirmSettled) await opts.confirmSettled()
        return { requestId: "req-sol-swap", changeLamports: 0n, settled: true }
      }
    )

    let swapPayer: PublicKey | null = null
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(async (_input, init) => {
        const body = JSON.parse(String(init?.body ?? "{}")) as {
          user_public_key: string
        }
        swapPayer = new PublicKey(body.user_public_key)
        return new Response(
          JSON.stringify({
            out_amount: 1_500_000,
            swap_transaction: makeUnsignedSwapTxBase64(swapPayer)
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        )
      })

    let submittedCounter = 0
    depositSplMock.mockImplementation(
      async (
        _conn: unknown,
        _dep: unknown,
        _addr: unknown,
        _mint: unknown,
        amount: bigint,
        assetId: string,
        _prog: unknown,
        onSubmitted?: (r: {
          signature: string
          blinding: Uint8Array
          assetId: string
          amount: bigint
        }) => Promise<void>
      ) => {
        submittedCounter++
        const res = {
          signature: `sig-reshield-${submittedCounter}`,
          blinding: new Uint8Array(32).fill(submittedCounter),
          assetId,
          amount
        }
        if (onSubmitted) await onSubmitted(res)
        return res
      }
    )

    const connection = {
      getBalance: vi.fn(async () => 15_000_000),
      sendRawTransaction: vi.fn(async () => "sig-swap-ok"),
      getSignatureStatus: vi.fn(async () => ({
        value: { err: null, confirmationStatus: "confirmed" }
      })),
      getTokenAccountBalance: vi.fn(async () => ({
        value: { amount: "1500000" }
      }))
    } as unknown as Connection

    const res = await privateSwap(
      connection,
      ACCOUNT,
      SPEND_PRIV,
      BOX_PUB,
      [makeNote({ amount: "20000000" })],
      {
        outputMint: USDC_MINT,
        amountLamports: 15_000_000n,
        reshield: true
      },
      undefined,
      (note) => persistReshieldedNote(ACCOUNT, note)
    )

    expect(res.reshielded).toBeDefined()
    const outputsAfterSwap = await listSwapOutputs()
    expect(outputsAfterSwap).toHaveLength(1)
    expect(outputsAfterSwap[0].reshield).toBe(true)
    expect(outputsAfterSwap[0].reshieldRecovered).toBe(true)

    // 2. Also verify reconcileSwapOutputs marks reshieldRecovered: true when a
    //    resumed swap's re-shield succeeds.
    const strandedFresh = Keypair.generate()
    await saveSwapOutput({
      freshAddress: strandedFresh.publicKey.toBase58(),
      freshSecretKeyHex: Buffer.from(strandedFresh.secretKey).toString("hex"),
      outputMint: BONK_MINT,
      outAmount: 0,
      swapSignature: "",
      reshield: true,
      createdAt: Date.now() - (RESUME_GRACE_MS + 5_000)
    })

    const resolved = await reconcileSwapOutputs(connection, ACCOUNT)
    expect(resolved).toBe(1)

    const allOutputs = await listSwapOutputs()
    const resumedRow = allOutputs.find(
      (o) => o.freshAddress === strandedFresh.publicKey.toBase58()
    )!
    expect(resumedRow.swapSignature).toBe("sig-swap-ok")
    expect(resumedRow.reshieldRecovered).toBe(true)

    // Backdate both rows past RESUME_GRACE_MS and verify recoverReshields skips
    // both because reshieldRecovered is already true.
    for (const o of allOutputs) {
      await saveSwapOutput({
        ...o,
        createdAt: Date.now() - (RESUME_GRACE_MS + 60_000)
      })
    }
    depositSplMock.mockClear()
    recoverReshieldedNoteMock.mockClear()

    const recovered = await recoverReshields(connection, ACCOUNT)
    expect(recovered).toBe(0)
    expect(recoverReshieldedNoteMock).not.toHaveBeenCalled()
    expect(depositSplMock).not.toHaveBeenCalled()

    fetchSpy.mockRestore()
  })
})
