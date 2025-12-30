"use client";

import { useEffect, useState, useCallback } from "react";
import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  SystemProgram,
  TransactionInstruction,
  LAMPORTS_PER_SOL,
} from "@solana/web3.js";
import bs58 from "bs58";

const PROGRAM_ID = new PublicKey("D7tQcLX8saQNyf4TGaWDZ2jNiUa4CgNidKohPJLxTgcK");
const RPC_URL = "https://api.devnet.solana.com";
const POOL_STATE_SIZE = 64 + 32 * 1024 * 2;

type Step = "idle" | "funding" | "creating_pool" | "depositing" | "updating_root" | "proving" | "withdrawing" | "done";

interface Wallets {
  payer: Keypair | null;
  depositor: Keypair;
  relayer: Keypair;
  recipient: Keypair;
}

interface Secrets {
  secret: string;
  nullifier: string;
}

interface WasmModule {
  generate_commitment: (secret: string, nullifier: string, amount: bigint) => string;
  generate_withdrawal_proof: (secret: string, nullifier: string, recipient: string, amount: bigint) => string;
  build_merkle_tree: (commitments: string, index: number) => string;
  get_prover_info: () => string;
}

export default function Home() {
  const [connection] = useState(() => new Connection(RPC_URL, "confirmed"));
  const [wallets, setWallets] = useState<Wallets | null>(null);
  const [secrets, setSecrets] = useState<Secrets | null>(null);
  const [poolState, setPoolState] = useState<Keypair | null>(null);
  const [wasm, setWasm] = useState<WasmModule | null>(null);
  const [step, setStep] = useState<Step>("idle");
  const [logs, setLogs] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [txSignatures, setTxSignatures] = useState<{ [key: string]: string }>({});
  const [balances, setBalances] = useState<{ [key: string]: number }>({});
  const [payerInput, setPayerInput] = useState("");
  const [useAirdrop, setUseAirdrop] = useState(false);

  const log = useCallback((msg: string) => {
    console.log(msg);
    setLogs((prev) => [...prev, `${new Date().toLocaleTimeString()} | ${msg}`]);
  }, []);

  const randomHex = (bytes: number): string => {
    const arr = new Uint8Array(bytes);
    crypto.getRandomValues(arr);
    return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
  };

  // Initialize other wallets and WASM on load
  useEffect(() => {
    const init = async () => {
      log("🔑 Generating participant keypairs...");
      const newWallets: Wallets = {
        payer: null, // Will be set by user
        depositor: Keypair.generate(),
        relayer: Keypair.generate(),
        recipient: Keypair.generate(),
      };
      setWallets(newWallets);
      log(`  Depositor: ${newWallets.depositor.publicKey.toBase58()}`);
      log(`  Relayer: ${newWallets.relayer.publicKey.toBase58()}`);
      log(`  Recipient: ${newWallets.recipient.publicKey.toBase58()}`);

      const secret = randomHex(32);
      const nullifier = randomHex(32);
      setSecrets({ secret, nullifier });
      log("🎲 Generated random secrets");

      log("📦 Loading WASM prover...");
      try {
        const script = document.createElement("script");
        script.type = "module";
        script.innerHTML = `
          import init, * as wasm from '/pkg/privacy_pool_wasm.js';
          await init();
          window.__privacyPoolWasm = wasm;
          window.dispatchEvent(new Event('wasmReady'));
        `;
        document.head.appendChild(script);
        
        await new Promise<void>((resolve, reject) => {
          const timeout = setTimeout(() => reject(new Error("WASM load timeout")), 30000);
          window.addEventListener("wasmReady", () => {
            clearTimeout(timeout);
            resolve();
          }, { once: true });
        });
        
        const wasmModule = (window as unknown as { __privacyPoolWasm: WasmModule }).__privacyPoolWasm;
        setWasm(wasmModule);
        const info = JSON.parse(wasmModule.get_prover_info());
        log(`✅ WASM loaded: ${info.name} (${info.proof_system})`);
      } catch (e) {
        log(`❌ Failed to load WASM: ${e}`);
        setError("Failed to load WASM prover");
      }
    };
    init();
  }, [log]);

  const loadPayerFromInput = () => {
    try {
      let keypair: Keypair;
      const trimmed = payerInput.trim();
      
      // Try parsing as JSON array
      if (trimmed.startsWith("[")) {
        const bytes = JSON.parse(trimmed) as number[];
        keypair = Keypair.fromSecretKey(new Uint8Array(bytes));
      } 
      // Try parsing as base58
      else {
        const bytes = bs58.decode(trimmed);
        keypair = Keypair.fromSecretKey(bytes);
      }
      
      setWallets((prev) => prev ? { ...prev, payer: keypair } : null);
      log(`✅ Payer loaded: ${keypair.publicKey.toBase58()}`);
      setError(null);
    } catch (e) {
      setError("Invalid private key format. Use base58 or JSON array.");
    }
  };

  const setupWithAirdrop = async () => {
    if (!wallets) return;
    setUseAirdrop(true);
    
    const payer = Keypair.generate();
    setWallets((prev) => prev ? { ...prev, payer } : null);
    log(`🎲 Generated payer: ${payer.publicKey.toBase58()}`);
    log("⏳ Requesting airdrop (this may take a few attempts)...");
    
    // Try airdrop with retries
    for (let i = 0; i < 5; i++) {
      try {
        const sig = await connection.requestAirdrop(payer.publicKey, 2 * LAMPORTS_PER_SOL);
        await connection.confirmTransaction(sig, "confirmed");
        log(`✅ Airdrop successful! Payer has 2 SOL`);
        setError(null);
        return;
      } catch (e) {
        log(`  Attempt ${i + 1}/5 failed, retrying...`);
        await new Promise((r) => setTimeout(r, 2000));
      }
    }
    setError("Airdrop failed after 5 attempts. Please use your own wallet or try later.");
    setUseAirdrop(false);
  };

  const updateBalances = async () => {
    if (!wallets) return;
    const newBalances: { [key: string]: number } = {};
    for (const [name, kp] of Object.entries(wallets)) {
      if (!kp) continue;
      try {
        const bal = await connection.getBalance(kp.publicKey);
        newBalances[name] = bal / LAMPORTS_PER_SOL;
      } catch {
        newBalances[name] = 0;
      }
    }
    setBalances(newBalances);
  };

  const runDemo = async () => {
    if (!wallets || !wallets.payer || !secrets || !wasm) return;
    setError(null);
    setTxSignatures({});

    const payer = wallets.payer;
    const depositAmount = 100_000_000; // 0.1 SOL

    try {
      // Step 1: Fund participant wallets from payer
      setStep("funding");
      log("💸 Funding participant wallets from payer...");
      
      const fundTx = new Transaction().add(
        SystemProgram.transfer({
          fromPubkey: payer.publicKey,
          toPubkey: wallets.depositor.publicKey,
          lamports: 0.3 * LAMPORTS_PER_SOL,
        }),
        SystemProgram.transfer({
          fromPubkey: payer.publicKey,
          toPubkey: wallets.relayer.publicKey,
          lamports: 0.05 * LAMPORTS_PER_SOL,
        })
      );
      fundTx.feePayer = payer.publicKey;
      fundTx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
      fundTx.sign(payer);
      
      const fundSig = await connection.sendRawTransaction(fundTx.serialize());
      await connection.confirmTransaction(fundSig, "confirmed");
      log("  ✅ Depositor funded (0.3 SOL)");
      log("  ✅ Relayer funded (0.05 SOL)");
      await updateBalances();

      // Step 2: Create pool account
      setStep("creating_pool");
      log("📦 Creating pool account...");
      
      const newPoolState = Keypair.generate();
      setPoolState(newPoolState);
      
      const rent = await connection.getMinimumBalanceForRentExemption(POOL_STATE_SIZE);
      
      const createPoolTx = new Transaction().add(
        SystemProgram.createAccount({
          fromPubkey: payer.publicKey,
          newAccountPubkey: newPoolState.publicKey,
          lamports: rent + depositAmount * 2,
          space: POOL_STATE_SIZE,
          programId: PROGRAM_ID,
        })
      );
      createPoolTx.feePayer = payer.publicKey;
      createPoolTx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
      createPoolTx.sign(payer, newPoolState);
      
      const createSig = await connection.sendRawTransaction(createPoolTx.serialize());
      await connection.confirmTransaction(createSig, "confirmed");
      setTxSignatures((prev) => ({ ...prev, create: createSig }));
      log(`  ✅ Pool created: ${newPoolState.publicKey.toBase58().slice(0, 20)}...`);

      // Initialize pool
      const initTx = new Transaction().add(
        new TransactionInstruction({
          programId: PROGRAM_ID,
          keys: [
            { pubkey: newPoolState.publicKey, isSigner: false, isWritable: true },
            { pubkey: payer.publicKey, isSigner: true, isWritable: true },
            { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
          ],
          data: Buffer.from([0]),
        })
      );
      initTx.feePayer = payer.publicKey;
      initTx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
      initTx.sign(payer);
      
      const initSig = await connection.sendRawTransaction(initTx.serialize());
      await connection.confirmTransaction(initSig, "confirmed");
      setTxSignatures((prev) => ({ ...prev, init: initSig }));
      log("  ✅ Pool initialized");

      // Step 3: Generate commitment and deposit
      setStep("depositing");
      log("📝 Generating commitment...");
      
      const commitmentResult = JSON.parse(
        wasm.generate_commitment(secrets.secret, secrets.nullifier, BigInt(depositAmount))
      );
      log(`  Commitment: ${commitmentResult.commitment.slice(0, 16)}...`);

      log("💰 Depositing 0.1 SOL...");
      const depositData = Buffer.alloc(41);
      depositData[0] = 1;
      Buffer.from(commitmentResult.commitment, "hex").copy(depositData, 1);
      depositData.writeBigUInt64LE(BigInt(depositAmount), 33);

      const depositTx = new Transaction().add(
        new TransactionInstruction({
          programId: PROGRAM_ID,
          keys: [
            { pubkey: newPoolState.publicKey, isSigner: false, isWritable: true },
            { pubkey: wallets.depositor.publicKey, isSigner: true, isWritable: true },
            { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
          ],
          data: depositData,
        })
      );
      depositTx.feePayer = wallets.depositor.publicKey;
      depositTx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
      depositTx.sign(wallets.depositor);
      
      const depositSig = await connection.sendRawTransaction(depositTx.serialize());
      await connection.confirmTransaction(depositSig, "confirmed");
      setTxSignatures((prev) => ({ ...prev, deposit: depositSig }));
      log(`  ✅ Deposit TX: ${depositSig.slice(0, 20)}...`);

      // Step 4: Build Merkle tree and update root
      setStep("updating_root");
      log("🌳 Building Merkle tree...");
      
      const merkleResult = JSON.parse(
        wasm.build_merkle_tree(commitmentResult.commitment, 0)
      );
      log(`  Root: ${merkleResult.root.slice(0, 16)}...`);

      log("📝 Updating on-chain Merkle root...");
      const updateRootData = Buffer.alloc(33);
      updateRootData[0] = 3;
      Buffer.from(merkleResult.root, "hex").copy(updateRootData, 1);

      const updateRootTx = new Transaction().add(
        new TransactionInstruction({
          programId: PROGRAM_ID,
          keys: [
            { pubkey: newPoolState.publicKey, isSigner: false, isWritable: true },
            { pubkey: payer.publicKey, isSigner: true, isWritable: false },
          ],
          data: updateRootData,
        })
      );
      updateRootTx.feePayer = payer.publicKey;
      updateRootTx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
      updateRootTx.sign(payer);
      
      const updateRootSig = await connection.sendRawTransaction(updateRootTx.serialize());
      await connection.confirmTransaction(updateRootSig, "confirmed");
      setTxSignatures((prev) => ({ ...prev, updateRoot: updateRootSig }));
      log("  ✅ Root updated");

      // Step 5: Generate ZK proof
      setStep("proving");
      log("🔐 Generating Groth16 proof (this may take 10-30s)...");
      
      const recipientHex = Buffer.from(wallets.recipient.publicKey.toBytes()).toString("hex");
      
      // Use setTimeout to allow UI to update
      const proofResult = await new Promise<ReturnType<typeof JSON.parse>>((resolve) => {
        setTimeout(() => {
          const result = JSON.parse(
            wasm.generate_withdrawal_proof(secrets.secret, secrets.nullifier, recipientHex, BigInt(depositAmount))
          );
          resolve(result);
        }, 100);
      });
      
      if (proofResult.error) {
        throw new Error(proofResult.error);
      }
      log(`  ✅ Proof generated in ${(proofResult.time_ms / 1000).toFixed(2)}s`);

      // Step 6: Submit withdrawal
      setStep("withdrawing");
      log("📤 Submitting withdrawal (RELAYER signs - not depositor!)...");
      
      // Format: discriminator(1) + proof_a(64) + proof_b(128) + proof_c(64) + 
      //         commitment(32) + nullifier_hash(32) + recipient_fr(32) + amount_fr(32) +
      //         leaf_index(4) + merkle_proof_len(1) + merkle_proof(len*32)
      const merkleProofLen = merkleResult.proof.length;
      const withdrawData = Buffer.alloc(1 + 64 + 128 + 64 + 32 + 32 + 32 + 32 + 4 + 1 + merkleProofLen * 32);
      let offset = 0;
      
      withdrawData[offset++] = 2; // discriminator
      Buffer.from(proofResult.proof_a, "hex").copy(withdrawData, offset); offset += 64;
      Buffer.from(proofResult.proof_b, "hex").copy(withdrawData, offset); offset += 128;
      Buffer.from(proofResult.proof_c, "hex").copy(withdrawData, offset); offset += 64;
      Buffer.from(proofResult.commitment, "hex").copy(withdrawData, offset); offset += 32;
      Buffer.from(proofResult.nullifier_hash, "hex").copy(withdrawData, offset); offset += 32;
      Buffer.from(proofResult.recipient_fr, "hex").copy(withdrawData, offset); offset += 32;
      Buffer.from(proofResult.amount_fr, "hex").copy(withdrawData, offset); offset += 32;
      withdrawData.writeUInt32LE(0, offset); offset += 4; // leaf_index = 0 (first deposit)
      withdrawData[offset++] = merkleProofLen;
      
      for (const sibling of merkleResult.proof) {
        Buffer.from(sibling, "hex").copy(withdrawData, offset);
        offset += 32;
      }
      
      log(`  📦 Withdraw data: ${withdrawData.length} bytes, proof siblings: ${merkleProofLen}`);

      const withdrawTx = new Transaction().add(
        new TransactionInstruction({
          programId: PROGRAM_ID,
          keys: [
            { pubkey: newPoolState.publicKey, isSigner: false, isWritable: true },
            { pubkey: wallets.recipient.publicKey, isSigner: false, isWritable: true },
          ],
          data: withdrawData, // Use full buffer, already correctly sized
        })
      );
      withdrawTx.feePayer = wallets.relayer.publicKey;
      withdrawTx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
      withdrawTx.sign(wallets.relayer);
      
      const withdrawSig = await connection.sendRawTransaction(withdrawTx.serialize());
      await connection.confirmTransaction(withdrawSig, "confirmed");
      setTxSignatures((prev) => ({ ...prev, withdraw: withdrawSig }));
      log(`  🎉 WITHDRAWAL SUCCESSFUL!`);
      log(`  TX: ${withdrawSig}`);

      await updateBalances();
      setStep("done");
      log("✅ Demo complete! Recipient received 0.1 SOL");
      log("");
      log("🔒 PRIVACY ACHIEVED:");
      log("   • Depositor ≠ Relayer ≠ Recipient");
      log("   • ZK proof hides which deposit was withdrawn");
      log("   • Nullifier prevents double-spending");

    } catch (e: unknown) {
      const errorMessage = e instanceof Error ? e.message : String(e);
      log(`❌ Error: ${errorMessage}`);
      setError(errorMessage);
      setStep("idle");
    }
  };

  const stepLabels: { [key in Step]: string } = {
    idle: "Ready",
    funding: "Funding wallets...",
    creating_pool: "Creating pool...",
    depositing: "Depositing...",
    updating_root: "Updating Merkle root...",
    proving: "Generating ZK proof...",
    withdrawing: "Withdrawing...",
    done: "Complete!",
  };

  const canRun = wallets?.payer && wasm && (step === "idle" || step === "done");

  return (
    <main className="min-h-screen p-8">
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold mb-2">
            <span className="text-[var(--accent)]">🔐</span> Privacy Pool Demo
          </h1>
          <p className="text-gray-400">
            ZK-powered private transfers on Solana • Groth16 proofs generated in your browser
          </p>
        </div>

        {/* Payer Setup */}
        {!wallets?.payer && (
          <div className="card p-6 mb-6">
            <h2 className="text-lg font-semibold mb-4">💳 Setup Payer Wallet</h2>
            <p className="text-gray-400 text-sm mb-4">
              You need a funded devnet wallet to run this demo. Choose one option:
            </p>
            
            <div className="space-y-4">
              {/* Option 1: Paste private key */}
              <div className="bg-black/30 p-4 rounded-lg">
                <div className="font-medium mb-2">Option 1: Use your devnet wallet</div>
                <p className="text-gray-400 text-xs mb-2">
                  Paste your private key (base58 or JSON array from ~/.config/solana/id.json)
                </p>
                <div className="flex gap-2">
                  <input
                    type="password"
                    className="flex-1 bg-black border border-[var(--border)] rounded px-3 py-2 text-sm mono"
                    placeholder="Paste private key..."
                    value={payerInput}
                    onChange={(e) => setPayerInput(e.target.value)}
                  />
                  <button className="btn-primary" onClick={loadPayerFromInput}>
                    Load
                  </button>
                </div>
              </div>

              {/* Option 2: Airdrop */}
              <div className="bg-black/30 p-4 rounded-lg">
                <div className="font-medium mb-2">Option 2: Request airdrop (may be slow/fail)</div>
                <p className="text-gray-400 text-xs mb-2">
                  Generate a new wallet and request 2 SOL from the devnet faucet
                </p>
                <button 
                  className="btn-primary bg-gray-600" 
                  onClick={setupWithAirdrop}
                  disabled={useAirdrop}
                >
                  {useAirdrop ? "Requesting..." : "Try Airdrop"}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Status */}
        <div className="card p-4 mb-6 flex items-center justify-between">
          <div className="flex items-center gap-3">
            {step !== "idle" && step !== "done" && <span className="spinner text-[var(--accent)]" />}
            {step === "done" && <span className="text-[var(--success)] text-xl">✓</span>}
            <span className="font-medium">{stepLabels[step]}</span>
          </div>
          <button
            className="btn-primary"
            onClick={runDemo}
            disabled={!canRun}
          >
            {step === "idle" ? "▶ Run Demo" : step === "done" ? "🔄 Run Again" : "Running..."}
          </button>
        </div>

        {/* Wallets */}
        <div className="card p-4 mb-6">
          <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
            <span>👥</span> Wallets
          </h2>
          <div className="grid grid-cols-2 gap-4 text-sm">
            {wallets && (
              <>
                <div className={`bg-black/30 p-3 rounded-lg ${!wallets.payer ? 'opacity-50' : ''}`}>
                  <div className="text-gray-400 text-xs uppercase mb-1">Payer {!wallets.payer && "(not set)"}</div>
                  <div className="mono text-xs truncate">
                    {wallets.payer?.publicKey.toBase58() || "—"}
                  </div>
                  {balances.payer !== undefined && (
                    <div className="text-[var(--accent)] mt-1">{balances.payer.toFixed(4)} SOL</div>
                  )}
                </div>
                {["depositor", "relayer", "recipient"].map((name) => {
                  const kp = wallets[name as keyof Wallets] as Keypair;
                  return (
                    <div key={name} className="bg-black/30 p-3 rounded-lg">
                      <div className="text-gray-400 text-xs uppercase mb-1">{name}</div>
                      <div className="mono text-xs truncate">{kp.publicKey.toBase58()}</div>
                      {balances[name] !== undefined && (
                        <div className="text-[var(--accent)] mt-1">{balances[name].toFixed(4)} SOL</div>
                      )}
                    </div>
                  );
                })}
              </>
            )}
          </div>
        </div>

        {/* Transactions */}
        {Object.keys(txSignatures).length > 0 && (
          <div className="card p-4 mb-6">
            <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
              <span>📜</span> Transactions
            </h2>
            <div className="space-y-2 text-sm">
              {Object.entries(txSignatures).map(([name, sig]) => (
                <div key={name} className="flex items-center justify-between bg-black/30 p-2 rounded">
                  <span className="capitalize">{name}</span>
                  <a
                    href={`https://explorer.solana.com/tx/${sig}?cluster=devnet`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[var(--accent)] hover:underline mono text-xs"
                  >
                    {sig.slice(0, 20)}... ↗
                  </a>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="card p-4 mb-6 border-[var(--error)] bg-[var(--error)]/10">
            <div className="text-[var(--error)] font-medium">❌ Error</div>
            <div className="text-sm mt-1">{error}</div>
          </div>
        )}

        {/* Logs */}
        <div className="card p-4">
          <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
            <span>📋</span> Logs
          </h2>
          <div className="bg-black/50 rounded-lg p-3 h-64 overflow-y-auto mono text-xs">
            {logs.length === 0 ? (
              <div className="text-gray-500">Waiting to start...</div>
            ) : (
              logs.map((log, i) => (
                <div key={i} className="py-0.5">
                  {log}
                </div>
              ))
            )}
          </div>
        </div>

        {/* Privacy Notice */}
        <div className="text-center mt-8 text-sm text-gray-500">
          <p>🔒 All ZK proofs are generated locally in your browser</p>
          <p>Your secrets never leave your device</p>
        </div>
      </div>
    </main>
  );
}
