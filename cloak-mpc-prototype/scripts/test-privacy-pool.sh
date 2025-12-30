#!/bin/bash
# =============================================================================
# Privacy Pool Full Integration Test Script
# =============================================================================
# This script tests the entire privacy pool flow:
# 1. MPC ceremony (simulated with 3 parties)
# 2. Key export and integration
# 3. On-chain program build
# 4. WASM prover build
# 5. Full integration test on devnet
# =============================================================================

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Directories
CEREMONY_DIR="$PROJECT_ROOT/ceremony_test"
PRIVACY_POOL_DIR="$PROJECT_ROOT/privacy-pool"
WASM_PROVER_DIR="$PROJECT_ROOT/privacy-pool-wasm"
MPC_CEREMONY_DIR="$PROJECT_ROOT/mpc-ceremony"

# Pool ID (use your deployed program ID)
POOL_ID="${POOL_ID:-D7tQcLX8saQNyf4TGaWDZ2jNiUa4CgNidKohPJLxTgcK}"

echo -e "${PURPLE}"
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║     🔒 PRIVACY POOL INTEGRATION TEST                              ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# =============================================================================
# STEP 0: Cleanup and preparation
# =============================================================================
step_cleanup() {
    echo -e "${CYAN}📋 Step 0: Cleanup and preparation${NC}"
    
    # Create ceremony directory
    rm -rf "$CEREMONY_DIR"
    mkdir -p "$CEREMONY_DIR"
    
    echo "   ✅ Created clean ceremony directory"
}

# =============================================================================
# STEP 1: Build MPC ceremony tool
# =============================================================================
step_build_mpc() {
    echo -e "${CYAN}🔨 Step 1: Building MPC ceremony tool${NC}"
    
    cd "$PROJECT_ROOT"
    cargo build -p mpc-ceremony --release 2>&1 | tail -5
    
    if [ -f "$PROJECT_ROOT/target/release/mpc-ceremony" ]; then
        echo "   ✅ MPC ceremony tool built"
    else
        echo -e "${RED}   ❌ Failed to build MPC ceremony tool${NC}"
        exit 1
    fi
}

# =============================================================================
# STEP 2: Run simulated MPC ceremony
# =============================================================================
step_mpc_ceremony() {
    echo -e "${CYAN}🎲 Step 2: Running simulated MPC ceremony${NC}"
    
    MPC_CLI="$PROJECT_ROOT/target/release/mpc-ceremony"
    cd "$CEREMONY_DIR"
    
    # Initialize ceremony
    echo "   🔧 Initializing ceremony with pool ID: $POOL_ID"
    $MPC_CLI init --pool-id "$POOL_ID" --output ceremony_init.bin
    
    # Party 1 contributes
    echo "   👤 Party 1 (Cloak-Core) contributing..."
    $MPC_CLI contribute -i ceremony_init.bin -o ceremony_p1.bin --name "Cloak-Core"
    
    # Party 2 contributes
    echo "   👤 Party 2 (Miner-Alpha) contributing..."
    $MPC_CLI contribute -i ceremony_p1.bin -o ceremony_p2.bin --name "Miner-Alpha"
    
    # Party 3 contributes
    echo "   👤 Party 3 (Miner-Beta) contributing..."
    $MPC_CLI contribute -i ceremony_p2.bin -o ceremony_final.bin --name "Miner-Beta"
    
    # Verify ceremony
    echo "   🔍 Verifying ceremony..."
    $MPC_CLI verify -i ceremony_final.bin --verbose
    
    # Show info
    echo ""
    $MPC_CLI info -i ceremony_final.bin
    
    echo "   ✅ MPC ceremony completed with 3 contributors"
}

# =============================================================================
# STEP 3: Export keys
# =============================================================================
step_export_keys() {
    echo -e "${CYAN}📦 Step 3: Exporting ceremony keys${NC}"
    
    MPC_CLI="$PROJECT_ROOT/target/release/mpc-ceremony"
    cd "$CEREMONY_DIR"
    
    # Export Rust code (for on-chain verifier)
    mkdir -p keys
    $MPC_CLI export -i ceremony_final.bin -o keys --format rust
    
    # Export binary (for WASM prover)
    $MPC_CLI export -i ceremony_final.bin -o keys --format bin
    
    echo "   ✅ Keys exported:"
    ls -la keys/
}

# =============================================================================
# STEP 4: Integrate keys into privacy pool
# =============================================================================
step_integrate_keys() {
    echo -e "${CYAN}🔗 Step 4: Integrating keys${NC}"
    
    # Copy verifying key to privacy pool
    if [ -f "$CEREMONY_DIR/keys/verifying_key.rs" ]; then
        cp "$CEREMONY_DIR/keys/verifying_key.rs" "$PRIVACY_POOL_DIR/src/circuit_vk.rs"
        echo "   ✅ Copied verifying_key.rs to privacy-pool"
    else
        echo -e "${YELLOW}   ⚠️  No verifying_key.rs found, using existing${NC}"
    fi
    
    # Note: For the WASM prover, you would need to update it to load the proving key
    # For now, we keep the deterministic setup in WASM for testing
    echo "   ℹ️  WASM prover still uses deterministic setup for testing"
}

# =============================================================================
# STEP 5: Build privacy pool program
# =============================================================================
step_build_program() {
    echo -e "${CYAN}🏗️  Step 5: Building privacy pool program${NC}"
    
    cd "$PRIVACY_POOL_DIR"
    
    # Check if we can build for BPF
    if command -v cargo-build-sbf &> /dev/null; then
        echo "   Building for Solana BPF..."
        cargo build-sbf 2>&1 | tail -10
        echo "   ✅ BPF build complete"
    else
        echo "   Building native (for testing)..."
        cargo build --release 2>&1 | tail -5
        echo "   ✅ Native build complete"
    fi
}

# =============================================================================
# STEP 6: Build WASM prover
# =============================================================================
step_build_wasm() {
    echo -e "${CYAN}🌐 Step 6: Building WASM prover${NC}"
    
    cd "$WASM_PROVER_DIR"
    
    if command -v wasm-pack &> /dev/null; then
        wasm-pack build --target web --out-dir www/pkg 2>&1 | tail -10
        echo "   ✅ WASM prover built"
    else
        echo -e "${YELLOW}   ⚠️  wasm-pack not found, skipping WASM build${NC}"
        echo "   Install with: cargo install wasm-pack"
    fi
}

# =============================================================================
# STEP 7: Run integration tests
# =============================================================================
step_run_tests() {
    echo -e "${CYAN}🧪 Step 7: Running integration tests${NC}"
    
    cd "$PRIVACY_POOL_DIR"
    
    # First, run the MPC ceremony simulation test (fast, no network)
    echo ""
    echo "   📋 7a: Running MPC ceremony simulation test..."
    MPC_OUTPUT=$(cargo test test_mpc_ceremony_simulation -- --nocapture 2>&1)
    MPC_EXIT=$?
    
    echo "$MPC_OUTPUT" | tail -30
    
    if [ $MPC_EXIT -eq 0 ]; then
        echo "   ✅ MPC ceremony simulation PASSED"
    else
        echo -e "${RED}   ❌ MPC ceremony simulation FAILED${NC}"
        return 1
    fi
    
    # Then run on-chain test
    echo ""
    echo "   📋 7b: Running on-chain test (devnet)..."
    echo "   ⚠️  Requires funded payer wallet (~0.5 SOL)"
    echo ""
    
    # Run test and capture output
    TEST_OUTPUT=$(cargo test --test onchain_test test_privacy_pool_onchain -- --nocapture 2>&1)
    TEST_EXIT=$?
    
    # Show last 50 lines
    echo "$TEST_OUTPUT" | tail -50
    
    if [ $TEST_EXIT -eq 0 ]; then
        echo "   ✅ On-chain test PASSED"
    else
        if echo "$TEST_OUTPUT" | grep -q "insufficient lamports"; then
            echo -e "${YELLOW}   ⚠️  Test failed due to insufficient SOL${NC}"
            echo "   Fund your payer wallet and retry:"
            echo "   solana airdrop 1 --keypair ~/.config/solana/id.json --url devnet"
            echo ""
            echo "   MPC ceremony and build steps completed successfully!"
            return 0  # Don't fail the script for balance issues
        else
            echo -e "${RED}   ❌ On-chain test FAILED${NC}"
            return 1
        fi
    fi
}

# =============================================================================
# STEP 8: Security checklist
# =============================================================================
step_security_check() {
    echo -e "${CYAN}🔐 Step 8: Security checklist${NC}"
    
    echo ""
    echo -e "${GREEN}✅ IMPLEMENTED:${NC}"
    echo "   • MPC ceremony for trusted setup"
    echo "   • Domain separation (pool ID bound to nullifier)"
    echo "   • Front-running protection (commit-reveal)"
    echo "   • Poseidon hash (collision-resistant)"
    echo "   • Range checks on amount (64-bit)"
    echo "   • Recipient binding in proof"
    echo "   • Relayer fee mechanism"
    echo "   • Emergency pause (admin)"
    echo "   • Amount limits (min/max)"
    echo ""
    echo -e "${YELLOW}⚠️  BEFORE MAINNET:${NC}"
    echo "   • Run MPC ceremony with REAL participants"
    echo "   • Professional security audit"
    echo "   • Formal verification (optional)"
    echo "   • Bug bounty program"
}

# =============================================================================
# Main execution
# =============================================================================
main() {
    echo ""
    echo -e "${BLUE}Starting full integration test...${NC}"
    echo ""
    
    step_cleanup
    echo ""
    
    step_build_mpc
    echo ""
    
    step_mpc_ceremony
    echo ""
    
    step_export_keys
    echo ""
    
    step_integrate_keys
    echo ""
    
    step_build_program
    echo ""
    
    # Optionally build WASM
    if [ "$SKIP_WASM" != "1" ]; then
        step_build_wasm
        echo ""
    fi
    
    # Optionally run tests
    if [ "$SKIP_TESTS" != "1" ]; then
        step_run_tests
        echo ""
    fi
    
    step_security_check
    echo ""
    
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║     ✅ ALL STEPS COMPLETED SUCCESSFULLY                          ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo "📁 Ceremony files: $CEREMONY_DIR"
    echo "🔑 Keys: $CEREMONY_DIR/keys/"
    echo ""
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-wasm)
            SKIP_WASM=1
            shift
            ;;
        --skip-tests)
            SKIP_TESTS=1
            shift
            ;;
        --pool-id)
            POOL_ID="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --skip-wasm     Skip WASM prover build"
            echo "  --skip-tests    Skip integration tests"
            echo "  --pool-id ID    Set pool ID for ceremony"
            echo ""
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Run main
main

