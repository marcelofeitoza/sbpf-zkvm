//! MPC Ceremony CLI for Groth16 Trusted Setup
//!
//! This tool enables a secure multi-party computation ceremony to generate
//! Groth16 proving/verifying keys for the Privacy Pool circuit.
//!
//! Security: As long as ONE participant is honest (uses true randomness and
//! deletes their secret), the resulting parameters are secure.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod ceremony;
mod circuit;
mod contribution;
mod transcript;
mod export;

use ceremony::Ceremony;
use contribution::Contribution;

#[derive(Parser)]
#[command(name = "mpc-ceremony")]
#[command(about = "MPC ceremony for Groth16 trusted setup", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new ceremony (first participant only)
    Init {
        /// Output file for ceremony state
        #[arg(short, long, default_value = "ceremony.bin")]
        output: PathBuf,
        
        /// Pool ID for domain separation (use your deployed program ID)
        #[arg(long)]
        pool_id: String,
    },
    
    /// Contribute randomness to an existing ceremony
    Contribute {
        /// Input ceremony file
        #[arg(short, long)]
        input: PathBuf,
        
        /// Output ceremony file with your contribution
        #[arg(short, long)]
        output: PathBuf,
        
        /// Your participant name/identifier
        #[arg(long)]
        name: String,
        
        /// Optional: Provide your own entropy (hex string). If not provided, uses OS randomness
        #[arg(long)]
        entropy: Option<String>,
    },
    
    /// Verify all contributions in a ceremony
    Verify {
        /// Ceremony file to verify
        #[arg(short, long)]
        input: PathBuf,
        
        /// Show detailed verification info
        #[arg(short, long)]
        verbose: bool,
    },
    
    /// Finalize ceremony and export keys
    Export {
        /// Final ceremony file
        #[arg(short, long)]
        input: PathBuf,
        
        /// Output directory for keys
        #[arg(short, long, default_value = ".")]
        output_dir: PathBuf,
        
        /// Export format: "rust" (embed in code) or "bin" (binary files)
        #[arg(long, default_value = "rust")]
        format: String,
    },
    
    /// Show ceremony status and contribution history
    Info {
        /// Ceremony file
        #[arg(short, long)]
        input: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Init { output, pool_id } => {
            println!("🎲 Initializing MPC ceremony...");
            println!("   Pool ID: {}", pool_id);
            
            let ceremony = Ceremony::initialize(&pool_id)
                .context("Failed to initialize ceremony")?;
            
            ceremony.save(&output)
                .context("Failed to save ceremony")?;
            
            println!("✅ Ceremony initialized!");
            println!("   Output: {}", output.display());
            println!("   Transcript hash: {}", ceremony.transcript_hash());
            println!();
            println!("📋 Next steps:");
            println!("   1. Share {} with the next participant", output.display());
            println!("   2. They run: mpc-ceremony contribute -i {} -o contrib.bin --name \"Party2\"", output.display());
        }
        
        Commands::Contribute { input, output, name, entropy } => {
            println!("🔐 Contributing to MPC ceremony...");
            println!("   Participant: {}", name);
            
            let mut ceremony = Ceremony::load(&input)
                .context("Failed to load ceremony")?;
            
            println!("   Previous contributions: {}", ceremony.num_contributions());
            println!("   Current transcript: {}", ceremony.transcript_hash());
            
            // Generate or use provided entropy
            let contribution = if let Some(hex_entropy) = entropy {
                println!("   Using provided entropy");
                Contribution::from_entropy(&hex_entropy, &name)
                    .context("Failed to create contribution from entropy")?
            } else {
                println!("   Generating secure random entropy...");
                Contribution::generate(&name)
                    .context("Failed to generate contribution")?
            };
            
            ceremony.add_contribution(contribution)
                .context("Failed to add contribution")?;
            
            ceremony.save(&output)
                .context("Failed to save ceremony")?;
            
            println!("✅ Contribution added!");
            println!("   New transcript: {}", ceremony.transcript_hash());
            println!("   Output: {}", output.display());
            println!();
            println!("⚠️  IMPORTANT: Delete any record of your secret entropy!");
            println!("   The security of this ceremony depends on it.");
        }
        
        Commands::Verify { input, verbose } => {
            println!("🔍 Verifying ceremony...");
            
            let ceremony = Ceremony::load(&input)
                .context("Failed to load ceremony")?;
            
            let verification = ceremony.verify(verbose)
                .context("Verification failed")?;
            
            if verification.is_valid {
                println!("✅ Ceremony is VALID");
                println!("   Contributions: {}", verification.num_contributions);
                println!("   Final transcript: {}", verification.final_hash);
            } else {
                println!("❌ Ceremony is INVALID");
                for error in &verification.errors {
                    println!("   Error: {}", error);
                }
            }
        }
        
        Commands::Export { input, output_dir, format } => {
            println!("📦 Exporting ceremony keys...");
            
            let ceremony = Ceremony::load(&input)
                .context("Failed to load ceremony")?;
            
            // Verify before export
            let verification = ceremony.verify(false)?;
            if !verification.is_valid {
                anyhow::bail!("Cannot export: ceremony verification failed");
            }
            
            match format.as_str() {
                "rust" => {
                    let pk_path = output_dir.join("proving_key.rs");
                    let vk_path = output_dir.join("verifying_key.rs");
                    
                    export::export_rust(&ceremony, &pk_path, &vk_path)
                        .context("Failed to export Rust code")?;
                    
                    println!("✅ Exported Rust code:");
                    println!("   Proving key:   {}", pk_path.display());
                    println!("   Verifying key: {}", vk_path.display());
                }
                "bin" => {
                    let pk_path = output_dir.join("proving_key.bin");
                    let vk_path = output_dir.join("verifying_key.bin");
                    
                    export::export_binary(&ceremony, &pk_path, &vk_path)
                        .context("Failed to export binary files")?;
                    
                    println!("✅ Exported binary files:");
                    println!("   Proving key:   {} ({} bytes)", pk_path.display(), std::fs::metadata(&pk_path)?.len());
                    println!("   Verifying key: {} ({} bytes)", vk_path.display(), std::fs::metadata(&vk_path)?.len());
                }
                _ => anyhow::bail!("Unknown format: {}. Use 'rust' or 'bin'", format),
            }
            
            println!();
            println!("📋 Integration:");
            println!("   1. Copy verifying_key.rs to privacy-pool/src/circuit_vk.rs");
            println!("   2. Copy proving_key to privacy-pool-wasm for WASM prover");
            println!("   3. Rebuild and redeploy");
        }
        
        Commands::Info { input } => {
            let ceremony = Ceremony::load(&input)
                .context("Failed to load ceremony")?;
            
            println!("📊 Ceremony Information");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("Pool ID:          {}", ceremony.pool_id());
            println!("Contributions:    {}", ceremony.num_contributions());
            println!("Transcript hash:  {}", ceremony.transcript_hash());
            println!();
            println!("Contribution History:");
            for (i, contrib) in ceremony.contributions().iter().enumerate() {
                println!("  {}. {} ({})", i + 1, contrib.name, contrib.timestamp);
                println!("     Hash: {}", contrib.hash);
            }
        }
    }
    
    Ok(())
}


