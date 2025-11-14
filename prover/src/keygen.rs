//! Proving and Verifying Key Generation
//!
//! Handles generation, caching, and loading of Halo2 proving and verifying keys.

use anyhow::{Context, Result};
use bpf_tracer::ExecutionTrace;
use halo2_base::{
    gates::{
        circuit::{
            builder::BaseCircuitBuilder,
            BaseCircuitParams,
            CircuitBuilderStage,
        },
        flex_gate::GateChip,
    },
    halo2_proofs::{
        plonk::{keygen_pk, keygen_vk, ProvingKey, VerifyingKey},
        poly::kzg::commitment::ParamsKZG,
        poly::commitment::Params,
        SerdeFormat,
    },
    halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine},
};
use rand::rngs::OsRng;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use zk_circuits::CounterCircuit;

/// Configuration for key generation
#[derive(Debug, Clone)]
pub struct KeygenConfig {
    /// Circuit size parameter (circuit has 2^k rows)
    pub k: u32,
    /// Directory to cache keys
    pub cache_dir: PathBuf,
    /// Lookup bits for range checks
    pub lookup_bits: usize,
    /// Maximum instructions per chunk (for recursive proving)
    pub chunk_size: usize,
}

impl KeygenConfig {
    /// Create a new keygen configuration
    pub fn new(k: u32, cache_dir: impl Into<PathBuf>, lookup_bits: usize) -> Self {
        Self {
            k,
            cache_dir: cache_dir.into(),
            lookup_bits,
            chunk_size: 1000, // Default: 1000 instructions per chunk
        }
    }

    /// Create a new keygen configuration with custom chunk size
    pub fn with_chunk_size(mut self, chunk_size: usize) -> Self {
        self.chunk_size = chunk_size;
        self
    }

    /// Get path to cached parameters file
    fn params_path(&self) -> PathBuf {
        self.cache_dir.join(format!("params_k{}.bin", self.k))
    }

    /// Get path to cached verifying key file
    fn vk_path(&self) -> PathBuf {
        self.cache_dir.join(format!("counter_vk_k{}.bin", self.k))
    }

    /// Get path to cached proving key file
    fn pk_path(&self) -> PathBuf {
        self.cache_dir.join(format!("counter_pk_k{}.bin", self.k))
    }

    /// Get path to cached break points file
    fn break_points_path(&self) -> PathBuf {
        self.cache_dir.join(format!("counter_bp_k{}.json", self.k))
    }

    /// Get path to cached circuit params file
    fn circuit_params_path(&self) -> PathBuf {
        self.cache_dir.join(format!("counter_params_k{}.json", self.k))
    }
}

impl Default for KeygenConfig {
    fn default() -> Self {
        Self {
            k: 17, // 2^17 = 131,072 rows
            cache_dir: PathBuf::from(".cache/keys"),
            lookup_bits: 8,
            chunk_size: 1000, // Default: 1000 instructions per chunk
        }
    }
}

/// Key pair for proving and verification
#[derive(Debug)]
pub struct KeyPair {
    /// KZG parameters
    pub params: ParamsKZG<Bn256>,
    /// Proving key
    pub pk: ProvingKey<G1Affine>,
    /// Verifying key (extracted from proving key)
    pub vk: VerifyingKey<G1Affine>,
    /// Break points from keygen (needed for prover circuit)
    pub break_points: Vec<Vec<usize>>,
    /// Circuit params from keygen (needed for loading keys)
    pub circuit_params: BaseCircuitParams,
}

impl KeyPair {
    /// Load or generate keys based on configuration
    ///
    /// If cached keys exist and are valid, loads them from disk.
    /// Otherwise, generates new keys and caches them.
    pub fn load_or_generate(config: &KeygenConfig) -> Result<Self> {
        // Check if cached keys exist
        if Self::cache_exists(config) {
            tracing::info!("Found cached keys, attempting to load...");
            match Self::load_from_cache(config) {
                Ok(keypair) => {
                    tracing::info!("Successfully loaded keys from cache");
                    return Ok(keypair);
                }
                Err(e) => {
                    tracing::warn!("Failed to load cached keys: {}. Regenerating...", e);
                }
            }
        }

        // Generate new keys
        tracing::info!("Generating new keys...");
        let keypair = Self::generate(config)?;

        // Cache the generated keys
        keypair.save_to_cache(config)
            .context("Failed to cache generated keys")?;

        Ok(keypair)
    }

    /// Generate new keys (bypasses cache)
    pub fn generate(config: &KeygenConfig) -> Result<Self> {
        tracing::info!(
            "Generating proving and verifying keys for k={}, lookup_bits={}",
            config.k,
            config.lookup_bits
        );

        // Set up KZG parameters
        tracing::info!("Setting up KZG parameters...");
        let params = ParamsKZG::<Bn256>::setup(config.k, OsRng);

        // Set environment variable for lookup bits
        std::env::set_var("LOOKUP_BITS", config.lookup_bits.to_string());

        // Create a dummy circuit for keygen with fixed chunk size
        // This circuit will be padded to chunk_size, establishing the fixed circuit shape
        tracing::info!(
            "Creating dummy circuit for keygen with chunk_size={}...",
            config.chunk_size
        );
        let dummy_trace = ExecutionTrace::new();
        let circuit_logic = CounterCircuit::from_trace_chunked(dummy_trace, config.chunk_size);

        // Build the circuit using BaseCircuitBuilder
        let mut builder = BaseCircuitBuilder::<Fr>::from_stage(CircuitBuilderStage::Keygen)
            .use_k(config.k as usize)
            .use_lookup_bits(config.lookup_bits);

        // Create a gate chip
        let gate = GateChip::<Fr>::default();

        // Synthesize the circuit
        circuit_logic.synthesize(builder.main(0), &gate)
            .context("Failed to synthesize circuit")?;

        // Configure the builder and get the circuit params
        let circuit_params = builder.calculate_params(Some(9));

        // Generate verifying key
        tracing::info!("Generating verifying key...");
        let vk = keygen_vk(&params, &builder)
            .context("Failed to generate verifying key")?;

        // Generate proving key
        tracing::info!("Generating proving key...");
        let pk = keygen_pk(&params, vk, &builder)
            .context("Failed to generate proving key")?;

        let vk = pk.get_vk().clone();

        // After keygen, extract the break points that were set during synthesis
        // These need to be saved so prover can use them
        let break_points = builder.break_points();
        tracing::debug!("Break points from keygen: {:?}", break_points);

        tracing::info!("Key generation complete");
        Ok(Self { params, pk, vk, break_points, circuit_params })
    }

    /// Load keys from cache
    pub fn load_from_cache(config: &KeygenConfig) -> Result<Self> {
        tracing::info!("Loading keys from cache: {:?}", config.cache_dir);

        let params = load_params(&config.params_path())
            .context("Failed to load KZG parameters")?;

        let circuit_params = load_circuit_params(&config.circuit_params_path())
            .context("Failed to load circuit params")?;

        let vk = load_vk(&params, &config.vk_path(), &circuit_params)
            .context("Failed to load verifying key")?;

        let pk = load_pk(&params, &config.pk_path(), &circuit_params)
            .context("Failed to load proving key")?;

        let break_points = load_break_points(&config.break_points_path())
            .context("Failed to load break points")?;

        tracing::info!("Successfully loaded keys from cache");
        Ok(Self { params, vk, pk, break_points, circuit_params })
    }

    /// Save keys to cache
    pub fn save_to_cache(&self, config: &KeygenConfig) -> Result<()> {
        // Create cache directory if it doesn't exist
        fs::create_dir_all(&config.cache_dir)
            .context("Failed to create cache directory")?;

        tracing::info!("Saving keys to cache: {:?}", config.cache_dir);

        save_params(&self.params, &config.params_path())
            .context("Failed to save KZG parameters")?;

        save_vk(&self.vk, &config.vk_path())
            .context("Failed to save verifying key")?;

        save_pk(&self.pk, &config.pk_path())
            .context("Failed to save proving key")?;

        save_break_points(&self.break_points, &config.break_points_path())
            .context("Failed to save break points")?;

        save_circuit_params(&self.circuit_params, &config.circuit_params_path())
            .context("Failed to save circuit params")?;

        tracing::info!("Successfully saved keys to cache");
        Ok(())
    }

    /// Check if cached keys exist for given configuration
    pub fn cache_exists(config: &KeygenConfig) -> bool {
        config.params_path().exists()
            && config.vk_path().exists()
            && config.pk_path().exists()
            && config.break_points_path().exists()
            && config.circuit_params_path().exists()
    }
}

/// Load KZG parameters from file
fn load_params(path: &Path) -> Result<ParamsKZG<Bn256>> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open params file: {:?}", path))?;
    let mut reader = BufReader::new(file);

    ParamsKZG::<Bn256>::read(&mut reader)
        .with_context(|| format!("Failed to deserialize params from {:?}", path))
}

/// Save KZG parameters to file
fn save_params(params: &ParamsKZG<Bn256>, path: &Path) -> Result<()> {
    let file = File::create(path)
        .with_context(|| format!("Failed to create params file: {:?}", path))?;
    let mut writer = BufWriter::new(file);

    params.write(&mut writer)
        .with_context(|| format!("Failed to serialize params to {:?}", path))?;

    Ok(())
}

/// Load verifying key from file
fn load_vk(
    _params: &ParamsKZG<Bn256>,
    path: &Path,
    circuit_params: &BaseCircuitParams,
) -> Result<VerifyingKey<G1Affine>> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open VK file: {:?}", path))?;
    let mut reader = BufReader::new(file);

    VerifyingKey::<G1Affine>::read::<_, BaseCircuitBuilder<Fr>>(
        &mut reader,
        SerdeFormat::RawBytesUnchecked,
        circuit_params.clone(),
    )
    .with_context(|| format!("Failed to deserialize VK from {:?}", path))
}

/// Save verifying key to file
fn save_vk(vk: &VerifyingKey<G1Affine>, path: &Path) -> Result<()> {
    let file = File::create(path)
        .with_context(|| format!("Failed to create VK file: {:?}", path))?;
    let mut writer = BufWriter::new(file);

    vk.write(&mut writer, SerdeFormat::RawBytesUnchecked)
        .with_context(|| format!("Failed to serialize VK to {:?}", path))?;

    Ok(())
}

/// Load proving key from file
fn load_pk(
    _params: &ParamsKZG<Bn256>,
    path: &Path,
    circuit_params: &BaseCircuitParams,
) -> Result<ProvingKey<G1Affine>> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open PK file: {:?}", path))?;
    let mut reader = BufReader::new(file);

    ProvingKey::<G1Affine>::read::<_, BaseCircuitBuilder<Fr>>(
        &mut reader,
        SerdeFormat::RawBytesUnchecked,
        circuit_params.clone(),
    )
    .with_context(|| format!("Failed to deserialize PK from {:?}", path))
}

/// Save proving key to file
fn save_pk(pk: &ProvingKey<G1Affine>, path: &Path) -> Result<()> {
    let file = File::create(path)
        .with_context(|| format!("Failed to create PK file: {:?}", path))?;
    let mut writer = BufWriter::new(file);

    pk.write(&mut writer, SerdeFormat::RawBytesUnchecked)
        .with_context(|| format!("Failed to serialize PK to {:?}", path))?;

    Ok(())
}

/// Load break points from file
fn load_break_points(path: &Path) -> Result<Vec<Vec<usize>>> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open break points file: {:?}", path))?;
    let reader = BufReader::new(file);

    serde_json::from_reader(reader)
        .with_context(|| format!("Failed to deserialize break points from {:?}", path))
}

/// Save break points to file
fn save_break_points(break_points: &[Vec<usize>], path: &Path) -> Result<()> {
    let file = File::create(path)
        .with_context(|| format!("Failed to create break points file: {:?}", path))?;
    let writer = BufWriter::new(file);

    serde_json::to_writer(writer, break_points)
        .with_context(|| format!("Failed to serialize break points to {:?}", path))?;

    Ok(())
}

/// Load circuit params from file
fn load_circuit_params(path: &Path) -> Result<BaseCircuitParams> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open circuit params file: {:?}", path))?;
    let reader = BufReader::new(file);

    serde_json::from_reader(reader)
        .with_context(|| format!("Failed to deserialize circuit params from {:?}", path))
}

/// Save circuit params to file
fn save_circuit_params(circuit_params: &BaseCircuitParams, path: &Path) -> Result<()> {
    let file = File::create(path)
        .with_context(|| format!("Failed to create circuit params file: {:?}", path))?;
    let writer = BufWriter::new(file);

    serde_json::to_writer_pretty(writer, circuit_params)
        .with_context(|| format!("Failed to serialize circuit params to {:?}", path))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_keygen_config_default() {
        let config = KeygenConfig::default();
        assert_eq!(config.k, 17);
        assert_eq!(config.lookup_bits, 8);
    }

    #[test]
    fn test_keygen_config_paths() {
        let config = KeygenConfig::new(10, "/tmp/test_keys", 8);

        assert_eq!(config.params_path(), PathBuf::from("/tmp/test_keys/params_k10.bin"));
        assert_eq!(config.vk_path(), PathBuf::from("/tmp/test_keys/counter_vk_k10.bin"));
        assert_eq!(config.pk_path(), PathBuf::from("/tmp/test_keys/counter_pk_k10.bin"));
    }

    #[test]
    fn test_cache_exists_returns_false_for_nonexistent() {
        let temp_dir = env::temp_dir().join("nonexistent_keygen_test");
        let config = KeygenConfig::new(10, temp_dir, 8);

        assert!(!KeyPair::cache_exists(&config));
    }

    // Note: test_load_or_generate removed - now tests actual key generation in integration tests
}
