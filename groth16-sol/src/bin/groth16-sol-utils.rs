use std::fmt;
use std::io::BufReader;
use std::str::FromStr;
use std::{fs::File, path::PathBuf, process::ExitCode};

use ark_bn254::Bn254;
use ark_ff::Zero;
use circom_types::groth16::{Proof, PublicInput, VerificationKey};
use clap::{Args, Parser, Subcommand};
use eyre::Context;
use taceo_groth16_sol::askama::Template;
use taceo_groth16_sol::{SolidityVerifierConfig, SolidityVerifierContext};

#[derive(Copy, Clone, Debug, Default)]
enum Format {
    #[default]
    Circom,
    Bellman,
    Gnark,
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Circom => write!(f, "circom"),
            Self::Bellman => write!(f, "bellman"),
            Self::Gnark => write!(f, "gnark"),
        }
    }
}

impl FromStr for Format {
    type Err = eyre::Report;

    fn from_str(s: &str) -> eyre::Result<Self> {
        match s {
            "circom" => Ok(Self::Circom),
            "bellman" => Ok(Self::Bellman),
            "gnark" => Ok(Self::Gnark),
            _ => eyre::bail!("Format must be either circom, bellman or gnark"),
        }
    }
}

/// Utility tools for creating and interacting with Solidity verifier contracts for BN254 Groth16 proofs. This CLI can extract a Solidity verifier from a verification key (based on the Groth16 implementation in gnark) and generate parameters for calling the verifier contract.
#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Config {
    #[clap(subcommand)]
    subcommand: SubCommand,
}

#[derive(Debug, Subcommand)]
enum SubCommand {
    GenerateCall(GenerateCallConfig),
    ExtractVerifier(ExtractVerifierConfig),
}

#[derive(Debug, Default, Args)]
struct GenerateCallConfig {
    /// Path to Circom proof.
    #[clap(long)]
    pub proof: PathBuf,
    /// Path to Circom public inputs.
    #[clap(long)]
    pub public: PathBuf,
    /// Location of the output file. Write to stdout if omitted.
    #[clap(short, long)]
    pub output: Option<PathBuf>,
    /// Proof format.
    #[clap(short, long, default_value_t = Format::Circom)]
    pub format: Format,
}

#[derive(Debug, Default, Args)]
struct ExtractVerifierConfig {
    /// Path to Circom verification key.
    #[clap(short, long)]
    pub vk: PathBuf,
    /// Output of the Solidity file. Write to stdout if omitted.
    #[clap(short, long)]
    pub output: Option<PathBuf>,
    /// The pragma version of the Solidity contract.
    #[clap(long, default_value = "^0.8.0")]
    pub pragma_version: String,
    /// Vk format.
    #[clap(short, long, default_value_t = Format::Circom)]
    pub format: Format,
}

fn generate_call(config: GenerateCallConfig) -> eyre::Result<ExitCode> {
    let GenerateCallConfig {
        proof,
        public,
        output,
        format,
    } = config;

    let proof_file = BufReader::new(File::open(proof).context("while opening input file")?);
    let proof = match format {
        Format::Circom => {
            let proof: Proof<Bn254> = serde_json::from_reader(proof_file)
                .context("while parsing circom groth16 proof")?;
            proof.into()
        }
        Format::Bellman => taceo_groth16_sol::read_bellman_proof(proof_file)
            .context("while parsing bellman groth16 proof")?,
        Format::Gnark => taceo_groth16_sol::read_gnark_proof(proof_file)
            .context("while parsing gnark groth16 proof")?,
    };

    let public_input: PublicInput<ark_bn254::Fr> = serde_json::from_reader(File::open(public)?)?;

    let pub_ins = public_input
        .0
        .into_iter()
        .map(|x| {
            if x.is_zero() {
                "0".to_owned()
            } else {
                x.to_string()
            }
        })
        .collect::<Vec<String>>()
        .join(",");

    let proof = taceo_groth16_sol::prepare_uncompressed_proof(&proof)
        .into_iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>()
        .join(",");
    let result = format!("[{proof}],[{pub_ins}]");
    if let Some(output) = output {
        std::fs::write(output, result)?;
    } else {
        println!("{result}");
    }
    Ok(ExitCode::SUCCESS)
}

fn extract_verifier(config: ExtractVerifierConfig) -> eyre::Result<ExitCode> {
    let ExtractVerifierConfig {
        vk,
        output,
        pragma_version,
        format,
    } = config;

    let vk_file = BufReader::new(File::open(vk).context("while opening input file")?);
    let vk = match format {
        Format::Circom => VerificationKey::<Bn254>::from_reader(vk_file)
            .context("while parsing circom verification-key")?
            .into(),
        Format::Bellman => taceo_groth16_sol::read_bellman_vk(vk_file)
            .context("while parsing bellman verification-key")?,
        Format::Gnark => taceo_groth16_sol::read_gnark_vk(vk_file)
            .context("while parsing gnark verification-key")?,
    };

    let contract = SolidityVerifierContext {
        little_endian: false,
        vk,
        config: SolidityVerifierConfig { pragma_version },
    };
    let rendered = contract.render().unwrap();
    if let Some(output) = output {
        std::fs::write(output, rendered).context("while writing output")?;
    } else {
        println!("{rendered}")
    }
    Ok(ExitCode::SUCCESS)
}

fn main() -> eyre::Result<ExitCode> {
    let config = Config::parse();
    match config.subcommand {
        SubCommand::GenerateCall(config) => generate_call(config),
        SubCommand::ExtractVerifier(config) => extract_verifier(config),
    }
}
