use anyhow::Result;
use attest::core::AttestCore;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "attest")]
#[command(about = "Verifiable CI/CD with cryptographic attestation")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(short, long, global = true, help = "Enable verbose logging")]
    verbose: bool,

    #[arg(short, long, global = true, help = "Suppress all output except errors")]
    quiet: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize ATTEST repository
    Init,

    /// Run pipeline with attestation
    Run {
        #[arg(short, long, value_name = "FILE", help = "Pipeline file path")]
        pipeline: Option<String>,

        #[arg(
            long,
            help = "Run steps under process isolation: resource limits and timeouts are enforced; \
                    network and filesystem access are not. The receipt lists each control and its state"
        )]
        verify: bool,

        #[arg(long, help = "Cryptographically sign results")]
        sign: bool,

        #[arg(
            long,
            value_name = "KEY_ID",
            help = "Signing key id (see 'attest keys list')"
        )]
        key: Option<String>,

        #[arg(
            long,
            help = "Run the pipeline twice in fresh workspaces and compare output hashes"
        )]
        check_reproducibility: bool,

        #[arg(
            long,
            help = "Request an RFC 3161 timestamp over the signature (requires --sign)"
        )]
        timestamp: bool,

        #[arg(
            long,
            value_name = "URL",
            help = "Timestamp authority to use with --timestamp"
        )]
        tsa: Option<String>,

        #[arg(
            long,
            help = "Wrap a single command instead of running a pipeline (no sandbox, no pipeline file)"
        )]
        wrap: bool,

        #[arg(
            long,
            value_name = "STEP_NAME",
            help = "Step name recorded in the receipt (required with --wrap)"
        )]
        name: Option<String>,

        #[arg(
            long = "input",
            value_name = "PATH",
            help = "Declared input path, repeatable (--wrap only)"
        )]
        inputs: Vec<String>,

        #[arg(
            long = "output",
            value_name = "PATH",
            help = "Declared output path, repeatable (--wrap only)"
        )]
        outputs: Vec<String>,

        #[arg(
            long,
            value_name = "DIR",
            help = "Workspace root for --wrap (default: current directory)"
        )]
        workspace: Option<String>,

        #[arg(
            last = true,
            value_name = "COMMAND",
            help = "Command to execute after `--` (--wrap only)"
        )]
        command: Vec<String>,
    },

    /// Sign a receipt produced elsewhere, in a process that ran no project command
    Sign {
        #[arg(value_name = "RECEIPT", help = "Unsigned receipt file")]
        receipt: String,

        #[arg(
            long,
            value_name = "KEY_ID",
            help = "Signing key id (see 'attest keys list'); the only private key if omitted"
        )]
        key: Option<String>,

        #[arg(long, help = "Request an RFC 3161 timestamp over the signature")]
        timestamp: bool,

        #[arg(
            long,
            value_name = "URL",
            help = "Timestamp authority to use with --timestamp"
        )]
        tsa: Option<String>,

        #[arg(
            long,
            value_name = "FILE",
            help = "Write the signed receipt here instead of in place"
        )]
        output: Option<String>,

        #[arg(
            long,
            value_name = "DIR",
            help = "Workspace holding .attest/ (default: current directory)"
        )]
        workspace: Option<String>,
    },

    /// Key management and trust store
    Keys {
        #[command(subcommand)]
        action: KeysCommands,
    },

    /// Trust bundles: hand your trust store to someone else, intact
    Trust {
        #[command(subcommand)]
        action: TrustCommands,
    },

    /// Compute a canonical attest-manifest/v1 hash for declared paths
    Hash {
        #[arg(
            long = "input",
            value_name = "PATH",
            help = "Declared input path, repeatable (requires --run)"
        )]
        inputs: Vec<String>,

        #[arg(
            long = "output",
            value_name = "PATH",
            help = "Declared output path, repeatable"
        )]
        outputs: Vec<String>,

        #[arg(
            long,
            value_name = "CMD",
            help = "Command string bound into the input manifest's run: line"
        )]
        run: Option<String>,

        #[arg(
            long,
            value_name = "STEP",
            default_value = "hash",
            help = "Step name used in error messages"
        )]
        name: String,

        #[arg(
            long,
            value_name = "DIR",
            help = "Workspace root (default: current directory)"
        )]
        workspace: Option<String>,
    },

    /// Manage hermetic execution capsules (attest-capsule/v1)
    Capsule {
        #[command(subcommand)]
        action: CapsuleCommands,
    },

    /// Verify one or more attestation receipts
    Verify {
        #[arg(value_name = "RECEIPT", help = "Receipt file(s) to verify")]
        receipts: Vec<String>,

        #[arg(
            long,
            value_name = "FILE",
            help = "Verify a self-contained archive (.attest.tar.zst) fully offline"
        )]
        archive: Option<String>,

        #[arg(
            long,
            default_value_t = true,
            action = clap::ArgAction::Set,
            help = "Verify Ed25519 signatures (default: true)"
        )]
        check_signatures: bool,

        #[arg(
            long,
            help = "Recompute the pipeline, step input and step output hashes from the workspace"
        )]
        recompute: bool,

        #[arg(
            long,
            help = "Accept a revoked key on the receipt's own timestamp, with no independent proof of when it was signed"
        )]
        trust_receipt_timestamp: bool,

        #[arg(
            long,
            value_name = "DIR",
            help = "Workspace root (default: current directory)"
        )]
        workspace: Option<String>,

        #[arg(long, value_name = "DIR", help = "Directory of trusted public keys")]
        trust_store: Option<String>,

        #[arg(
            long,
            help = "Never perform network access (all checks are local today)"
        )]
        offline: bool,

        #[arg(
            long,
            value_name = "PROPERTY",
            help = "Refuse unless this property is established: signature, timestamp, recompute, linkage, trust, success (comma-separated, repeatable)"
        )]
        require: Vec<String>,

        #[arg(
            long,
            value_name = "BYTES",
            help = "Refuse an archive larger than this on disk (default 64 MiB)"
        )]
        max_archive_bytes: Option<u64>,

        #[arg(
            long,
            value_name = "BYTES",
            help = "Refuse an archive that expands past this (default 512 MiB)"
        )]
        max_unpacked_bytes: Option<u64>,

        #[arg(
            long,
            value_name = "N",
            help = "Refuse an archive with more entries than this (default 10000)"
        )]
        max_entries: Option<usize>,

        #[arg(
            long,
            value_name = "BYTES",
            help = "Refuse an archive entry larger than this (default 64 MiB)"
        )]
        max_entry_bytes: Option<u64>,

        #[arg(
            long,
            default_value = "text",
            help = "Output format: text or json (NDJSON)"
        )]
        format: String,
    },

    /// Export a receipt to a standard attestation format
    Export {
        #[arg(long, value_name = "RECEIPT", help = "Receipt file to export")]
        receipt: String,

        #[arg(long, value_name = "FORMAT", help = "Export format (in-toto)")]
        format: String,

        #[arg(
            long,
            value_name = "FILE",
            default_value = "-",
            help = "Output file, or - for stdout"
        )]
        output: String,

        #[arg(
            long,
            help = "Export an unsigned receipt as a DSSE envelope without signatures"
        )]
        allow_unsigned: bool,

        #[arg(
            long,
            value_name = "KEY_ID",
            help = "Envelope signing key id (see 'attest keys list')"
        )]
        key: Option<String>,

        #[arg(
            long,
            value_name = "DIR",
            help = "Workspace root (default: current directory)"
        )]
        workspace: Option<String>,
    },

    /// Import and verify a standard attestation
    Import {
        #[arg(value_name = "STATEMENT", help = "DSSE envelope JSON file")]
        statement: String,

        #[arg(long, value_name = "FORMAT", help = "Import format (in-toto)")]
        format: String,

        #[arg(
            long,
            value_name = "DIR",
            help = "Workspace root (default: current directory)"
        )]
        workspace: Option<String>,

        #[arg(long, value_name = "DIR", help = "Directory of trusted public keys")]
        trust_store: Option<String>,

        #[arg(
            long,
            help = "Accept a revoked key on the statement's own finishedOn, with no independent proof of when it was signed"
        )]
        trust_statement_time: bool,

        #[arg(
            long,
            value_name = "PROPERTY",
            help = "Refuse unless this property is established: signature (comma-separated, repeatable)"
        )]
        require: Vec<String>,

        #[arg(
            long,
            default_value = "text",
            help = "Report format: text or json (NDJSON)"
        )]
        report: String,
    },

    /// Image signature verification operations
    Image {
        #[command(subcommand)]
        action: ImageCommands,
    },

    /// Causal ledger operations
    Causal {
        #[command(subcommand)]
        action: CausalCommands,
    },
}

#[derive(Subcommand)]
enum CapsuleCommands {
    /// Create a capsule manifest pinned to an image digest
    Init {
        #[arg(
            long,
            value_name = "REF",
            help = "Digest-pinned OCI reference: <repo>@sha256:<64 hex> (tags rejected)"
        )]
        image: String,

        #[arg(long, value_name = "NAME", help = "Capsule name")]
        name: String,

        #[arg(
            long,
            value_name = "DIR",
            help = "Workspace root (default: current directory)"
        )]
        workspace: Option<String>,
    },

    /// Execute a command inside a capsule
    Run {
        #[arg(value_name = "NAME", help = "Capsule name")]
        name: String,

        #[arg(
            long,
            value_name = "DIR",
            help = "Workspace root (default: current directory)"
        )]
        workspace: Option<String>,

        #[arg(
            last = true,
            value_name = "COMMAND",
            help = "Command to execute inside the capsule"
        )]
        command: Vec<String>,
    },

    /// Print a capsule's hash; fails if the stored hash mismatches
    Hash {
        #[arg(value_name = "NAME", help = "Capsule name")]
        name: String,

        #[arg(
            long,
            value_name = "DIR",
            help = "Workspace root (default: current directory)"
        )]
        workspace: Option<String>,
    },
}

#[derive(Subcommand)]
enum KeysCommands {
    /// Generate a new Ed25519 keypair and trust it
    Generate {
        #[arg(long, value_name = "NAME", help = "Display name for the key")]
        name: String,
    },

    /// List trust store entries
    List {
        #[arg(
            long,
            default_value = "text",
            help = "Output format: text or json (NDJSON)"
        )]
        format: String,
    },

    /// Export a PUBLIC key PEM (never private material)
    Export {
        #[arg(value_name = "KEY_ID", help = "Key id to export")]
        key_id: String,

        #[arg(
            short,
            long,
            value_name = "FILE",
            help = "Write PEM to file instead of stdout"
        )]
        output: Option<String>,
    },

    /// Import a public key PEM into the trust store as trusted
    Import {
        #[arg(value_name = "PUBKEY.pem", help = "Public key PEM file")]
        pubkey: String,

        #[arg(long, value_name = "NAME", help = "Display name for the key")]
        name: String,
    },

    /// Pin a timestamp authority's issuing certificate
    TrustTsa {
        #[arg(value_name = "CERTIFICATE", help = "PEM or DER certificate file")]
        certificate: std::path::PathBuf,

        #[arg(
            long,
            value_name = "NAME",
            help = "Name for the pinned authority (becomes <name>.crt)"
        )]
        name: String,
    },

    /// Revoke a key (sets status=revoked, never deletes files)
    Revoke {
        #[arg(value_name = "KEY_ID", help = "Key id to revoke")]
        key_id: String,
    },
}

#[derive(Subcommand)]
enum TrustCommands {
    /// Assemble and sign a bundle of the keys this store trusts and has revoked
    Bundle {
        #[arg(short, long, value_name = "FILE", help = "Where to write the bundle")]
        output: String,

        #[arg(
            long,
            value_name = "KEY_ID",
            help = "Issuer key (see 'attest keys list'); the only private key if omitted"
        )]
        key: Option<String>,

        #[arg(
            long,
            value_name = "DAYS",
            default_value = "90",
            help = "How long the bundle stays valid"
        )]
        valid_for: u32,

        #[arg(
            long,
            value_name = "KEY_ID",
            help = "Hand over to this trusted key: recipients accept its first bundle on the strength of this one"
        )]
        successor: Option<String>,

        #[arg(
            long,
            value_name = "DIR",
            help = "Workspace holding .attest/ (default: current directory)"
        )]
        workspace: Option<String>,
    },

    /// Import a bundle into the trust store, or refresh from a newer one; never online
    #[command(visible_alias = "refresh")]
    Import {
        #[arg(value_name = "BUNDLE", help = "Bundle file")]
        bundle: String,

        #[arg(
            long,
            value_name = "KEY_ID",
            help = "Issuer key id you expect, obtained through another channel; required the first time"
        )]
        issuer: Option<String>,

        #[arg(
            long,
            value_name = "DIR",
            help = "Workspace holding .attest/ (default: current directory)"
        )]
        workspace: Option<String>,
    },

    /// Read a bundle and say who issued it, until when, and whether it is intact
    Show {
        #[arg(value_name = "BUNDLE", help = "Bundle file")]
        bundle: String,

        #[arg(long, default_value = "text", help = "Output format: text or json")]
        format: String,
    },
}

#[derive(Subcommand)]
enum ImageCommands {
    /// Sign a container image with cosign (digest references only)
    Sign {
        #[arg(
            value_name = "IMAGE_REF",
            help = "Digest reference: registry/repo@sha256:<digest>"
        )]
        image_ref: String,

        #[arg(
            long,
            value_name = "KEY_URI",
            help = "Signing key URI (azurekms://...); file paths need --allow-file-key"
        )]
        key: String,

        #[arg(
            long = "annotation",
            value_name = "K=V",
            help = "Signature annotation (repeatable); continuum.git.revision defaults to HEAD"
        )]
        annotations: Vec<String>,

        #[arg(long, help = "Permit a file-based private key (development only)")]
        allow_file_key: bool,

        #[arg(
            long,
            help = "Disable the clean-tree precondition (enabled by default)"
        )]
        no_require_clean_tree: bool,

        #[arg(
            long = "clean-paths",
            value_name = "PATH",
            num_args = 1..,
            help = "Paths for the clean-tree check (default: whole repository)"
        )]
        clean_paths: Vec<String>,

        #[arg(
            long,
            value_name = "DIR",
            help = "Where the signing receipt is written (default: .attest/receipts/)"
        )]
        receipt_dir: Option<String>,

        #[arg(long, help = "Sign the receipt with the local ATTEST key")]
        sign: bool,

        #[arg(
            long,
            value_name = "KEY_ID",
            help = "ATTEST receipt signing key id (see 'attest keys list')"
        )]
        receipt_key: Option<String>,
    },

    /// Verify container image signature and supply-chain content
    Verify {
        #[arg(
            value_name = "IMAGE",
            help = "Container image to verify; digest form repo@sha256:<digest> \
                    is mandatory with the supply-chain options"
        )]
        image: String,

        #[arg(long, help = "Enforce a structurally valid SPDX SBOM attestation")]
        require_sbom: bool,

        #[arg(long, help = "Enforce a complete SLSA provenance attestation")]
        require_provenance: bool,

        #[arg(
            long,
            value_name = "HEXSHA",
            help = "Expected git revision (full object id) bound in provenance \
                    and signature annotations"
        )]
        expected_revision: Option<String>,

        #[arg(
            long,
            value_name = "KEY_URI",
            help = "Verification key: azurekms://... (public key exported first) \
                    or a public-key file; enables the signature check"
        )]
        key: Option<String>,

        #[arg(
            long,
            value_name = "IDENTITY",
            help = "Keyless: the certificate identity the signature must carry (with --certificate-oidc-issuer)"
        )]
        certificate_identity: Option<String>,

        #[arg(
            long,
            value_name = "ISSUER",
            help = "Keyless: the OIDC issuer the identity must come from (with --certificate-identity)"
        )]
        certificate_oidc_issuer: Option<String>,

        #[arg(
            long,
            value_name = "FORMAT",
            default_value = "text",
            help = "Report format: text or json"
        )]
        format: String,

        #[arg(
            long,
            help = "Write a verification receipt (path printed as the last stdout line)"
        )]
        receipt: bool,

        #[arg(
            long,
            value_name = "DIR",
            help = "Where the verification receipt is written (default: .attest/receipts/); \
                    implies --receipt"
        )]
        receipt_dir: Option<String>,

        #[arg(
            long,
            help = "Sign the receipt with the local ATTEST key; implies --receipt"
        )]
        sign_receipt: bool,

        #[arg(
            long,
            value_name = "KEY_ID",
            help = "ATTEST receipt signing key id (see 'attest keys list')"
        )]
        receipt_key: Option<String>,
    },

    /// Check image verification configuration
    Config {
        #[arg(long, help = "Show current verification configuration")]
        show: bool,

        #[arg(long, help = "Test cosign availability")]
        test_cosign: bool,
    },
}

#[derive(Subcommand)]
enum CausalCommands {
    /// Query causal path between two events
    Path {
        #[arg(value_name = "FROM_EVENT", help = "Source event ID")]
        from_event: String,

        #[arg(value_name = "TO_EVENT", help = "Target event ID")]
        to_event: String,

        #[arg(long, help = "Show detailed path information")]
        detailed: bool,
    },

    /// Show causal ledger statistics
    Stats {
        #[arg(long, help = "Show detailed statistics")]
        detailed: bool,
    },

    /// List recent causal events
    Events {
        #[arg(short, long, default_value = "10", help = "Number of events to show")]
        limit: usize,

        #[arg(long, help = "Filter by step name")]
        step: Option<String>,
    },

    /// Build and display causal chain
    Chain {
        #[arg(value_name = "EVENT_IDS", help = "Event IDs to include in chain")]
        event_ids: Vec<String>,

        #[arg(long, help = "Save chain to file")]
        save: bool,
    },

    /// Export a receipt and its causal chain as a self-contained archive
    Export {
        #[arg(long, value_name = "PATH", help = "Receipt file to export")]
        receipt: String,

        #[arg(
            short,
            long,
            value_name = "FILE",
            help = "Output archive path (.attest.tar.zst)"
        )]
        output: String,

        #[arg(
            long,
            help = "Export even if causal references cannot be resolved locally"
        )]
        allow_partial: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging based on verbosity flags
    let level = if cli.quiet {
        "error"
    } else if cli.verbose {
        "debug"
    } else {
        "info"
    };

    tracing_subscriber::fmt()
        .with_env_filter(format!("attest={}", level))
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .init();

    let attest = AttestCore::new().await?;

    match cli.command {
        Commands::Init => match attest.init().await {
            Ok(()) => Ok(()),
            Err(err) => {
                eprintln!("error: {:#}", err);
                std::process::exit(2);
            }
        },

        Commands::Run {
            pipeline,
            verify,
            sign,
            key,
            check_reproducibility,
            timestamp,
            tsa,
            wrap,
            name,
            inputs,
            outputs,
            workspace,
            command,
        } => {
            // Before anything runs, once, for every way a run can happen:
            // a wrapped command, a pipeline, or a pipeline replayed for
            // reproducibility all pass through here.
            refuse_unmet(&[
                Prerequisite {
                    option: "--timestamp",
                    given: timestamp,
                    requires: "--sign",
                    met: sign,
                    why: "there is no signature to timestamp",
                },
                Prerequisite {
                    option: "--key",
                    given: key.is_some(),
                    requires: "--sign",
                    met: sign,
                    why: "a key was named but nothing would be signed",
                },
                Prerequisite {
                    option: "--tsa",
                    given: tsa.is_some(),
                    requires: "--timestamp",
                    met: timestamp,
                    why: "an authority was named but no timestamp was requested",
                },
                Prerequisite {
                    option: "--wrap",
                    given: wrap,
                    requires: "--name <STEP_NAME>",
                    met: name.is_some(),
                    why: "the receipt records the wrapped command under a step name",
                },
                Prerequisite {
                    option: "--wrap",
                    given: wrap,
                    requires: "a command after `--`",
                    met: !command.is_empty(),
                    why: "there is nothing to wrap otherwise",
                },
                Prerequisite {
                    option: "--name",
                    given: name.is_some(),
                    requires: "--wrap",
                    met: wrap,
                    why: "a pipeline run takes step names from the pipeline file",
                },
                Prerequisite {
                    option: "--input",
                    given: !inputs.is_empty(),
                    requires: "--wrap",
                    met: wrap,
                    why: "a pipeline run declares inputs in the pipeline file",
                },
                Prerequisite {
                    option: "--output",
                    given: !outputs.is_empty(),
                    requires: "--wrap",
                    met: wrap,
                    why: "a pipeline run declares outputs in the pipeline file",
                },
                Prerequisite {
                    option: "--workspace",
                    given: workspace.is_some(),
                    requires: "--wrap",
                    met: wrap,
                    why: "a pipeline run uses the current directory",
                },
                Prerequisite {
                    option: "a command after `--`",
                    given: !command.is_empty(),
                    requires: "--wrap",
                    met: wrap,
                    why: "a pipeline run takes its commands from the pipeline file",
                },
                Prerequisite {
                    option: "--check-reproducibility",
                    given: check_reproducibility,
                    requires: "a pipeline run, not --wrap",
                    met: !wrap,
                    why: "a wrapped command runs once; there is nothing to replay",
                },
                Prerequisite {
                    option: "--pipeline",
                    given: pipeline.is_some(),
                    requires: "a pipeline run, not --wrap",
                    met: !wrap,
                    why: "--wrap takes a command, not a pipeline file",
                },
                Prerequisite {
                    option: "--verify",
                    given: verify,
                    requires: "a pipeline run, not --wrap",
                    met: !wrap,
                    why: "--wrap runs without a sandbox",
                },
            ]);
            if wrap {
                // Both guaranteed by the rules above.
                let name = name.unwrap_or_default();
                let workspace = workspace
                    .map(std::path::PathBuf::from)
                    .map_or_else(std::env::current_dir, Ok)
                    .unwrap_or_else(|e| {
                        eprintln!("error: cannot determine working directory: {e}");
                        std::process::exit(2);
                    });
                let options = attest::wrap::WrapOptions {
                    name,
                    inputs: inputs.iter().map(std::path::PathBuf::from).collect(),
                    outputs: outputs.iter().map(std::path::PathBuf::from).collect(),
                    sign,
                    key,
                    tsa: timestamp.then(|| {
                        tsa.clone().unwrap_or_else(|| {
                            attest::crypto::timestamp::DEFAULT_TSA_URL.to_string()
                        })
                    }),
                    workspace,
                };
                match attest::wrap::run_wrap(&command, &options) {
                    Ok(code) => std::process::exit(code),
                    Err(e) => {
                        eprintln!("error: {e:#}");
                        std::process::exit(2);
                    }
                }
            }
            let config = attest::executor::ExecutorConfig {
                isolated: verify,
                sign_results: sign,
                max_parallel: num_cpus::get(),
                deterministic: true,
                container_image: None,
                container_runtime: None,
                sandbox_config: None,
                hermetic_env: false,
            };
            let tsa_url = timestamp.then(|| {
                tsa.clone()
                    .unwrap_or_else(|| attest::crypto::timestamp::DEFAULT_TSA_URL.to_string())
            });

            let outcome = if check_reproducibility {
                attest
                    .run_pipeline_check_reproducibility(
                        pipeline.as_deref(),
                        config,
                        key.as_deref(),
                        tsa_url.as_deref(),
                    )
                    .await
            } else {
                attest
                    .run_pipeline(
                        pipeline.as_deref(),
                        config,
                        key.as_deref(),
                        tsa_url.as_deref(),
                    )
                    .await
            };
            match outcome {
                Ok(code) => std::process::exit(code),
                Err(err) => {
                    eprintln!("error: {:#}", err);
                    std::process::exit(2);
                }
            }
        }

        Commands::Verify {
            receipts,
            archive,
            check_signatures,
            recompute,
            trust_receipt_timestamp,
            workspace,
            trust_store,
            offline,
            require,
            max_archive_bytes,
            max_unpacked_bytes,
            max_entries,
            max_entry_bytes,
            format,
        } => {
            let mut limits = attest::archive::ArchiveLimits::default();
            if let Some(v) = max_archive_bytes {
                limits.compressed = v;
            }
            if let Some(v) = max_unpacked_bytes {
                limits.decompressed = v;
            }
            if let Some(v) = max_entries {
                limits.entries = v;
            }
            if let Some(v) = max_entry_bytes {
                limits.entry = v;
            }
            let code = handle_verify(
                receipts,
                archive,
                check_signatures,
                recompute,
                trust_receipt_timestamp,
                workspace,
                trust_store,
                offline,
                require,
                limits,
                format,
            );
            std::process::exit(code);
        }

        Commands::Sign {
            receipt,
            key,
            timestamp,
            tsa,
            output,
            workspace,
        } => {
            refuse_unmet(&[Prerequisite {
                option: "--tsa",
                given: tsa.is_some(),
                requires: "--timestamp",
                met: timestamp,
                why: "an authority was named but no timestamp was requested",
            }]);
            let workspace = workspace
                .map(std::path::PathBuf::from)
                .map_or_else(std::env::current_dir, Ok)
                .unwrap_or_else(|e| {
                    eprintln!("error: cannot determine working directory: {e}");
                    std::process::exit(2);
                });
            let tsa_url = timestamp.then(|| {
                tsa.clone()
                    .unwrap_or_else(|| attest::crypto::timestamp::DEFAULT_TSA_URL.to_string())
            });
            match attest::core::sign_receipt_file(
                &workspace,
                std::path::Path::new(&receipt),
                key.as_deref(),
                tsa_url.as_deref(),
                output.as_deref().map(std::path::Path::new),
            ) {
                Ok(code) => std::process::exit(code),
                Err(err) => {
                    eprintln!("error: {err:#}");
                    std::process::exit(2);
                }
            }
        }

        Commands::Trust { action } => std::process::exit(handle_trust(action)),

        Commands::Keys { action } => {
            let code = handle_keys(action);
            std::process::exit(code);
        }

        Commands::Export {
            receipt,
            format,
            output,
            allow_unsigned,
            key,
            workspace,
        } => {
            let code = handle_export(receipt, format, output, allow_unsigned, key, workspace);
            std::process::exit(code);
        }

        Commands::Hash {
            inputs,
            outputs,
            run,
            name,
            workspace,
        } => {
            let workspace = match workspace.map(std::path::PathBuf::from) {
                Some(dir) => dir,
                None => std::env::current_dir().unwrap_or_else(|e| {
                    eprintln!("error: cannot determine working directory: {e}");
                    std::process::exit(2);
                }),
            };
            let input_paths: Vec<std::path::PathBuf> =
                inputs.iter().map(std::path::PathBuf::from).collect();
            let output_paths: Vec<std::path::PathBuf> =
                outputs.iter().map(std::path::PathBuf::from).collect();
            let result = if !output_paths.is_empty() && input_paths.is_empty() && run.is_none() {
                attest::hashing::hash_outputs(&workspace, &name, &output_paths)
            } else if run.is_some() && output_paths.is_empty() {
                let run = run.unwrap_or_default();
                attest::hashing::hash_inputs(&workspace, &name, &run, &input_paths)
            } else {
                eprintln!(
                    "error: use either --output <PATH>... (output manifest) or --run <CMD> [--input <PATH>]... (input manifest)"
                );
                std::process::exit(2);
            };
            match result {
                Ok(hash) => {
                    println!("{hash}");
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
        }

        Commands::Capsule { action } => {
            let resolve_workspace = |workspace: Option<String>| -> std::path::PathBuf {
                match workspace.map(std::path::PathBuf::from) {
                    Some(dir) => dir,
                    None => std::env::current_dir().unwrap_or_else(|e| {
                        eprintln!("error: cannot determine working directory: {e}");
                        std::process::exit(2);
                    }),
                }
            };
            match action {
                CapsuleCommands::Init {
                    image,
                    name,
                    workspace,
                } => {
                    let workspace = resolve_workspace(workspace);
                    match attest::capsule::init(&workspace, &name, &image) {
                        Ok(path) => {
                            println!("capsule '{name}' written to {}", path.display());
                            std::process::exit(0);
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            // Tag references are a usage error (exit 2).
                            let code = if e
                                .downcast_ref::<attest::capsule::CapsuleError>()
                                .is_some_and(|err| {
                                    matches!(err, attest::capsule::CapsuleError::TagReference(_))
                                }) {
                                2
                            } else {
                                1
                            };
                            std::process::exit(code);
                        }
                    }
                }
                CapsuleCommands::Run {
                    name,
                    workspace,
                    command,
                } => {
                    if command.is_empty() {
                        eprintln!("error: capsule run requires a command after `--`");
                        std::process::exit(2);
                    }
                    let workspace = resolve_workspace(workspace);
                    match attest::capsule::run(&workspace, &name, &command) {
                        Ok(code) => std::process::exit(code),
                        Err(e) => {
                            eprintln!("error: {e}");
                            std::process::exit(2);
                        }
                    }
                }
                CapsuleCommands::Hash { name, workspace } => {
                    let workspace = resolve_workspace(workspace);
                    match attest::capsule::load(&workspace, &name) {
                        Ok(manifest) => {
                            println!("{}", manifest.capsule_hash.unwrap_or_default());
                            std::process::exit(0);
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            std::process::exit(1);
                        }
                    }
                }
            }
        }

        Commands::Import {
            statement,
            format,
            workspace,
            trust_store,
            trust_statement_time,
            require,
            report,
        } => {
            let code = handle_import(
                statement,
                format,
                workspace,
                trust_store,
                trust_statement_time,
                require,
                report,
            );
            std::process::exit(code);
        }

        Commands::Image { action } => {
            match action {
                ImageCommands::Sign {
                    image_ref,
                    key,
                    annotations,
                    allow_file_key,
                    no_require_clean_tree,
                    clean_paths,
                    receipt_dir,
                    sign,
                    receipt_key,
                } => {
                    refuse_unmet(&[Prerequisite {
                        option: "--receipt-key",
                        given: receipt_key.is_some(),
                        requires: "--sign",
                        met: sign,
                        why: "a key was named but the signing receipt would not be signed",
                    }]);
                    let code = handle_image_sign(
                        image_ref,
                        key,
                        annotations,
                        allow_file_key,
                        no_require_clean_tree,
                        clean_paths,
                        receipt_dir,
                        sign,
                        receipt_key,
                    );
                    std::process::exit(code);
                }
                ImageCommands::Verify {
                    image,
                    require_sbom,
                    require_provenance,
                    expected_revision,
                    key,
                    certificate_identity,
                    certificate_oidc_issuer,
                    format,
                    receipt,
                    receipt_dir,
                    sign_receipt,
                    receipt_key,
                } => {
                    let signature_requested = key.is_some()
                        || (certificate_identity.is_some() && certificate_oidc_issuer.is_some());
                    let anything_requested = require_sbom
                        || require_provenance
                        || expected_revision.is_some()
                        || signature_requested;
                    refuse_unmet(&[
                    Prerequisite {
                        option: "--receipt-key",
                        given: receipt_key.is_some(),
                        requires: "--sign-receipt",
                        met: sign_receipt,
                        why: "a key was named but the verification receipt would not be signed",
                    },
                    Prerequisite {
                        option: "--certificate-identity",
                        given: certificate_identity.is_some(),
                        requires: "--certificate-oidc-issuer",
                        met: certificate_oidc_issuer.is_some(),
                        why: "an identity is only meaningful from a named issuer",
                    },
                    Prerequisite {
                        option: "--certificate-oidc-issuer",
                        given: certificate_oidc_issuer.is_some(),
                        requires: "--certificate-identity",
                        met: certificate_identity.is_some(),
                        why: "an issuer alone would accept any identity it issued",
                    },
                    Prerequisite {
                        option: "--key",
                        given: key.is_some(),
                        requires: "no --certificate-identity",
                        met: certificate_identity.is_none(),
                        why: "a signature is verified against a key or against an identity, not both",
                    },
                    Prerequisite {
                        option: "image verify",
                        given: true,
                        requires: "at least one property to establish",
                        met: anything_requested,
                        why: "pass --key or --certificate-identity with --certificate-oidc-issuer, \
                              --require-sbom, --require-provenance or --expected-revision; a \
                              verification that checks nothing does not pass, it does not run",
                    },
                ]);
                    let receipt_requested = receipt || receipt_dir.is_some() || sign_receipt;
                    let receipt_options = if receipt_requested {
                        Some(attest::crypto::supply_chain::VerifyReceiptOptions {
                            receipt_dir: receipt_dir.map(std::path::PathBuf::from),
                            sign_receipt,
                            receipt_key,
                        })
                    } else {
                        None
                    };
                    let request = attest::crypto::supply_chain::SupplyChainRequest {
                        image_ref: image,
                        require_sbom,
                        require_provenance,
                        expected_revision,
                        key_uri: key,
                        certificate_identity,
                        certificate_oidc_issuer,
                    };
                    let code = handle_image_supply_chain(request, format, receipt_options);
                    std::process::exit(code);
                }
                ImageCommands::Config { show, test_cosign } => {
                    handle_image_config(show, test_cosign).await
                }
            }
        }

        Commands::Causal { action } => match action {
            CausalCommands::Path {
                from_event,
                to_event,
                detailed,
            } => handle_causal_path(from_event, to_event, detailed).await,
            CausalCommands::Stats { detailed } => handle_causal_stats(detailed).await,
            CausalCommands::Events { limit, step } => handle_causal_events(limit, step).await,
            CausalCommands::Chain { event_ids, save } => handle_causal_chain(event_ids, save).await,
            CausalCommands::Export {
                receipt,
                output,
                allow_partial,
            } => {
                let code = handle_causal_export(receipt, output, allow_partial);
                std::process::exit(code);
            }
        },
    }
}

/// Handle key management commands.
///
/// Exit codes: 0 success, 1 verification-meaningful failure (e.g. revoking
/// an unknown id), 2 operational error — same convention as verify.
fn handle_keys(action: KeysCommands) -> i32 {
    use attest::keys::KeyStore;

    let workspace = match std::env::current_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("error: cannot determine current directory: {}", err);
            return 2;
        }
    };
    let store = KeyStore::new(&workspace);

    match action {
        KeysCommands::Generate { name } => match store.generate(&name) {
            Ok(id) => {
                println!("{}", id);
                0
            }
            Err(err) => {
                eprintln!("error: {:#}", err);
                2
            }
        },

        KeysCommands::TrustTsa { certificate, name } => {
            match store.trust_tsa(&certificate, &name) {
                Ok(subject) => {
                    println!("pinned timestamp authority '{name}': {subject}");
                    0
                }
                Err(err) => {
                    eprintln!("error: {err:#}");
                    2
                }
            }
        }

        KeysCommands::List { format } => {
            if format != "text" && format != "json" {
                eprintln!(
                    "error: unsupported --format '{}' (expected text or json)",
                    format
                );
                return 2;
            }
            match store.list() {
                Ok(entries) => {
                    for entry in &entries {
                        if format == "json" {
                            println!(
                                "{}",
                                serde_json::to_string(entry).expect("listing serializes")
                            );
                        } else {
                            let private = if entry.private_key_present {
                                "private+public"
                            } else {
                                "public only"
                            };
                            let revoked = entry
                                .revoked_at
                                .map(|at| format!(" (revoked at {})", at))
                                .unwrap_or_default();
                            println!(
                                "{}  {:<20} {:<8} {}{}",
                                entry.id, entry.name, entry.status, private, revoked
                            );
                        }
                    }
                    0
                }
                Err(err) => {
                    eprintln!("error: {:#}", err);
                    2
                }
            }
        }

        KeysCommands::Export { key_id, output } => match store.export(&key_id) {
            Ok(pem) => match output {
                Some(path) => {
                    if let Err(err) = std::fs::write(&path, &pem) {
                        eprintln!("error: cannot write {}: {}", path, err);
                        return 2;
                    }
                    0
                }
                None => {
                    print!("{}", pem);
                    0
                }
            },
            Err(err) => {
                eprintln!("error: {:#}", err);
                2
            }
        },

        KeysCommands::Import { pubkey, name } => {
            match store.import(std::path::Path::new(&pubkey), &name) {
                Ok(id) => {
                    println!("{}", id);
                    0
                }
                Err(err) => {
                    eprintln!("error: {:#}", err);
                    2
                }
            }
        }

        KeysCommands::Revoke { key_id } => match store.revoke(&key_id) {
            Ok(true) => 0,
            Ok(false) => {
                eprintln!("error: unknown key id: {}", key_id);
                1
            }
            Err(err) => {
                eprintln!("error: {:#}", err);
                2
            }
        },
    }
}

fn handle_trust(action: TrustCommands) -> i32 {
    match action {
        TrustCommands::Bundle {
            output,
            key,
            valid_for,
            successor,
            workspace,
        } => {
            let workspace = workspace
                .map(std::path::PathBuf::from)
                .map_or_else(std::env::current_dir, Ok)
                .unwrap_or_else(|e| {
                    eprintln!("error: cannot determine working directory: {e}");
                    std::process::exit(2);
                });
            let validity = chrono::Duration::days(i64::from(valid_for));
            match attest::trust::produce(&workspace, key.as_deref(), validity, successor.as_deref())
                .and_then(|bundle| {
                    attest::trust::write(&bundle, std::path::Path::new(&output))?;
                    Ok(bundle)
                }) {
                Ok(bundle) => {
                    eprintln!(
                        "bundle issued by {} with {} keys, valid until {}",
                        bundle.issuer.key_id,
                        bundle.keys.len(),
                        bundle.valid_until
                    );
                    println!("{output}");
                    0
                }
                Err(err) => {
                    eprintln!("error: {err:#}");
                    2
                }
            }
        }

        TrustCommands::Import {
            bundle,
            issuer,
            workspace,
        } => {
            let workspace = workspace
                .map(std::path::PathBuf::from)
                .map_or_else(std::env::current_dir, Ok)
                .unwrap_or_else(|e| {
                    eprintln!("error: cannot determine working directory: {e}");
                    std::process::exit(2);
                });
            match attest::trust::import(
                &workspace,
                std::path::Path::new(&bundle),
                issuer.as_deref(),
                chrono::Utc::now(),
            ) {
                Ok(report) => {
                    if report.already_current {
                        println!(
                            "already current: bundle {} from {} was accepted before",
                            report.sequence, report.issuer
                        );
                        return 0;
                    }
                    if let Some((predecessor, sequence)) = &report.handover_from {
                        println!(
                            "handover: {predecessor} named {} as its successor in bundle {sequence}; \
                             accepting this first bundle from {} on that basis",
                            report.issuer, report.issuer
                        );
                    }
                    for (id, name, status) in &report.added {
                        println!("added    {id}  {name:<20} {status}");
                    }
                    for (id, name, at) in &report.revoked {
                        println!("revoked  {id}  {name:<20} at {at}");
                    }
                    for (id, name, at) in &report.revocation_moved_earlier {
                        println!("revoked  {id}  {name:<20} earlier, at {at}");
                    }
                    for (id, name) in &report.kept_revoked {
                        println!(
                            "kept     {id}  {name:<20} revoked here; the bundle lists it as trusted, \
                             a bundle does not un-revoke"
                        );
                    }
                    println!(
                        "accepted bundle {} from {}: {} added, {} revoked, {} unchanged; valid until {}",
                        report.sequence,
                        report.issuer,
                        report.added.len(),
                        report.revoked.len(),
                        report.unchanged,
                        report
                            .valid_until
                            .map(|t| t.to_string())
                            .unwrap_or_default()
                    );
                    0
                }
                Err(err) => {
                    eprintln!("error: {err:#}");
                    1
                }
            }
        }

        TrustCommands::Show { bundle, format } => {
            if format != "text" && format != "json" {
                eprintln!("error: --format must be text or json");
                return 2;
            }
            let path = std::path::Path::new(&bundle);
            let parsed = match attest::trust::read(path) {
                Ok(parsed) => parsed,
                Err(err) => {
                    eprintln!("error: {err:#}");
                    return 2;
                }
            };
            let report = attest::trust::report(path, &parsed, chrono::Utc::now());
            if format == "json" {
                println!(
                    "{}",
                    serde_json::to_string(&report).expect("report serializes")
                );
            } else {
                println!("{}: {}", report.bundle, report.verdict);
                println!("  issuer       {}", report.issuer.key_id);
                println!("  issued       {}", report.issued_at);
                println!("  valid until  {}", report.valid_until);
                println!("  sequence     {}", report.sequence);
                if let Some(successor) = &report.successor {
                    println!("  successor    {}", successor.key_id);
                }
                println!("  keys");
                for key in &report.keys {
                    let revoked = key
                        .revoked_at
                        .map(|at| format!(" at {at}"))
                        .unwrap_or_default();
                    println!("    {}  {:<20} {}{}", key.id, key.name, key.status, revoked);
                }
                println!("  checks");
                for check in &report.checks {
                    let status = if check.passed { "pass" } else { "fail" };
                    println!("    {:<10} {:<5} {}", check.name, status, check.detail);
                }
            }
            if report.verdict == "pass" {
                0
            } else {
                1
            }
        }
    }
}

/// An option whose effect depends on another option. Every such pairing is
/// declared here and checked before a single project command runs: an
/// option that could not take effect is a usage error at the prompt, not
/// something discovered after the build has had its side effects, and never
/// something silently dropped. A new security-sensitive option states its
/// prerequisite in one of these tables rather than in the code that would
/// eventually fail to honour it.
struct Prerequisite {
    option: &'static str,
    given: bool,
    requires: &'static str,
    met: bool,
    why: &'static str,
}

/// Exit 2 on the first unmet prerequisite: an operational error, not a
/// verification result, because nothing has run yet.
fn refuse_unmet(rules: &[Prerequisite]) {
    for rule in rules {
        if rule.given && !rule.met {
            eprintln!(
                "error: {} requires {}; {}",
                rule.option, rule.requires, rule.why
            );
            std::process::exit(2);
        }
    }
}

/// Handle receipt verification.
///
/// Exit codes: 0 = every receipt passes, 1 = at least one verification
/// failure, 2 = operational error (unreadable file, invalid flags).
#[allow(clippy::too_many_arguments)]
fn handle_verify(
    receipts: Vec<String>,
    archive: Option<String>,
    check_signatures: bool,
    recompute: bool,
    trust_receipt_timestamp: bool,
    workspace: Option<String>,
    trust_store: Option<String>,
    _offline: bool, // all checks are local today; reserved for future remote lookups
    require: Vec<String>,
    limits: attest::archive::ArchiveLimits,
    format: String,
) -> i32 {
    use attest::verify::{verify_receipt_file, Policy, VerifyOptions};

    let policy = match Policy::parse(&require) {
        Ok(policy) => policy,
        Err(err) => {
            eprintln!("error: --require: {err}");
            return 2;
        }
    };
    if format != "text" && format != "json" {
        eprintln!(
            "error: unsupported --format '{}' (expected text or json)",
            format
        );
        return 2;
    }
    match (&archive, receipts.is_empty()) {
        (None, true) => {
            eprintln!("error: provide receipt file(s) or --archive FILE");
            return 2;
        }
        (Some(_), false) => {
            eprintln!("error: --archive cannot be combined with receipt arguments");
            return 2;
        }
        _ => {}
    }
    if archive.is_some() && recompute {
        // An archive is verified offline, detached from any workspace: there
        // is nothing to recompute against.
        eprintln!("error: --recompute is invalid with --archive");
        return 2;
    }

    let workspace = workspace
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().expect("cannot determine current directory"));

    let opts = VerifyOptions {
        check_signatures,
        recompute,
        workspace,
        trust_store: trust_store.map(std::path::PathBuf::from),
        trust_receipt_timestamp,
        policy,
    };

    if let Some(archive_path) = archive {
        let path = std::path::Path::new(&archive_path);
        let verdict = match attest::archive::verify_archive_bounded(path, &opts, &limits) {
            Ok(verdict) => verdict,
            Err(err) => return report_operational_error(&archive_path, &err, &format),
        };

        for receipt_verdict in &verdict.receipts {
            print_verdict(receipt_verdict, &format);
        }
        let overall = if verdict.passed() { "pass" } else { "fail" };
        if format == "json" {
            println!(
                "{}",
                serde_json::json!({
                    "archive": archive_path,
                    "verdict": overall,
                    "partial": verdict.partial,
                })
            );
        } else {
            let suffix = if verdict.partial { " (partial)" } else { "" };
            println!("archive {}: {}{}", archive_path, overall, suffix);
        }
        return if verdict.passed() { 0 } else { 1 };
    }

    let mut all_pass = true;
    for receipt_path in &receipts {
        let verdict = match verify_receipt_file(std::path::Path::new(receipt_path), &opts) {
            Ok(verdict) => verdict,
            Err(err) => return report_operational_error(receipt_path, &err, &format),
        };

        print_verdict(&verdict, &format);

        if !verdict.passed() {
            all_pass = false;
        }
    }

    if all_pass {
        0
    } else {
        1
    }
}

/// Handle `attest export`.
///
/// Exit codes: 0 = envelope written, 1 = precondition failed (unsigned or
/// invalid receipt, no envelope signing key), 2 = operational error.
fn handle_export(
    receipt: String,
    format: String,
    output: String,
    allow_unsigned: bool,
    key: Option<String>,
    workspace: Option<String>,
) -> i32 {
    use attest::interop::{export_receipt_file, ExportOptions, ExportOutcome};

    if format != "in-toto" {
        eprintln!(
            "error: unsupported --format '{}' (expected in-toto)",
            format
        );
        return 2;
    }
    let workspace = workspace
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().expect("cannot determine current directory"));

    let options = ExportOptions {
        allow_unsigned,
        key,
        workspace,
    };
    match export_receipt_file(std::path::Path::new(&receipt), &options) {
        Ok(ExportOutcome::Written { json, warnings }) => {
            for warning in &warnings {
                eprintln!("warning: {}", warning);
            }
            if output == "-" {
                print!("{}", json);
                0
            } else {
                match std::fs::write(&output, &json) {
                    Ok(()) => {
                        println!("{}", output);
                        0
                    }
                    Err(err) => {
                        eprintln!("error: cannot write {}: {}", output, err);
                        2
                    }
                }
            }
        }
        Ok(ExportOutcome::UnsignedReceipt) => {
            eprintln!("error: receipt is unsigned (use --allow-unsigned to export anyway)");
            1
        }
        Ok(ExportOutcome::InvalidReceiptSignature(detail)) => {
            eprintln!("error: {}", detail);
            1
        }
        Ok(ExportOutcome::NoSigningKey(detail)) => {
            eprintln!("error: {}", detail);
            1
        }
        Err(err) => {
            eprintln!("error: {:#}", err);
            2
        }
    }
}

/// Handle `attest import`. Prints the same report as
/// `attest verify`; exit codes 0 = pass, 1 = fail, 2 = operational error.
fn handle_import(
    statement: String,
    format: String,
    workspace: Option<String>,
    trust_store: Option<String>,
    trust_statement_time: bool,
    require: Vec<String>,
    report: String,
) -> i32 {
    use attest::interop::{import_statement_file, ImportOptions};

    let policy = match attest::verify::Policy::parse(&require) {
        Ok(policy) => policy,
        Err(err) => {
            eprintln!("error: --require: {err}");
            return 2;
        }
    };

    if format != "in-toto" {
        eprintln!(
            "error: unsupported --format '{}' (expected in-toto)",
            format
        );
        return 2;
    }
    if report != "text" && report != "json" {
        eprintln!(
            "error: unsupported --report '{}' (expected text or json)",
            report
        );
        return 2;
    }
    let workspace = workspace
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().expect("cannot determine current directory"));

    let options = ImportOptions {
        workspace,
        trust_store: trust_store.map(std::path::PathBuf::from),
        trust_statement_time,
        policy,
    };
    let verdict = match import_statement_file(std::path::Path::new(&statement), &options) {
        Ok(verdict) => verdict,
        Err(err) => {
            eprintln!("error: {:#}", err);
            return 2;
        }
    };
    print_verdict(&verdict, &report);
    if verdict.passed() {
        0
    } else {
        1
    }
}

/// An error that stopped verification before any verdict: exit 2, and in
/// JSON mode one record that says so, with `resource-limit` set apart from
/// every other operational cause so a consumer never confuses "too big to
/// look at" with "looked at and wrong".
fn report_operational_error(subject: &str, err: &anyhow::Error, format: &str) -> i32 {
    let kind = if attest::archive::resource_limit(err).is_some() {
        "resource-limit"
    } else {
        "operational"
    };
    eprintln!("error: {err:#}");
    if format == "json" {
        println!(
            "{}",
            serde_json::json!({
                "subject": subject,
                "verdict": "error",
                "error": kind,
                "detail": format!("{err:#}"),
            })
        );
    }
    2
}

/// Print one receipt verdict in the requested format (text or NDJSON) and
/// its warnings to stderr.
fn print_verdict(verdict: &attest::verify::ReceiptVerdict, format: &str) {
    use attest::verify::CheckStatus;

    if format == "json" {
        println!(
            "{}",
            serde_json::to_string(verdict).expect("verdict serializes")
        );
    } else {
        println!("{}: {}", verdict.receipt, verdict.verdict);
        for check in &verdict.checks {
            let status = match check.status {
                CheckStatus::Pass => "pass",
                CheckStatus::Fail => "FAIL",
                CheckStatus::Skipped => "skipped",
            };
            println!("  {:<12} {:<8} {}", check.name, status, check.detail);
        }
        if let Some(key) = &verdict.signed_by {
            println!("  signed by: {}", key);
        }
        if let Some(execution) = &verdict.execution {
            println!(
                "  execution: {}{}",
                execution.outcome,
                if execution.failed_steps > 0 {
                    format!(" ({} failed step(s))", execution.failed_steps)
                } else {
                    String::new()
                }
            );
        }
        if let Some(policy) = &verdict.policy {
            if !policy.required.is_empty() {
                let names: Vec<&str> = policy.required.iter().map(|r| r.name()).collect();
                println!("  required: {}", names.join(", "));
            }
            for unmet in &policy.unmet {
                println!(
                    "  REFUSED: requirement '{}' not met: {}",
                    unmet.requirement.name(),
                    unmet.reason
                );
            }
        }
        if let Some(material) = &verdict.trust_material {
            match (material.state.as_str(), &material.issuer) {
                ("none", _) | (_, None) => println!(
                    "  trust material: no bundle on record; revocations are as current as this \
                     store's last manual change"
                ),
                (state, Some(issuer)) => println!(
                    "  trust material: bundle {} from {} {} {} ({})",
                    material.sequence.unwrap_or_default(),
                    issuer,
                    if state == "expired" {
                        "expired at"
                    } else {
                        "valid until"
                    },
                    material
                        .valid_until
                        .map(|t| t.to_string())
                        .unwrap_or_default(),
                    material.judged_by
                ),
            }
        }
    }

    for warning in &verdict.warnings {
        eprintln!("warning: {}", warning);
    }
}

/// Handle `attest causal export`.
///
/// Exit codes: 0 = archive written, 1 = causal chain has unresolved
/// references and --allow-partial was not given, 2 = operational error.
fn handle_causal_export(receipt: String, output: String, allow_partial: bool) -> i32 {
    use attest::archive::{export_archive, ExportOutcome};

    match export_archive(
        std::path::Path::new(&receipt),
        std::path::Path::new(&output),
        allow_partial,
    ) {
        Ok(ExportOutcome::Written { partial }) => {
            if partial {
                eprintln!("warning: partial archive (unresolved causal references)");
            }
            println!("{}", output);
            0
        }
        Ok(ExportOutcome::IncompleteChain { missing }) => {
            eprintln!(
                "error: causal chain references receipts missing from the local ledger: {} (use --allow-partial to export anyway)",
                missing.join(", ")
            );
            1
        }
        Err(err) => {
            eprintln!("error: {:#}", err);
            2
        }
    }
}

/// Handle `attest image sign` (spec IMG-1..IMG-6/IMG-11/IMG-12).
///
/// Exit codes: 0 signed, 1 precondition failed (dirty tree),
/// 2 operational error.
#[allow(clippy::too_many_arguments)]
fn handle_image_sign(
    image_ref: String,
    key: String,
    annotations: Vec<String>,
    allow_file_key: bool,
    no_require_clean_tree: bool,
    clean_paths: Vec<String>,
    receipt_dir: Option<String>,
    sign: bool,
    receipt_key: Option<String>,
) -> i32 {
    use attest::crypto::image_signing::{sign_image, ImageSignRequest};

    let workspace = match std::env::current_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("error: cannot determine current directory: {}", err);
            return 2;
        }
    };

    let mut parsed_annotations = Vec::new();
    for annotation in &annotations {
        match annotation.split_once('=') {
            Some((k, v)) if !k.is_empty() => {
                parsed_annotations.push((k.to_string(), v.to_string()))
            }
            _ => {
                eprintln!("error: invalid --annotation '{}': expected K=V", annotation);
                return 2;
            }
        }
    }

    let request = ImageSignRequest {
        image_ref,
        key_uri: key,
        annotations: parsed_annotations,
        allow_file_key,
        require_clean_tree: !no_require_clean_tree,
        clean_paths,
        receipt_dir: receipt_dir.map(std::path::PathBuf::from),
        sign_receipt: sign,
        receipt_key,
    };

    match sign_image(&workspace, &request) {
        Ok(outcome) => {
            println!(
                "signed {} (revision {})",
                request.image_ref, outcome.revision
            );
            println!("{}", outcome.receipt_path.display());
            0
        }
        Err(failure) => {
            eprintln!("error: {}", failure.message());
            failure.exit_code()
        }
    }
}

/// Handle image verification command
/// Handle `attest image verify` with supply-chain checks:
/// SBOM (IMG-7), SLSA provenance (IMG-8), revision binding (IMG-8/9),
/// signature with the Azure KMS export workaround (IMG-9/10). Exit
/// codes per IMG-12: 0 pass, 1 enforced check failed, 2 operational.
fn handle_image_supply_chain(
    request: attest::crypto::supply_chain::SupplyChainRequest,
    format: String,
    receipt_options: Option<attest::crypto::supply_chain::VerifyReceiptOptions>,
) -> i32 {
    use attest::crypto::supply_chain::{write_verification_receipt, SupplyChainVerifier};

    if format != "text" && format != "json" {
        eprintln!(
            "error: invalid --format '{}': expected text or json",
            format
        );
        return 2;
    }

    let verifier = match SupplyChainVerifier::locate(request.signature_requested()) {
        Ok(verifier) => verifier,
        Err(failure) => {
            eprintln!("error: {}", failure.message());
            return failure.exit_code();
        }
    };

    match verifier.verify(&request) {
        Ok(report) => {
            if format == "json" {
                match serde_json::to_string_pretty(&report) {
                    Ok(json) => println!("{}", json),
                    Err(err) => {
                        eprintln!("error: cannot serialize report: {}", err);
                        return 2;
                    }
                }
            } else {
                println!("image: {}", report.image);
                for check in &report.checks {
                    let status = match check.status {
                        attest::crypto::supply_chain::CheckStatus::Pass => "pass",
                        attest::crypto::supply_chain::CheckStatus::Fail => "fail",
                        attest::crypto::supply_chain::CheckStatus::Skipped => "skipped",
                    };
                    println!("  {:<10} {:<7} {}", check.name, status, check.detail);
                }
                let names: Vec<&str> = report.policy.required.iter().map(|r| r.name()).collect();
                println!("required: {}", names.join(", "));
                for unmet in &report.policy.unmet {
                    println!(
                        "REFUSED: requirement '{}' not met: {}",
                        unmet.requirement.name(),
                        unmet.reason
                    );
                }
                println!("verdict: {}", report.verdict);
            }
            if let Some(options) = &receipt_options {
                let workspace = match std::env::current_dir() {
                    Ok(dir) => dir,
                    Err(err) => {
                        eprintln!("error: cannot determine current directory: {}", err);
                        return 2;
                    }
                };
                match write_verification_receipt(&workspace, &request, &report, options) {
                    Ok(path) => println!("{}", path.display()),
                    Err(err) => {
                        eprintln!("error: cannot write verification receipt: {:#}", err);
                        return 2;
                    }
                }
            }
            if report.passed() {
                0
            } else {
                1
            }
        }
        Err(failure) => {
            eprintln!("error: {}", failure.message());
            failure.exit_code()
        }
    }
}

async fn handle_image_config(show: bool, test_cosign: bool) -> Result<()> {
    use attest::crypto::image_verification::{ImageVerificationConfig, ImageVerifier};

    if show {
        let config = ImageVerificationConfig::default();
        println!("Current Image Verification Configuration:");
        println!("Require signatures: {}", config.require_signatures);
        println!(
            "   Verify transparency log: {}",
            config.verify_transparency_log
        );
        println!("Enforcement level: {:?}", config.enforcement_level);
        // Not printed: the trusted key and issuer lists. This shows the
        // default configuration, where both are empty, and a line about
        // trusted keys next to a key count reads as more than it is.
    }

    if test_cosign {
        println!("\nTesting cosign availability...");
        match ImageVerifier::find_cosign_binary() {
            Ok(Some(path)) => {
                println!("cosign found at: {}", path);
            }
            Ok(None) => {
                println!("cosign not found in PATH");
                println!("Install cosign: https://docs.sigstore.dev/cosign/installation/");
            }
            Err(e) => {
                println!("Error checking cosign: {}", e);
            }
        }
    }

    Ok(())
}

/// Handle causal path query command
async fn handle_causal_path(from_event: String, to_event: String, detailed: bool) -> Result<()> {
    use attest::storage::Storage;

    println!("Querying causal path: {} -> {}", from_event, to_event);

    let mut storage = Storage::new(std::env::current_dir()?.as_path())?;
    storage.load_keypair(true)?;

    let ledger = storage.get_causal_ledger().await?;
    let query = ledger.query_causal_path(&from_event, &to_event).await?;

    if query.causal_path.is_empty() {
        println!("No causal path found between events");
        return Ok(());
    }

    if query.is_valid {
        println!("Valid causal path found:");
        // The ends of a path are worth marking; they used to be marked with
        // glyphs, which is fine on a terminal and useless in a log or a
        // ticket. Words survive both.
        let last = query.causal_path.len() - 1;
        for (i, event_id) in query.causal_path.iter().enumerate() {
            let position = match i {
                0 => "from",
                n if n == last => "to  ",
                _ => "    ",
            };
            println!("  {position}  {event_id}");
        }
    } else {
        println!("Invalid causal path (verification failed)");
    }

    if detailed {
        println!("\nDetailed Path Information:");
        println!("Path length: {}", query.causal_path.len());
        println!("Valid signatures: {}", query.is_valid);
    }

    Ok(())
}

/// Handle causal ledger statistics command
async fn handle_causal_stats(detailed: bool) -> Result<()> {
    use attest::storage::Storage;

    println!("Causal Ledger Statistics");

    let mut storage = Storage::new(std::env::current_dir()?.as_path())?;
    let ledger = storage.get_causal_ledger().await?;
    let stats = ledger.get_statistics();

    println!("Total events: {}", stats.total_events);
    println!("Total chains: {}", stats.total_chains);
    println!("Root events: {}", stats.root_events);
    println!("Leaf events: {}", stats.leaf_events);

    if detailed {
        println!("Average chain length: {}", stats.avg_chain_length);
        println!(
            "   Parallelization factor: {:.2}",
            if stats.total_events > 0 {
                stats.total_events as f64 / stats.total_chains as f64
            } else {
                0.0
            }
        );
    }

    Ok(())
}

/// Handle causal events listing command
async fn handle_causal_events(limit: usize, step_filter: Option<String>) -> Result<()> {
    use attest::storage::Storage;

    if let Some(step) = &step_filter {
        println!("Recent causal events for step '{step}':");
    }

    let mut storage = Storage::new(std::env::current_dir()?.as_path())?;
    let ledger = storage.get_causal_ledger().await?;
    ledger.load_events().await?;

    let mut events = match step_filter {
        Some(step) => ledger.get_events_by_step(&step).await?,
        None => ledger.get_all_events().await?,
    };

    if events.is_empty() {
        println!("no causal events recorded");
        return Ok(());
    }

    // Most recent first, then truncated: "recent" has to mean recent.
    events.sort_by_key(|event| std::cmp::Reverse(event.timestamp));
    let total = events.len();
    events.truncate(limit);

    for event in &events {
        println!(
            "{}  {:<24}  exit {:<3}  {}",
            event.timestamp.to_rfc3339(),
            event.step_name,
            event.exit_code,
            &event.event_id[..event.event_id.len().min(12)]
        );
    }

    if total > events.len() {
        println!(
            "showing {} of {} events; raise --limit to see more",
            events.len(),
            total
        );
    }

    Ok(())
}

/// Handle causal chain building command
async fn handle_causal_chain(event_ids: Vec<String>, save: bool) -> Result<()> {
    use attest::storage::Storage;

    if event_ids.is_empty() {
        println!("No event IDs provided");
        return Ok(());
    }

    println!("Building causal chain from {} events", event_ids.len());

    let mut storage = Storage::new(std::env::current_dir()?.as_path())?;
    storage.load_keypair(true)?;

    let ledger = storage.get_causal_ledger().await?;
    let chain = ledger.build_causal_chain(event_ids.clone()).await?;

    println!("Causal chain built successfully:");
    println!("Chain ID: {}", chain.chain_id);
    println!("Events: {}", chain.events.len());
    println!("Chain hash: {}", chain.chain_hash);

    if chain.chain_signature.is_some() {
        println!("Cryptographically signed");
    }

    if save {
        println!("Chain saved to ledger storage");
    }

    println!("\nEvent sequence:");
    for (i, event) in chain.events.iter().enumerate() {
        println!(
            "   {}. {} ({})",
            i + 1,
            event.step_name,
            &event.event_id[..8]
        );
        if !event.causal_parents.is_empty() {
            println!("Dependencies: {}", event.causal_parents.len());
        }
    }

    Ok(())
}
