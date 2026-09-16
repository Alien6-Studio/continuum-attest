use anyhow::Result;
use chrono::{DateTime, TimeZone, Utc};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Provides deterministic time for reproducible builds
pub struct DeterministicTime {
    fixed_timestamp: Option<DateTime<Utc>>,
    start_time: DateTime<Utc>,
    virtual_offset: Arc<AtomicU64>,
}

impl DeterministicTime {
    /// Create a new deterministic time provider
    pub fn new(fixed_timestamp: Option<DateTime<Utc>>) -> Result<Self> {
        let start_time = fixed_timestamp.unwrap_or_else(|| {
            // Use a fixed timestamp for reproducibility if none provided
            Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0)
                .single()
                .expect("2024-01-01T00:00:00Z is a valid, unambiguous UTC timestamp")
        });

        Ok(Self {
            fixed_timestamp,
            start_time,
            virtual_offset: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Get the current deterministic time
    pub fn current_time(&self) -> DateTime<Utc> {
        if let Some(fixed) = self.fixed_timestamp {
            // Always return the same fixed timestamp
            fixed
        } else {
            // Return start time plus virtual offset
            let offset_secs = self.virtual_offset.load(Ordering::SeqCst);
            self.start_time + chrono::Duration::seconds(offset_secs as i64)
        }
    }

    /// Advance virtual time by the specified seconds
    pub fn advance_time(&self, seconds: u64) {
        self.virtual_offset.fetch_add(seconds, Ordering::SeqCst);
    }

    /// Reset virtual time to start
    pub fn reset_time(&self) {
        self.virtual_offset.store(0, Ordering::SeqCst);
    }

    /// Get environment variables for deterministic time
    pub fn environment_variables(&self) -> HashMap<String, String> {
        let current = self.current_time();
        let mut env = HashMap::new();

        // Set standard time environment variables
        env.insert("ATTEST_DETERMINISTIC_TIME".to_string(), "1".to_string());
        env.insert(
            "ATTEST_FIXED_TIMESTAMP".to_string(),
            current.timestamp().to_string(),
        );
        env.insert(
            "ATTEST_FIXED_TIME_RFC3339".to_string(),
            current.to_rfc3339(),
        );

        // Unix timestamp variants
        env.insert(
            "ATTEST_UNIX_TIMESTAMP".to_string(),
            current.timestamp().to_string(),
        );
        env.insert(
            "ATTEST_UNIX_TIMESTAMP_MS".to_string(),
            current.timestamp_millis().to_string(),
        );

        // Date components for scripts that need them
        env.insert("ATTEST_YEAR".to_string(), current.format("%Y").to_string());
        env.insert("ATTEST_MONTH".to_string(), current.format("%m").to_string());
        env.insert("ATTEST_DAY".to_string(), current.format("%d").to_string());
        env.insert("ATTEST_HOUR".to_string(), current.format("%H").to_string());
        env.insert(
            "ATTEST_MINUTE".to_string(),
            current.format("%M").to_string(),
        );
        env.insert(
            "ATTEST_SECOND".to_string(),
            current.format("%S").to_string(),
        );

        // ISO format
        env.insert(
            "ATTEST_ISO_DATE".to_string(),
            current.format("%Y-%m-%d").to_string(),
        );
        env.insert(
            "ATTEST_ISO_DATETIME".to_string(),
            current.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        );

        // Build-specific variables commonly used
        env.insert(
            "BUILD_TIMESTAMP".to_string(),
            current.timestamp().to_string(),
        );
        env.insert(
            "BUILD_DATE".to_string(),
            current.format("%Y-%m-%d").to_string(),
        );
        env.insert(
            "BUILD_TIME".to_string(),
            current.format("%H:%M:%S").to_string(),
        );

        // Set SOURCE_DATE_EPOCH for reproducible builds
        env.insert(
            "SOURCE_DATE_EPOCH".to_string(),
            current.timestamp().to_string(),
        );

        env
    }

    /// Generate deterministic random seed based on current time
    pub fn deterministic_seed(&self) -> u64 {
        self.current_time().timestamp() as u64
    }

    /// Get a deterministic temporary directory name
    pub fn temp_dir_name(&self, prefix: &str) -> String {
        format!("{}_{}", prefix, self.current_time().timestamp())
    }
}

/// Utility functions for deterministic execution environments
pub struct DeterministicEnv;

impl DeterministicEnv {
    /// Remove non-deterministic environment variables
    pub fn sanitize_environment(env: &mut HashMap<String, String>) {
        let non_deterministic_vars = [
            "RANDOM",
            "SECONDS",
            "EPOCHREALTIME",
            "EPOCHSECONDS",
            "PWD", // Can vary between runs
            "OLDPWD",
            "SHLVL",
            "_", // Last command
            "PS1",
            "PS2",
            "PS3",
            "PS4",
            "HISTFILE",
            "HISTSIZE",
            "HISTCONTROL",
            "HOSTNAME", // May not be deterministic
        ];

        for var in &non_deterministic_vars {
            env.remove(*var);
        }

        // Ensure consistent locale
        env.insert("LANG".to_string(), "C".to_string());
        env.insert("LC_ALL".to_string(), "C".to_string());
        env.insert("LC_COLLATE".to_string(), "C".to_string());
        env.insert("LC_CTYPE".to_string(), "C".to_string());
        env.insert("LC_MESSAGES".to_string(), "C".to_string());
        env.insert("LC_MONETARY".to_string(), "C".to_string());
        env.insert("LC_NUMERIC".to_string(), "C".to_string());
        env.insert("LC_TIME".to_string(), "C".to_string());

        // Set deterministic timezone
        env.insert("TZ".to_string(), "UTC".to_string());
    }

    /// Create a minimal deterministic environment
    pub fn minimal_environment() -> HashMap<String, String> {
        let mut env = HashMap::new();

        // Essential variables
        env.insert(
            "PATH".to_string(),
            "/usr/local/bin:/usr/bin:/bin".to_string(),
        );
        env.insert("HOME".to_string(), "/tmp/attest-home".to_string());
        env.insert("USER".to_string(), "attest".to_string());
        env.insert("LOGNAME".to_string(), "attest".to_string());

        // Deterministic settings
        env.insert("LANG".to_string(), "C".to_string());
        env.insert("LC_ALL".to_string(), "C".to_string());
        env.insert("TZ".to_string(), "UTC".to_string());

        // Shell settings for reproducibility
        env.insert("SHELL".to_string(), "/bin/sh".to_string());
        env.insert("TERM".to_string(), "dumb".to_string());

        env
    }

    /// Set up deterministic random number generation
    pub fn setup_deterministic_random(env: &mut HashMap<String, String>, seed: u64) {
        // Set seed for various RNG systems
        env.insert("PYTHONHASHSEED".to_string(), seed.to_string());
        env.insert("ATTEST_RANDOM_SEED".to_string(), seed.to_string());
    }
}
