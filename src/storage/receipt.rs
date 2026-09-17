//! Receipt handling for execution tracking

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Execution receipt that tracks pipeline run results
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Receipt {
    /// Unique identifier for this receipt
    pub id: String,
    /// Hash of the pipeline configuration
    pub pipeline_hash: String,
    /// Timestamp when execution started
    pub start_time: DateTime<Utc>,
    /// Timestamp when execution completed
    pub end_time: Option<DateTime<Utc>>,
    /// Overall execution status
    pub status: ExecutionStatus,
    /// Individual step results
    pub step_results: Vec<StepResult>,
    /// Environment variables at execution time
    pub environment: HashMap<String, String>,
    /// Total execution duration in seconds
    pub total_duration_secs: Option<u64>,
    /// Cryptographic signature of the receipt
    pub signature: Option<String>,
    /// Version of ATTEST that generated this receipt
    pub attest_version: String,
}

/// Status of pipeline execution
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ExecutionStatus {
    /// Execution completed successfully
    Success,
    /// Execution failed
    Failed,
    /// Execution was cancelled
    Cancelled,
    /// Execution is still in progress
    InProgress,
    /// Execution timed out
    TimedOut,
}

/// Result of executing a single step
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StepResult {
    /// Name of the step
    pub name: String,
    /// Hash of step inputs
    pub input_hash: String,
    /// Hash of step outputs  
    pub output_hash: String,
    /// Step execution duration in seconds
    pub duration_secs: u64,
    /// Exit code from step execution
    pub exit_code: i32,
    /// Whether this step hit the cache
    pub cache_hit: bool,
    /// Standard output from step
    pub stdout: String,
    /// Standard error from step
    pub stderr: String,
    /// Timestamp when step started
    pub start_time: DateTime<Utc>,
    /// Timestamp when step completed
    pub end_time: DateTime<Utc>,
}

impl Receipt {
    /// Create a new receipt for a pipeline execution
    pub fn new(pipeline_hash: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            pipeline_hash,
            start_time: Utc::now(),
            end_time: None,
            status: ExecutionStatus::InProgress,
            step_results: Vec::new(),
            environment: std::env::vars().collect(),
            total_duration_secs: None,
            signature: None,
            attest_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Mark the receipt as completed with the given status
    pub fn complete(&mut self, status: ExecutionStatus) {
        self.end_time = Some(Utc::now());
        self.status = status;

        if let Some(end_time) = self.end_time {
            self.total_duration_secs = Some((end_time - self.start_time).num_seconds() as u64);
        }
    }

    /// Add a step result to the receipt
    pub fn add_step_result(&mut self, step_result: StepResult) {
        self.step_results.push(step_result);
    }

    /// Get the number of successful steps
    pub fn successful_steps(&self) -> usize {
        self.step_results
            .iter()
            .filter(|s| s.exit_code == 0)
            .count()
    }

    /// Get the number of failed steps
    pub fn failed_steps(&self) -> usize {
        self.step_results
            .iter()
            .filter(|s| s.exit_code != 0)
            .count()
    }

    /// Get total cache hits
    pub fn cache_hits(&self) -> usize {
        self.step_results.iter().filter(|s| s.cache_hit).count()
    }

    /// Check if the execution was successful
    pub fn is_successful(&self) -> bool {
        matches!(self.status, ExecutionStatus::Success) && self.failed_steps() == 0
    }

    /// Get execution summary statistics
    pub fn summary(&self) -> ExecutionSummary {
        ExecutionSummary {
            total_steps: self.step_results.len(),
            successful_steps: self.successful_steps(),
            failed_steps: self.failed_steps(),
            cache_hits: self.cache_hits(),
            total_duration_secs: self.total_duration_secs.unwrap_or(0),
            status: self.status.clone(),
        }
    }

    /// Sign the receipt with the provided signature
    pub fn sign(&mut self, signature: String) {
        self.signature = Some(signature);
    }

    /// Verify that the receipt has a valid signature
    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
    }

    /// Load receipt from YAML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let receipt: Receipt = serde_yaml::from_str(&content)?;
        Ok(receipt)
    }

    /// Save receipt to YAML file
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = serde_yaml::to_string(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Convert receipt to JSON string
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Create receipt from JSON string
    pub fn from_json(json: &str) -> Result<Self> {
        Ok(serde_json::from_str(json)?)
    }
}

impl StepResult {
    /// Create a new step result
    pub fn new(
        name: String,
        input_hash: String,
        output_hash: String,
        exit_code: i32,
        cache_hit: bool,
        stdout: String,
        stderr: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            name,
            input_hash,
            output_hash,
            duration_secs: 0,
            exit_code,
            cache_hit,
            stdout,
            stderr,
            start_time: now,
            end_time: now,
        }
    }

    /// Set the duration for this step
    pub fn with_duration(mut self, duration_secs: u64) -> Self {
        self.duration_secs = duration_secs;
        self.end_time = self.start_time + chrono::Duration::seconds(duration_secs as i64);
        self
    }

    /// Check if this step was successful
    pub fn is_successful(&self) -> bool {
        self.exit_code == 0
    }
}

/// Summary statistics for a receipt
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExecutionSummary {
    pub total_steps: usize,
    pub successful_steps: usize,
    pub failed_steps: usize,
    pub cache_hits: usize,
    pub total_duration_secs: u64,
    pub status: ExecutionStatus,
}

impl ExecutionSummary {
    /// Calculate cache hit rate as a percentage
    pub fn cache_hit_rate(&self) -> f64 {
        if self.total_steps == 0 {
            0.0
        } else {
            (self.cache_hits as f64 / self.total_steps as f64) * 100.0
        }
    }

    /// Calculate success rate as a percentage
    pub fn success_rate(&self) -> f64 {
        if self.total_steps == 0 {
            0.0
        } else {
            (self.successful_steps as f64 / self.total_steps as f64) * 100.0
        }
    }
}
