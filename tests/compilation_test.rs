//! Smoke test for the public library surface.
//!
//! This file previously gated blocks behind the `gitops` and `policy`
//! features. Those modules now live in separate plugin programs (see
//! the documentation site) and the crate has no cargo features left, so
//! what remains is the one assertion that still means something: the
//! library links and the default operation mode is the cheap one.

#[cfg(test)]
mod tests {
    use anyhow::Result;

    #[tokio::test]
    async fn test_core_compilation() -> Result<()> {
        let core = attest::core::AttestCore::new().await?;
        assert_eq!(core.get_mode(), attest::core::OperationMode::Light);
        core.show_mode_info().await?;
        Ok(())
    }
}
