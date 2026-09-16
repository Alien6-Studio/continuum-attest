//! Pipeline export functionality

use anyhow::Result;
use std::collections::HashMap;

use crate::pipeline::Pipeline;

#[derive(Debug, Clone, Copy)]
pub enum ExportFormat {
    DockerCompose,
    GitLabCI,
    GitHubActions,
    Makefile,
    Jenkins,
}

#[derive(Debug, Clone)]
pub struct ExportOptions {
    pub format: ExportFormat,
    pub output_file: Option<String>,
    pub template_dir: Option<String>,
    pub variables: HashMap<String, String>,
    pub include_cache: bool,
    pub include_signatures: bool,
    pub target_environment: Option<String>,
}

pub struct MultiFormatExporter;

impl MultiFormatExporter {
    pub fn export(pipeline: &Pipeline, options: ExportOptions) -> Result<String> {
        match options.format {
            ExportFormat::DockerCompose => Self::export_docker_compose(pipeline, &options),
            ExportFormat::GitLabCI => Self::export_gitlab_ci(pipeline, &options),
            ExportFormat::GitHubActions => Self::export_github_actions(pipeline, &options),
            ExportFormat::Makefile => Self::export_makefile(pipeline, &options),
            ExportFormat::Jenkins => Self::export_jenkins(pipeline, &options),
        }
    }

    fn export_docker_compose(pipeline: &Pipeline, _options: &ExportOptions) -> Result<String> {
        let mut output = String::new();

        output.push_str("version: '3.8'\n");
        output.push_str("services:\n");

        for (step_name, step) in &pipeline.steps {
            output.push_str(&format!("  {}:\n", step_name));

            let image = step.image.as_deref().unwrap_or("alpine:latest");
            output.push_str(&format!("    image: {}\n", image));

            if !step.run.trim().is_empty() {
                output.push_str(&format!("    command: {}\n", step.run));
            }
        }

        Ok(output)
    }

    fn export_gitlab_ci(pipeline: &Pipeline, _options: &ExportOptions) -> Result<String> {
        let mut output = String::new();

        let default_name = "unnamed".to_string();
        let pipeline_name = pipeline.name.as_ref().unwrap_or(&default_name);
        output.push_str(&format!("# Pipeline: {}\n", pipeline_name));
        output.push_str(&format!("# Version: {}\n\n", pipeline.version));

        output.push_str("stages:\n");
        for step_name in pipeline.steps.keys() {
            output.push_str(&format!("  - {}\n", step_name));
        }
        output.push('\n');

        for (step_name, step) in &pipeline.steps {
            output.push_str(&format!("{}:\n", step_name));
            output.push_str(&format!("  stage: {}\n", step_name));

            let image = step.image.as_deref().unwrap_or("alpine:latest");
            output.push_str(&format!("  image: {}\n", image));

            if !step.run.trim().is_empty() {
                output.push_str("  script:\n");
                output.push_str(&format!("    - {}\n", step.run));
            }
            output.push('\n');
        }

        Ok(output)
    }

    fn export_github_actions(pipeline: &Pipeline, _options: &ExportOptions) -> Result<String> {
        let mut output = String::new();

        let default_name = "unnamed".to_string();
        let pipeline_name = pipeline.name.as_ref().unwrap_or(&default_name);
        output.push_str(&format!("name: {}\n\n", pipeline_name));

        output.push_str("on: [push, pull_request]\n\n");
        output.push_str("jobs:\n");

        for (step_name, step) in &pipeline.steps {
            output.push_str(&format!("  {}:\n", step_name));
            output.push_str("    runs-on: ubuntu-latest\n");

            output.push_str("    steps:\n");
            output.push_str("    - uses: actions/checkout@v3\n");

            if !step.run.trim().is_empty() {
                output.push_str(&format!("    - name: {}\n", step_name));
                output.push_str("      run: |\n");
                output.push_str(&format!("        {}\n", step.run));
            }
            output.push('\n');
        }

        Ok(output)
    }

    fn export_makefile(pipeline: &Pipeline, _options: &ExportOptions) -> Result<String> {
        let mut output = String::new();

        let default_name = "unnamed".to_string();
        let pipeline_name = pipeline.name.as_ref().unwrap_or(&default_name);
        output.push_str(&format!("# Generated Makefile for {}\n", pipeline_name));
        output.push_str(&format!("# Version: {}\n\n", pipeline.version));

        output.push_str(".PHONY: all clean");
        for step_name in pipeline.steps.keys() {
            output.push_str(&format!(" {}", step_name));
        }
        output.push_str("\n\n");

        output.push_str("all:");
        for step_name in pipeline.steps.keys() {
            output.push_str(&format!(" {}", step_name));
        }
        output.push_str("\n\n");

        for (step_name, step) in &pipeline.steps {
            output.push_str(&format!("{}:\n", step_name));

            if !step.run.trim().is_empty() {
                output.push_str(&format!("\t{}\n", step.run));
            }
            output.push('\n');
        }

        output.push_str("clean:\n");
        output.push_str("\trm -rf build/\n");

        Ok(output)
    }

    fn export_jenkins(pipeline: &Pipeline, _options: &ExportOptions) -> Result<String> {
        let mut output = String::new();

        let default_name = "unnamed".to_string();
        let _pipeline_name = pipeline.name.as_ref().unwrap_or(&default_name);
        output.push_str("pipeline {\n");
        output.push_str("    agent any\n\n");

        output.push_str("    stages {\n");

        for (step_name, step) in &pipeline.steps {
            output.push_str(&format!("        stage('{}') {{\n", step_name));
            output.push_str("            steps {\n");

            if !step.run.trim().is_empty() {
                output.push_str(&format!("                sh '{}'\n", step.run));
            }

            output.push_str("            }\n");
            output.push_str("        }\n");
        }

        output.push_str("    }\n");
        output.push_str("}\n");

        Ok(output)
    }
}
