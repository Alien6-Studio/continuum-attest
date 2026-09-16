//! Tests for DAG analysis and advanced cycle detection

use anyhow::Result;
use attest::pipeline::{ExecutionDAG, Pipeline};
use std::io::Write;
use tempfile::NamedTempFile;

fn create_temp_pipeline(yaml_content: &str) -> Result<NamedTempFile> {
    let mut temp_file = NamedTempFile::new()?;
    write!(temp_file, "{}", yaml_content)?;
    Ok(temp_file)
}

#[tokio::test]
async fn test_dag_build_and_basic_analysis() -> Result<()> {
    let yaml = r#"
version: "0.1"
name: "dag-analysis"

steps:
  start:
    run: "echo start"
    
  middle:
    run: "echo middle"
    needs: ["start"]
    
  end:
    run: "echo end"
    needs: ["middle"]
"#;

    let temp_file = create_temp_pipeline(yaml)?;
    let pipeline = Pipeline::load(temp_file.path().to_str().unwrap()).await?;
    let dag = ExecutionDAG::build(&pipeline)?;

    assert_eq!(dag.nodes.len(), 3);
    assert!(dag.nodes.contains(&"start".to_string()));
    assert!(dag.nodes.contains(&"middle".to_string()));
    assert!(dag.nodes.contains(&"end".to_string()));

    // Check edges: start -> middle -> end
    assert_eq!(dag.edges.get("start").unwrap(), &vec!["middle".to_string()]);
    assert_eq!(dag.edges.get("middle").unwrap(), &vec!["end".to_string()]);
    assert_eq!(dag.edges.get("end").unwrap(), &Vec::<String>::new());

    Ok(())
}

#[tokio::test]
async fn test_complex_dag_structure() -> Result<()> {
    let yaml = r#"
version: "0.1"
name: "complex-dag"

steps:
  # Level 0 - roots
  lint:
    run: "lint code"
  
  security:
    run: "security scan"
    
  # Level 1 - depends on roots
  build:
    run: "build project"
    needs: ["lint"]
    
  docs:
    run: "generate docs"
    needs: ["lint"]
    
  # Level 2 - depends on level 1
  test:
    run: "run tests"
    needs: ["build"]
    
  # Level 3 - depends on multiple previous levels
  integration:
    run: "integration tests"
    needs: ["test", "docs", "security"]
    
  # Level 4 - final
  deploy:
    run: "deploy app"
    needs: ["integration"]
"#;

    let temp_file = create_temp_pipeline(yaml)?;
    let pipeline = Pipeline::load(temp_file.path().to_str().unwrap()).await?;
    let dag = ExecutionDAG::build(&pipeline)?;
    let analysis = dag.analyze();

    // Check structure analysis
    assert_eq!(analysis.total_nodes, 7);
    assert_eq!(analysis.max_depth, 4); // 0: lint/security, 1: build/docs, 2: test, 3: integration, 4: deploy
    assert!(!analysis.is_linear); // Has parallelization opportunities

    // Check root nodes (no dependencies)
    assert_eq!(analysis.root_nodes.len(), 2);
    assert!(analysis.root_nodes.contains(&"lint".to_string()));
    assert!(analysis.root_nodes.contains(&"security".to_string()));

    // Check leaf nodes (no dependents)
    assert_eq!(analysis.leaf_nodes.len(), 1);
    assert!(analysis.leaf_nodes.contains(&"deploy".to_string()));

    // Check parallelizable groups
    assert_eq!(analysis.parallelizable_groups.len(), 5);
    assert_eq!(analysis.parallelizable_groups[0].len(), 2); // lint, security
    assert_eq!(analysis.parallelizable_groups[1].len(), 2); // build, docs
    assert_eq!(analysis.parallelizable_groups[2].len(), 1); // test
    assert_eq!(analysis.parallelizable_groups[3].len(), 1); // integration
    assert_eq!(analysis.parallelizable_groups[4].len(), 1); // deploy

    Ok(())
}

#[tokio::test]
async fn test_diamond_dependency_pattern() -> Result<()> {
    let yaml = r#"
version: "0.1"
name: "diamond-pattern"

steps:
  # Top of diamond
  setup:
    run: "setup environment"
    
  # Left and right sides of diamond
  build-frontend:
    run: "build frontend"
    needs: ["setup"]
    
  build-backend:
    run: "build backend"  
    needs: ["setup"]
    
  # Bottom of diamond - depends on both sides
  integration:
    run: "integration test"
    needs: ["build-frontend", "build-backend"]
"#;

    let temp_file = create_temp_pipeline(yaml)?;
    let pipeline = Pipeline::load(temp_file.path().to_str().unwrap()).await?;
    let dag = ExecutionDAG::build(&pipeline)?;
    let analysis = dag.analyze();

    // Classic diamond pattern
    assert_eq!(analysis.total_nodes, 4);
    assert_eq!(analysis.max_depth, 2); // 0: setup, 1: builds, 2: integration
    assert!(!analysis.is_linear);

    // One root, one leaf
    assert_eq!(analysis.root_nodes, vec!["setup".to_string()]);
    assert_eq!(analysis.leaf_nodes, vec!["integration".to_string()]);

    // Three execution groups
    assert_eq!(analysis.parallelizable_groups.len(), 3);
    assert_eq!(analysis.parallelizable_groups[0], vec!["setup".to_string()]);
    assert_eq!(analysis.parallelizable_groups[1].len(), 2); // Both builds in parallel
    assert_eq!(
        analysis.parallelizable_groups[2],
        vec!["integration".to_string()]
    );

    // Check that builds can run in parallel
    let parallel_builds = &analysis.parallelizable_groups[1];
    assert!(parallel_builds.contains(&"build-frontend".to_string()));
    assert!(parallel_builds.contains(&"build-backend".to_string()));

    Ok(())
}

#[tokio::test]
async fn test_wide_parallel_pipeline() -> Result<()> {
    let yaml = r#"
version: "0.1"
name: "wide-parallel"

steps:
  # 10 parallel tasks
  task1: { run: "task 1" }
  task2: { run: "task 2" }
  task3: { run: "task 3" }
  task4: { run: "task 4" }
  task5: { run: "task 5" }
  task6: { run: "task 6" }
  task7: { run: "task 7" }
  task8: { run: "task 8" }
  task9: { run: "task 9" }
  task10: { run: "task 10" }
  
  # Final aggregation step
  aggregate:
    run: "aggregate results"
    needs: ["task1", "task2", "task3", "task4", "task5", "task6", "task7", "task8", "task9", "task10"]
"#;

    let temp_file = create_temp_pipeline(yaml)?;
    let pipeline = Pipeline::load(temp_file.path().to_str().unwrap()).await?;
    let dag = ExecutionDAG::build(&pipeline)?;
    let analysis = dag.analyze();

    // Wide but shallow
    assert_eq!(analysis.total_nodes, 11);
    assert_eq!(analysis.max_depth, 1); // 0: all tasks, 1: aggregate
    assert!(!analysis.is_linear);

    // 10 root nodes, 1 leaf
    assert_eq!(analysis.root_nodes.len(), 10);
    assert_eq!(analysis.leaf_nodes, vec!["aggregate".to_string()]);

    // Two execution groups: massive parallel, then single aggregate
    assert_eq!(analysis.parallelizable_groups.len(), 2);
    assert_eq!(analysis.parallelizable_groups[0].len(), 10); // All tasks in parallel
    assert_eq!(
        analysis.parallelizable_groups[1],
        vec!["aggregate".to_string()]
    );

    Ok(())
}

#[tokio::test]
async fn test_toplogical_sort_complex() -> Result<()> {
    let yaml = r#"
version: "0.1"
name: "topo-complex"

steps:
  f:
    run: "f"
    needs: ["d", "e"]
    
  d:
    run: "d"
    needs: ["b"]
    
  e:
    run: "e"
    needs: ["b", "c"]
    
  b:
    run: "b"
    needs: ["a"]
    
  c:
    run: "c" 
    needs: ["a"]
    
  a:
    run: "a"
"#;

    let temp_file = create_temp_pipeline(yaml)?;
    let pipeline = Pipeline::load(temp_file.path().to_str().unwrap()).await?;
    let dag = ExecutionDAG::build(&pipeline)?;
    let sorted = dag.topological_sort()?;

    assert_eq!(sorted.len(), 6);

    // Get positions
    let positions: std::collections::HashMap<&str, usize> = sorted
        .iter()
        .enumerate()
        .map(|(i, name)| (name.as_str(), i))
        .collect();

    // Verify all dependency constraints
    assert!(positions["a"] < positions["b"]);
    assert!(positions["a"] < positions["c"]);
    assert!(positions["b"] < positions["d"]);
    assert!(positions["b"] < positions["e"]);
    assert!(positions["c"] < positions["e"]);
    assert!(positions["d"] < positions["f"]);
    assert!(positions["e"] < positions["f"]);

    // 'a' should be first
    assert_eq!(sorted[0], "a");

    // 'f' should be last
    assert_eq!(sorted[sorted.len() - 1], "f");

    Ok(())
}

#[tokio::test]
async fn test_isolated_components() -> Result<()> {
    let yaml = r#"
version: "0.1"
name: "isolated-components"

steps:
  # Component 1: a -> b -> c
  a:
    run: "component 1 start"
    
  b:
    run: "component 1 middle"
    needs: ["a"]
    
  c:
    run: "component 1 end"
    needs: ["b"]
    
  # Component 2: x -> y (isolated)
  x:
    run: "component 2 start"
    
  y:
    run: "component 2 end"
    needs: ["x"]
    
  # Component 3: standalone
  z:
    run: "standalone task"
"#;

    let temp_file = create_temp_pipeline(yaml)?;
    let pipeline = Pipeline::load(temp_file.path().to_str().unwrap()).await?;
    let dag = ExecutionDAG::build(&pipeline)?;
    let analysis = dag.analyze();

    // Multiple disconnected components
    assert_eq!(analysis.total_nodes, 6);
    assert_eq!(analysis.max_depth, 2); // a->b->c is longest chain
                                       // `is_linear` reflects per-node fan-in/fan-out (no node has more than one
                                       // dependency or dependent), not "single connected chain" - since none of
                                       // these disjoint chains branch, the DAG is still considered linear.
    assert!(analysis.is_linear);

    // Multiple root nodes (no dependencies)
    assert_eq!(analysis.root_nodes.len(), 3);
    assert!(analysis.root_nodes.contains(&"a".to_string()));
    assert!(analysis.root_nodes.contains(&"x".to_string()));
    assert!(analysis.root_nodes.contains(&"z".to_string()));

    // Multiple leaf nodes (no dependents)
    assert_eq!(analysis.leaf_nodes.len(), 3);
    assert!(analysis.leaf_nodes.contains(&"c".to_string()));
    assert!(analysis.leaf_nodes.contains(&"y".to_string()));
    assert!(analysis.leaf_nodes.contains(&"z".to_string()));

    // Should be able to parallelize the three components
    let sorted = dag.topological_sort()?;
    assert_eq!(sorted.len(), 6);

    Ok(())
}

#[tokio::test]
async fn test_dependencies_and_dependents() -> Result<()> {
    let yaml = r#"
version: "0.1"
name: "deps-and-dependents"

steps:
  central:
    run: "central node"
    needs: ["input1", "input2"]
    
  input1:
    run: "input 1"
    
  input2:
    run: "input 2"
    
  output1:
    run: "output 1"
    needs: ["central"]
    
  output2:
    run: "output 2"
    needs: ["central"]
    
  final:
    run: "final step"
    needs: ["output1", "output2"]
"#;

    let temp_file = create_temp_pipeline(yaml)?;
    let pipeline = Pipeline::load(temp_file.path().to_str().unwrap()).await?;
    let dag = ExecutionDAG::build(&pipeline)?;

    // Test get_dependencies
    assert_eq!(dag.get_dependencies("input1").len(), 0);
    assert_eq!(dag.get_dependencies("input2").len(), 0);

    let central_deps = dag.get_dependencies("central");
    assert_eq!(central_deps.len(), 2);
    assert!(central_deps.contains(&"input1".to_string()));
    assert!(central_deps.contains(&"input2".to_string()));

    assert_eq!(dag.get_dependencies("output1"), vec!["central".to_string()]);
    assert_eq!(dag.get_dependencies("output2"), vec!["central".to_string()]);

    let final_deps = dag.get_dependencies("final");
    assert_eq!(final_deps.len(), 2);
    assert!(final_deps.contains(&"output1".to_string()));
    assert!(final_deps.contains(&"output2".to_string()));

    // Test get_dependents
    assert_eq!(dag.get_dependents("input1"), vec!["central".to_string()]);
    assert_eq!(dag.get_dependents("input2"), vec!["central".to_string()]);

    let central_dependents = dag.get_dependents("central");
    assert_eq!(central_dependents.len(), 2);
    assert!(central_dependents.contains(&"output1".to_string()));
    assert!(central_dependents.contains(&"output2".to_string()));

    assert_eq!(dag.get_dependents("output1"), vec!["final".to_string()]);
    assert_eq!(dag.get_dependents("output2"), vec!["final".to_string()]);
    assert_eq!(dag.get_dependents("final").len(), 0);

    Ok(())
}

#[tokio::test]
async fn test_cycle_path_building() -> Result<()> {
    let yaml = r#"
version: "0.1"  
name: "cycle-path-test"

steps:
  a:
    run: "step a"
    needs: ["c"]
    
  b:
    run: "step b"
    needs: ["a"]
    
  c:
    run: "step c"
    needs: ["b"]
"#;

    let temp_file = create_temp_pipeline(yaml)?;
    let result = Pipeline::load(temp_file.path().to_str().unwrap()).await;

    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("Cycle detected"));

    // Should show the complete cycle path
    assert!(error_msg.contains("->"));

    // The cycle should involve all three nodes
    assert!(error_msg.contains("a") && error_msg.contains("b") && error_msg.contains("c"));

    Ok(())
}

#[tokio::test]
async fn test_self_loop_cycle() -> Result<()> {
    let yaml = r#"
version: "0.1"
name: "self-loop"

steps:
  selfish:
    run: "self referencing step"
    needs: ["selfish"]
"#;

    let temp_file = create_temp_pipeline(yaml)?;
    let result = Pipeline::load(temp_file.path().to_str().unwrap()).await;

    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("Cycle detected"));

    Ok(())
}

#[tokio::test]
async fn test_large_dag_performance() -> Result<()> {
    // Generate a large DAG programmatically
    let mut yaml_content = String::from(
        r#"
version: "0.1"
name: "large-dag-performance"

steps:
"#,
    );

    // Create 100 steps in a fan-out, fan-in pattern
    // 1 root -> 98 parallel steps -> 1 final aggregator

    yaml_content.push_str("  root:\n    run: \"root step\"\n\n");

    for i in 1..99 {
        yaml_content.push_str(&format!(
            "  parallel_{}:\n    run: \"parallel step {}\"\n    needs: [\"root\"]\n\n",
            i, i
        ));
    }

    yaml_content.push_str("  final:\n    run: \"final step\"\n    needs: [");
    for i in 1..99 {
        if i > 1 {
            yaml_content.push_str(", ");
        }
        yaml_content.push_str(&format!("\"parallel_{}\"", i));
    }
    yaml_content.push_str("]\n");

    let temp_file = create_temp_pipeline(&yaml_content)?;
    let start_time = std::time::Instant::now();

    let pipeline = Pipeline::load(temp_file.path().to_str().unwrap()).await?;
    let dag = ExecutionDAG::build(&pipeline)?;
    let analysis = dag.analyze();

    let elapsed = start_time.elapsed();

    // Should complete quickly even for large DAGs
    assert!(
        elapsed.as_millis() < 1000,
        "Large DAG analysis took too long: {:?}",
        elapsed
    );

    // Verify structure
    assert_eq!(analysis.total_nodes, 100);
    assert_eq!(analysis.max_depth, 2); // root -> parallel -> final
    assert_eq!(analysis.root_nodes, vec!["root".to_string()]);
    assert_eq!(analysis.leaf_nodes, vec!["final".to_string()]);

    // Should detect the massive parallelization opportunity
    assert_eq!(analysis.parallelizable_groups.len(), 3);
    assert_eq!(analysis.parallelizable_groups[0], vec!["root".to_string()]);
    assert_eq!(analysis.parallelizable_groups[1].len(), 98); // All parallel steps
    assert_eq!(analysis.parallelizable_groups[2], vec!["final".to_string()]);

    println!("Large DAG analysis completed in {:?}", elapsed);

    Ok(())
}

#[tokio::test]
async fn test_node_depths() -> Result<()> {
    let yaml = r#"
version: "0.1"
name: "node-depths"

steps:
  level0:
    run: "level 0"
    
  level1a:
    run: "level 1a"
    needs: ["level0"]
    
  level1b:
    run: "level 1b"
    needs: ["level0"]
    
  level2:
    run: "level 2"
    needs: ["level1a", "level1b"]
    
  level3:
    run: "level 3"
    needs: ["level2"]
"#;

    let temp_file = create_temp_pipeline(yaml)?;
    let pipeline = Pipeline::load(temp_file.path().to_str().unwrap()).await?;
    let dag = ExecutionDAG::build(&pipeline)?;
    let analysis = dag.analyze();

    // Check node depths
    assert_eq!(*analysis.node_depths.get("level0").unwrap(), 0);
    assert_eq!(*analysis.node_depths.get("level1a").unwrap(), 1);
    assert_eq!(*analysis.node_depths.get("level1b").unwrap(), 1);
    assert_eq!(*analysis.node_depths.get("level2").unwrap(), 2);
    assert_eq!(*analysis.node_depths.get("level3").unwrap(), 3);

    assert_eq!(analysis.max_depth, 3);

    Ok(())
}
