use anyhow::Result;
use std::collections::{HashMap, HashSet, VecDeque};

use super::Pipeline;

#[derive(Debug)]
pub struct ExecutionDAG {
    pub nodes: Vec<String>,
    pub edges: HashMap<String, Vec<String>>,
}

impl ExecutionDAG {
    pub fn build(pipeline: &Pipeline) -> Result<Self> {
        let mut edges: HashMap<String, Vec<String>> = HashMap::new();

        for step_name in pipeline.steps.keys() {
            edges.insert(step_name.clone(), Vec::new());
        }

        for (step_name, step) in &pipeline.steps {
            if let Some(needs) = &step.needs {
                for dep in needs {
                    if let Some(dep_edges) = edges.get_mut(dep) {
                        dep_edges.push(step_name.clone());
                    } else {
                        return Err(anyhow::anyhow!(
                            "Step '{}' depends on unknown step '{}'",
                            step_name,
                            dep
                        ));
                    }
                }
            }
        }

        let dag = Self {
            nodes: pipeline.steps.keys().cloned().collect(),
            edges,
        };

        dag.check_cycles()?;
        Ok(dag)
    }

    fn check_cycles(&self) -> Result<()> {
        let mut visited = HashSet::new();
        let mut rec_stack = HashSet::new();

        for node in &self.nodes {
            if !visited.contains(node) {
                self.has_cycle_util(node, &mut visited, &mut rec_stack)?;
            }
        }

        Ok(())
    }

    fn has_cycle_util(
        &self,
        node: &str,
        visited: &mut HashSet<String>,
        rec_stack: &mut HashSet<String>,
    ) -> Result<()> {
        if rec_stack.contains(node) {
            let cycle_path = self.build_cycle_path(node, rec_stack);
            anyhow::bail!("Cycle detected in pipeline dependencies: {}", cycle_path);
        }

        if visited.contains(node) {
            return Ok(());
        }

        visited.insert(node.to_string());
        rec_stack.insert(node.to_string());

        if let Some(neighbors) = self.edges.get(node) {
            for neighbor in neighbors {
                self.has_cycle_util(neighbor, visited, rec_stack)?;
            }
        }

        rec_stack.remove(node);
        Ok(())
    }

    fn build_cycle_path(&self, cycle_node: &str, rec_stack: &HashSet<String>) -> String {
        let mut path = Vec::new();
        let mut current = cycle_node;

        // Build the cycle path by following dependencies
        loop {
            path.push(current.to_string());

            // Find the next node in the cycle
            let mut next_node = None;
            if let Some(neighbors) = self.edges.get(current) {
                for neighbor in neighbors {
                    if rec_stack.contains(neighbor) {
                        next_node = Some(neighbor.as_str());
                        break;
                    }
                }
            }

            match next_node {
                Some(next) if next == cycle_node => {
                    path.push(cycle_node.to_string());
                    break;
                }
                Some(next) => current = next,
                None => break,
            }

            // Prevent infinite loops in case of complex cycles
            if path.len() > self.nodes.len() {
                break;
            }
        }

        path.join(" -> ")
    }

    pub fn topological_sort(&self) -> Result<Vec<String>> {
        let mut in_degree: HashMap<String, usize> = HashMap::new();
        let mut reverse_edges: HashMap<String, Vec<String>> = HashMap::new();

        for node in &self.nodes {
            in_degree.insert(node.clone(), 0);
            reverse_edges.insert(node.clone(), Vec::new());
        }

        for (from, to_list) in &self.edges {
            for to in to_list {
                *in_degree
                    .get_mut(to)
                    .expect("`to` is always a pipeline node inserted above") += 1;
                reverse_edges
                    .get_mut(from)
                    .expect("`from` is always a pipeline node inserted above")
                    .push(to.clone());
            }
        }

        let mut queue: VecDeque<String> = in_degree
            .iter()
            .filter(|(_, &degree)| degree == 0)
            .map(|(name, _)| name.clone())
            .collect();

        let mut result = Vec::new();

        while let Some(current) = queue.pop_front() {
            result.push(current.clone());

            if let Some(neighbors) = reverse_edges.get(&current) {
                for neighbor in neighbors {
                    let degree = in_degree
                        .get_mut(neighbor)
                        .expect("`neighbor` is always a pipeline node inserted above");
                    *degree -= 1;
                    if *degree == 0 {
                        queue.push_back(neighbor.clone());
                    }
                }
            }
        }

        if result.len() != self.nodes.len() {
            anyhow::bail!("Pipeline contains cycles");
        }

        Ok(result)
    }

    /// Find all nodes with no dependencies (root nodes)
    pub fn find_root_nodes(&self) -> Vec<String> {
        let mut has_incoming = HashSet::new();

        for neighbors in self.edges.values() {
            for neighbor in neighbors {
                has_incoming.insert(neighbor.clone());
            }
        }

        self.nodes
            .iter()
            .filter(|node| !has_incoming.contains(*node))
            .cloned()
            .collect()
    }

    /// Find all nodes with no dependents (leaf nodes)
    pub fn find_leaf_nodes(&self) -> Vec<String> {
        self.nodes
            .iter()
            .filter(|node| {
                self.edges
                    .get(*node)
                    .map(|neighbors| neighbors.is_empty())
                    .unwrap_or(true)
            })
            .cloned()
            .collect()
    }

    /// Get all direct dependencies of a node
    pub fn get_dependencies(&self, node: &str) -> Vec<String> {
        // Find nodes that this node depends on (reverse of edges)
        let mut dependencies = Vec::new();
        for (from, to_list) in &self.edges {
            if to_list.contains(&node.to_string()) {
                dependencies.push(from.clone());
            }
        }
        dependencies
    }

    /// Get all direct dependents of a node
    pub fn get_dependents(&self, node: &str) -> Vec<String> {
        self.edges.get(node).cloned().unwrap_or_default()
    }

    /// Analyze the DAG structure and provide insights
    pub fn analyze(&self) -> DAGAnalysis {
        let root_nodes = self.find_root_nodes();
        let leaf_nodes = self.find_leaf_nodes();
        let total_nodes = self.nodes.len();

        let mut max_depth = 0;
        let mut node_depths = HashMap::new();

        // Calculate depths using topological sort
        if let Ok(sorted_nodes) = self.topological_sort() {
            for node in sorted_nodes {
                let deps = self.get_dependencies(&node);
                let depth = if deps.is_empty() {
                    0
                } else {
                    deps.iter()
                        .map(|dep| node_depths.get(dep).unwrap_or(&0))
                        .max()
                        .unwrap_or(&0)
                        + 1
                };

                node_depths.insert(node, depth);
                max_depth = max_depth.max(depth);
            }
        }

        DAGAnalysis {
            total_nodes,
            root_nodes,
            leaf_nodes,
            max_depth,
            node_depths,
            is_linear: self.is_linear_pipeline(),
            parallelizable_groups: self.find_parallelizable_groups(),
        }
    }

    /// Check if the pipeline is linear (no parallelization possible)
    fn is_linear_pipeline(&self) -> bool {
        // A pipeline is linear if each node has at most one dependency and one dependent
        for (node, dependents) in &self.edges {
            if dependents.len() > 1 {
                return false;
            }

            let dependencies = self.get_dependencies(node);
            if dependencies.len() > 1 {
                return false;
            }
        }
        true
    }

    /// Find groups of steps that can be executed in parallel
    fn find_parallelizable_groups(&self) -> Vec<Vec<String>> {
        let mut groups = Vec::new();

        if let Ok(sorted_nodes) = self.topological_sort() {
            let mut remaining_nodes: HashSet<String> = sorted_nodes.into_iter().collect();

            while !remaining_nodes.is_empty() {
                let mut current_group = Vec::new();
                let mut to_remove = Vec::new();

                for node in &remaining_nodes {
                    let dependencies = self.get_dependencies(node);

                    // Check if all dependencies are already processed
                    if dependencies
                        .iter()
                        .all(|dep| !remaining_nodes.contains(dep))
                    {
                        current_group.push(node.clone());
                        to_remove.push(node.clone());
                    }
                }

                for node in to_remove {
                    remaining_nodes.remove(&node);
                }

                if !current_group.is_empty() {
                    groups.push(current_group);
                }
            }
        }

        groups
    }
}

#[derive(Debug, Clone)]
pub struct DAGAnalysis {
    pub total_nodes: usize,
    pub root_nodes: Vec<String>,
    pub leaf_nodes: Vec<String>,
    pub max_depth: usize,
    pub node_depths: HashMap<String, usize>,
    pub is_linear: bool,
    pub parallelizable_groups: Vec<Vec<String>>,
}
