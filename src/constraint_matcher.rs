use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct FunctionCandidate {
    pub id: i64,
    pub address: u64,
    pub name: String,
    pub exe_name: String,
    pub guid: String,
    pub constraints: HashSet<String>,
}

#[derive(Debug, Clone)]
pub struct MatchResult {
    pub candidate: FunctionCandidate,
    pub confidence: f64,
    pub matching_constraints: usize,
    pub total_constraints: usize,
}

/// Trait for different solver implementations
pub trait ConstraintSolver: Send + Sync {
    /// Find unique function match given query constraints
    fn solve(
        &self,
        query_constraints: &HashSet<String>,
        candidates: &[FunctionCandidate],
        debug: bool,
    ) -> Option<MatchResult>;

    /// Get solver name for logging
    fn name(&self) -> &str;
}

/// SAT-based constraint solver
pub struct SATConstraintSolver {
    debug_enabled: bool,
}

impl SATConstraintSolver {
    pub fn new(debug_enabled: bool) -> Self {
        Self { debug_enabled }
    }

    /// Generate all non-empty subsets of a set
    fn powerset(items: &HashSet<String>) -> Vec<HashSet<String>> {
        let items_vec: Vec<_> = items.iter().cloned().collect();
        let n = items_vec.len();
        let mut result = Vec::new();

        // Generate all subsets except empty set
        for i in 1..(1 << n) {
            let mut subset = HashSet::new();
            for j in 0..n {
                if i & (1 << j) != 0 {
                    subset.insert(items_vec[j].clone());
                }
            }
            result.push(subset);
        }
        result
    }

    fn log_debug(&self, debug: bool, msg: &str) {
        if debug && self.debug_enabled {
            eprintln!("[SAT Solver] {msg}");
        }
    }
}

impl ConstraintSolver for SATConstraintSolver {
    fn solve(
        &self,
        query_constraints: &HashSet<String>,
        candidates: &[FunctionCandidate],
        debug: bool,
    ) -> Option<MatchResult> {
        self.log_debug(
            debug,
            &format!(
                "Starting SAT solver with {} query constraints and {} candidates",
                query_constraints.len(),
                candidates.len()
            ),
        );

        // Build constraint table
        let mut constraint_table: HashMap<String, HashSet<String>> = HashMap::new();
        for candidate in candidates {
            constraint_table.insert(
                format!("{}_{}", candidate.id, candidate.name),
                candidate.constraints.clone(),
            );
        }

        let names: Vec<String> = constraint_table.keys().cloned().collect();
        let mut valid_candidates = Vec::new();

        for (idx, candidate_key) in names.iter().enumerate() {
            let mut satisfies_criterion = true;

            self.log_debug(
                debug,
                &format!(
                    "Checking candidate {}/{}: {}",
                    idx + 1,
                    names.len(),
                    candidate_key
                ),
            );

            for subset in Self::powerset(query_constraints) {
                // Find all names that contain this subset
                let matching_names: Vec<_> = names
                    .iter()
                    .filter(|name| subset.is_subset(&constraint_table[*name]))
                    .collect();

                // If this subset uniquely identifies someone
                if matching_names.len() == 1 {
                    let unique_match = &matching_names[0];
                    // If it's not our candidate, then candidate can't be the answer
                    if unique_match != &candidate_key {
                        self.log_debug(
                            debug,
                            &format!(
                                "  Subset {subset:?} uniquely identifies {unique_match} (not current candidate)"
                            ),
                        );
                        satisfies_criterion = false;
                        break;
                    }
                }
            }

            if satisfies_criterion {
                self.log_debug(
                    debug,
                    &format!("  Candidate {candidate_key} satisfies matching criterion"),
                );
                valid_candidates.push(candidate_key);
            }
        }

        // Return the unique candidate if exactly one exists
        if valid_candidates.len() == 1 {
            let winner_key = valid_candidates[0];
            self.log_debug(debug, &format!("Found unique match: {winner_key}"));

            // Find the corresponding candidate
            for candidate in candidates {
                let key = format!("{}_{}", candidate.id, candidate.name);
                if key == *winner_key {
                    let matching = query_constraints
                        .intersection(&candidate.constraints)
                        .count();

                    return Some(MatchResult {
                        candidate: candidate.clone(),
                        confidence: 1.0, // Perfect match per SAT criteria
                        matching_constraints: matching,
                        total_constraints: candidate.constraints.len(),
                    });
                }
            }
        } else {
            self.log_debug(
                debug,
                &format!(
                    "No unique match found ({} valid candidates)",
                    valid_candidates.len()
                ),
            );
        }

        None
    }

    fn name(&self) -> &str {
        "SAT Constraint Solver"
    }
}

/// Naive solver that simply counts matching constraints
pub struct NaiveConstraintSolver {
    debug_enabled: bool,
    min_lead_margin: f64, // Minimum margin to be considered clearly better
}

impl NaiveConstraintSolver {
    pub fn new(debug_enabled: bool) -> Self {
        Self {
            debug_enabled,
            min_lead_margin: 0.2, // Default: must have 20% more matches than second best
        }
    }

    pub fn with_margin(debug_enabled: bool, min_lead_margin: f64) -> Self {
        Self {
            debug_enabled,
            min_lead_margin,
        }
    }

    fn log_debug(&self, debug: bool, msg: &str) {
        if debug && self.debug_enabled {
            eprintln!("[Naive Solver] {msg}");
        }
    }
}

impl ConstraintSolver for NaiveConstraintSolver {
    fn solve(
        &self,
        query_constraints: &HashSet<String>,
        candidates: &[FunctionCandidate],
        debug: bool,
    ) -> Option<MatchResult> {
        self.log_debug(
            debug,
            &format!(
                "Starting naive solver with {} query constraints and {} candidates",
                query_constraints.len(),
                candidates.len()
            ),
        );

        if candidates.is_empty() || query_constraints.is_empty() {
            return None;
        }

        // Count matching constraints for each candidate
        let mut match_counts: Vec<(usize, &FunctionCandidate)> = candidates
            .iter()
            .map(|candidate| {
                let matching = query_constraints
                    .intersection(&candidate.constraints)
                    .count();
                (matching, candidate)
            })
            .collect();

        // Sort by match count descending
        match_counts.sort_by(|a, b| b.0.cmp(&a.0));

        let best_count = match_counts[0].0;
        let best_candidate = match_counts[0].1;

        self.log_debug(
            debug,
            &format!(
                "Best candidate: {} ({}) with {} matches",
                best_candidate.name, best_candidate.id, best_count
            ),
        );

        // Check if there's a clear winner
        if match_counts.len() > 1 {
            let second_best_count = match_counts[1].0;
            let second_best = match_counts[1].1;

            self.log_debug(
                debug,
                &format!(
                    "Second best: {} ({}) with {} matches",
                    second_best.name, second_best.id, second_best_count
                ),
            );

            // Calculate margin
            let margin = if second_best_count > 0 {
                (best_count as f64 - second_best_count as f64) / second_best_count as f64
            } else if best_count > 0 {
                f64::INFINITY
            } else {
                0.0
            };

            self.log_debug(
                debug,
                &format!(
                    "Margin: {:.2} (requires >= {:.2})",
                    margin, self.min_lead_margin
                ),
            );

            // Must have significantly more matches than second place
            if margin < self.min_lead_margin {
                self.log_debug(debug, "No clear winner - margin too small");
                return None;
            }
        }

        // Must match at least one constraint
        if best_count == 0 {
            self.log_debug(debug, "No matches found");
            return None;
        }

        // Calculate confidence as percentage of query constraints matched
        let confidence = best_count as f64 / query_constraints.len() as f64;

        self.log_debug(
            debug,
            &format!(
                "Winner: {} with confidence {:.3}",
                best_candidate.name, confidence
            ),
        );

        Some(MatchResult {
            candidate: best_candidate.clone(),
            confidence,
            matching_constraints: best_count,
            total_constraints: best_candidate.constraints.len(),
        })
    }

    fn name(&self) -> &str {
        "Naive Constraint Solver"
    }
}

/// Simple heuristic solver as an alternative
pub struct HeuristicConstraintSolver {
    debug_enabled: bool,
}

impl HeuristicConstraintSolver {
    pub fn new(debug_enabled: bool) -> Self {
        Self { debug_enabled }
    }

    fn log_debug(&self, debug: bool, msg: &str) {
        if debug && self.debug_enabled {
            eprintln!("[Heuristic Solver] {msg}");
        }
    }
}

impl ConstraintSolver for HeuristicConstraintSolver {
    fn solve(
        &self,
        query_constraints: &HashSet<String>,
        candidates: &[FunctionCandidate],
        debug: bool,
    ) -> Option<MatchResult> {
        self.log_debug(
            debug,
            &format!(
                "Starting heuristic solver with {} query constraints and {} candidates",
                query_constraints.len(),
                candidates.len()
            ),
        );

        let mut best_match: Option<MatchResult> = None;
        let mut best_score = 0.0;

        for candidate in candidates {
            let matching = query_constraints
                .intersection(&candidate.constraints)
                .count();

            let total_union = query_constraints.union(&candidate.constraints).count();

            // Jaccard similarity
            let score = if total_union > 0 {
                matching as f64 / total_union as f64
            } else {
                0.0
            };

            self.log_debug(
                debug,
                &format!(
                    "Candidate {} ({}): {} matching constraints, score = {:.3}",
                    candidate.id, candidate.name, matching, score
                ),
            );

            if score > best_score {
                best_score = score;
                best_match = Some(MatchResult {
                    candidate: candidate.clone(),
                    confidence: score,
                    matching_constraints: matching,
                    total_constraints: candidate.constraints.len(),
                });
            }
        }

        // Only return if we have a reasonably good match
        if best_score >= 0.5 {
            if let Some(ref result) = best_match {
                self.log_debug(
                    debug,
                    &format!(
                        "Best match: {} with score {:.3}",
                        result.candidate.name, result.confidence
                    ),
                );
            }
            best_match
        } else {
            self.log_debug(debug, "No match with sufficient confidence");
            None
        }
    }

    fn name(&self) -> &str {
        "Heuristic Constraint Solver"
    }
}

/// Manager for constraint-based function matching
pub struct ConstraintMatcher {
    solver: Box<dyn ConstraintSolver>,
    debug_enabled: bool,
}

impl ConstraintMatcher {
    pub fn new(solver: Box<dyn ConstraintSolver>, debug_enabled: bool) -> Self {
        Self {
            solver,
            debug_enabled,
        }
    }

    pub fn with_sat_solver(debug_enabled: bool) -> Self {
        Self::new(
            Box::new(SATConstraintSolver::new(debug_enabled)),
            debug_enabled,
        )
    }

    pub fn with_heuristic_solver(debug_enabled: bool) -> Self {
        Self::new(
            Box::new(HeuristicConstraintSolver::new(debug_enabled)),
            debug_enabled,
        )
    }

    pub fn with_naive_solver(debug_enabled: bool) -> Self {
        Self::new(
            Box::new(NaiveConstraintSolver::new(debug_enabled)),
            debug_enabled,
        )
    }

    pub fn with_naive_solver_margin(debug_enabled: bool, min_lead_margin: f64) -> Self {
        Self::new(
            Box::new(NaiveConstraintSolver::with_margin(
                debug_enabled,
                min_lead_margin,
            )),
            debug_enabled,
        )
    }

    /// Match function using constraints
    pub fn match_function(
        &self,
        query_constraints: &HashSet<String>,
        candidates: &[FunctionCandidate],
        debug: bool,
    ) -> Option<MatchResult> {
        if self.debug_enabled || debug {
            eprintln!("[ConstraintMatcher] Using solver: {}", self.solver.name());
        }

        self.solver
            .solve(query_constraints, candidates, debug || self.debug_enabled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_candidates() -> Vec<FunctionCandidate> {
        vec![
            FunctionCandidate {
                id: 1,
                address: 0x1000,
                name: "Alice".to_string(),
                exe_name: "test.exe".to_string(),
                guid: "guid1".to_string(),
                constraints: ["A", "B", "C"].iter().map(|s| s.to_string()).collect(),
            },
            FunctionCandidate {
                id: 2,
                address: 0x2000,
                name: "Bob".to_string(),
                exe_name: "test.exe".to_string(),
                guid: "guid2".to_string(),
                constraints: ["A", "D"].iter().map(|s| s.to_string()).collect(),
            },
            FunctionCandidate {
                id: 3,
                address: 0x3000,
                name: "Carol".to_string(),
                exe_name: "test.exe".to_string(),
                guid: "guid3".to_string(),
                constraints: ["B", "C", "E"].iter().map(|s| s.to_string()).collect(),
            },
        ]
    }

    #[test]
    fn test_sat_solver() {
        let solver = SATConstraintSolver::new(true);
        let candidates = create_test_candidates();

        // Test case 1: Query that uniquely identifies Alice
        let query1: HashSet<String> = ["A", "C"].iter().map(|s| s.to_string()).collect();
        let result1 = solver.solve(&query1, &candidates, true);
        assert!(result1.is_some());
        assert_eq!(result1.unwrap().candidate.name, "Alice");

        // Test case 2: Query that uniquely identifies Bob
        let query2: HashSet<String> = ["A", "D"].iter().map(|s| s.to_string()).collect();
        let result2 = solver.solve(&query2, &candidates, true);
        assert!(result2.is_some());
        assert_eq!(result2.unwrap().candidate.name, "Bob");

        // Test case 3: Query that uniquely identifies Carol
        let query3: HashSet<String> = ["E"].iter().map(|s| s.to_string()).collect();
        let result3 = solver.solve(&query3, &candidates, true);
        assert!(result3.is_some());
        assert_eq!(result3.unwrap().candidate.name, "Carol");

        // Test case 4: Ambiguous query
        let query4: HashSet<String> = ["B"].iter().map(|s| s.to_string()).collect();
        let result4 = solver.solve(&query4, &candidates, true);
        assert!(result4.is_none()); // Both Alice and Carol have B
    }

    #[test]
    fn test_naive_solver() {
        let solver = NaiveConstraintSolver::new(true);
        let candidates = create_test_candidates();

        // Test clear winner - Alice has 3 matches, others have 0 or 1
        let query1: HashSet<String> = ["A", "B", "C"].iter().map(|s| s.to_string()).collect();
        let result1 = solver.solve(&query1, &candidates, true);
        assert!(result1.is_some());
        assert_eq!(result1.unwrap().candidate.name, "Alice");

        // Test no clear winner - Alice and Carol both have 2 matches
        let query2: HashSet<String> = ["B", "C", "D"].iter().map(|s| s.to_string()).collect();
        let result2 = solver.solve(&query2, &candidates, true);
        assert!(result2.is_none()); // No clear winner

        // Test with custom margin
        let solver_low_margin = NaiveConstraintSolver::with_margin(true, 0.0);
        let result3 = solver_low_margin.solve(&query2, &candidates, true);
        assert!(result3.is_some()); // With 0 margin, any winner is acceptable

        // Test single match is clear winner
        let query4: HashSet<String> = ["E"].iter().map(|s| s.to_string()).collect();
        let result4 = solver.solve(&query4, &candidates, true);
        assert!(result4.is_some());
        assert_eq!(result4.unwrap().candidate.name, "Carol");
    }

    #[test]
    fn test_heuristic_solver() {
        let solver = HeuristicConstraintSolver::new(true);
        let candidates = create_test_candidates();

        // Test exact match
        let query1: HashSet<String> = ["A", "B", "C"].iter().map(|s| s.to_string()).collect();
        let result1 = solver.solve(&query1, &candidates, true);
        assert!(result1.is_some());
        assert_eq!(result1.unwrap().candidate.name, "Alice");

        // Test partial match
        let query2: HashSet<String> = ["A", "D", "X"].iter().map(|s| s.to_string()).collect();
        let result2 = solver.solve(&query2, &candidates, true);
        assert!(result2.is_some());
        assert_eq!(result2.unwrap().candidate.name, "Bob");
    }
}
