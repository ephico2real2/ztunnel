// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::telemetry;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tracing::info;
mod server;
pub use server::*;

/// Ready tracks whether the process is ready.
#[derive(Default)]
struct ReadinessState {
    tasks: HashSet<String>,
    checks: HashMap<String, Arc<dyn Fn() -> bool + Send + Sync>>,
}
#[derive(Clone, Default)]
pub struct Ready(Arc<Mutex<ReadinessState>>);
impl std::fmt::Debug for Ready {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Ready").field(&self.pending()).finish()
    }
}

impl Ready {
    pub fn new() -> Ready {
        Ready(Default::default())
    }

    /// register_task allows a caller to add a dependency to be marked "ready".
    pub fn register_task(&self, name: &str) -> BlockReady {
        self.0.lock().unwrap().tasks.insert(name.to_string());
        BlockReady {
            parent: self.to_owned(),
            name: name.to_string(),
        }
    }

    /// Dynamic checks run on each readiness request. They cannot grant traffic
    /// admission and must not perform I/O or acquire a checkpoint-store lock.
    pub fn register_dynamic(
        &self,
        name: &str,
        check: impl Fn() -> bool + Send + Sync + 'static,
    ) -> anyhow::Result<()> {
        let mut state = self.0.lock().unwrap();
        anyhow::ensure!(
            !state.tasks.contains(name) && !state.checks.contains_key(name),
            "duplicate readiness dependency"
        );
        state.checks.insert(name.to_string(), Arc::new(check));
        Ok(())
    }
    pub fn pending(&self) -> HashSet<String> {
        let (mut pending, checks) = {
            let state = self.0.lock().unwrap();
            (state.tasks.clone(), state.checks.clone())
        };
        // Never hold the readiness registry lock while invoking a component.
        for (name, check) in checks {
            if !check() {
                pending.insert(name);
            }
        }
        pending
    }
}

/// BlockReady blocks readiness until it is dropped.
pub struct BlockReady {
    parent: Ready,
    name: String,
}

impl BlockReady {
    pub fn subtask(&self, name: &str) -> BlockReady {
        self.parent.register_task(name)
    }
}

impl Drop for BlockReady {
    fn drop(&mut self) {
        let removed = self.parent.0.lock().unwrap().tasks.remove(&self.name);
        debug_assert!(removed); // It is a bug to somehow remove something twice
        let left = self.parent.pending().len();
        let dur = telemetry::APPLICATION_START_TIME.elapsed();
        if left == 0 {
            info!(
                "Task '{}' complete ({dur:?}), marking server ready",
                self.name
            );
        } else {
            info!(
                "Task '{}' complete ({dur:?}), still awaiting {left} tasks",
                self.name
            );
        }
    }
}

#[cfg(test)]
mod dynamic_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    #[test]
    fn live_dependency_tracks_failure_recovery_and_refuses_duplicate_names() {
        let ready = Ready::new();
        let live = Arc::new(AtomicBool::new(false));
        let observed = live.clone();
        ready
            .register_dynamic("native issuer profile", move || {
                observed.load(Ordering::Acquire)
            })
            .unwrap();
        assert!(ready.pending().contains("native issuer profile"));
        live.store(true, Ordering::Release);
        assert!(ready.pending().is_empty());
        live.store(false, Ordering::Release);
        assert!(ready.pending().contains("native issuer profile"));
        assert!(
            ready
                .register_dynamic("native issuer profile", || true)
                .is_err()
        );
        let block = ready.register_task("initial");
        assert!(ready.pending().contains("initial"));
        drop(block);
        assert!(!ready.pending().contains("initial"));
        assert!(ready.pending().contains("native issuer profile"));
    }
}
