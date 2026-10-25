use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use tokio::sync::watch;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct DrainParticipant(u64);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Snapshot {
    pub generation: u64,
    pub ready: bool,
    pub drained_generation: u64,
    pub pending_drains: usize,
}

#[derive(Default)]
struct GateState {
    next_id: u64,
    active: HashSet<DrainParticipant>,
    pending: HashSet<DrainParticipant>,
    snapshot: Snapshot,
    revoked: bool,
}

#[derive(Clone)]
pub(crate) struct XdsSessionGate {
    snapshot: watch::Sender<Snapshot>,
    state: Arc<Mutex<GateState>>,
}

impl XdsSessionGate {
    pub fn new() -> Self {
        let (snapshot, _) = watch::channel(Snapshot::default());
        Self {
            snapshot,
            state: Arc::new(Mutex::new(GateState::default())),
        }
    }

    pub fn subscribe(&self) -> watch::Receiver<Snapshot> {
        self.snapshot.subscribe()
    }

    pub fn snapshot(&self) -> Snapshot {
        self.state.lock().expect("xDS session state").snapshot
    }

    pub(crate) fn is_revoked(&self) -> bool {
        self.state.lock().expect("xDS session state").revoked
    }
    pub fn is_open(&self) -> bool {
        self.open_generation().is_some()
    }

    /// Return the generation only while the complete snapshot and all proxy
    /// drains are current. Callers bind protected requests to this value so a
    /// request built from an older cache cannot be admitted after reconnect.
    pub fn open_generation(&self) -> Option<u64> {
        let state = self.state.lock().expect("xDS session state");
        (state.snapshot.ready
            && state.snapshot.drained_generation >= state.snapshot.generation
            && state.snapshot.pending_drains == 0
            && !state.revoked)
            .then_some(state.snapshot.generation)
    }

    /// Register one proxy's inbound connection manager as a drain participant.
    /// A participant joining an already established session must drain its own
    /// manager before that session can be used by any proxy.
    pub fn register_drain_participant(&self) -> DrainParticipant {
        let mut state = self.state.lock().expect("xDS session state");
        state.next_id = state
            .next_id
            .checked_add(1)
            .expect("xDS drain participant id overflow");
        let participant = DrainParticipant(state.next_id);
        state.active.insert(participant);

        let mut snapshot = state.snapshot;
        if snapshot.generation > 0 {
            state.pending.insert(participant);
            snapshot.pending_drains = state.pending.len();
        }
        self.publish(&mut state, snapshot);
        participant
    }

    /// Remove a watcher only after its connection manager has been drained.
    pub fn unregister_drain_participant(&self, participant: DrainParticipant) {
        let mut state = self.state.lock().expect("xDS session state");
        state.active.remove(&participant);
        state.pending.remove(&participant);
        let mut snapshot = state.snapshot;
        snapshot.pending_drains = state.pending.len();
        if snapshot.generation > 0 && state.pending.is_empty() {
            snapshot.drained_generation = snapshot.generation;
        }
        self.publish(&mut state, snapshot);
    }

    pub fn begin_session(&self) -> u64 {
        let mut state = self.state.lock().expect("xDS session state");
        let current = state.snapshot;
        let generation = current
            .generation
            .checked_add(1)
            .expect("xDS session generation overflow");
        state.pending = state.active.clone();
        state.revoked = false;
        let snapshot = Snapshot {
            generation,
            ready: false,
            drained_generation: if state.pending.is_empty() {
                generation
            } else {
                current.drained_generation.min(generation - 1)
            },
            pending_drains: state.pending.len(),
        };
        self.publish(&mut state, snapshot);
        generation
    }

    pub fn mark_snapshot_ready(&self, generation: u64) {
        let mut state = self.state.lock().expect("xDS session state");
        let mut snapshot = state.snapshot;
        if snapshot.generation != generation || state.revoked {
            return;
        }
        snapshot.ready = true;
        self.publish(&mut state, snapshot);
    }

    pub fn mark_stale(&self, generation: u64) {
        let mut state = self.state.lock().expect("xDS session state");
        let mut snapshot = state.snapshot;
        if snapshot.generation != generation || state.revoked {
            return;
        }
        snapshot.ready = false;
        state.revoked = true;
        state.pending = state.active.clone();
        snapshot.pending_drains = state.pending.len();
        if state.pending.is_empty() {
            snapshot.drained_generation = generation;
        } else {
            snapshot.drained_generation = generation.saturating_sub(1);
        }
        self.publish(&mut state, snapshot);
    }

    pub fn needs_drain(&self, generation: u64, participant: DrainParticipant) -> bool {
        let state = self.state.lock().expect("xDS session state");
        state.snapshot.generation == generation && state.pending.contains(&participant)
    }

    pub fn mark_drained(&self, generation: u64, participant: DrainParticipant) {
        let mut state = self.state.lock().expect("xDS session state");
        let mut snapshot = state.snapshot;
        if snapshot.generation != generation || !state.active.contains(&participant) {
            return;
        }
        state.pending.remove(&participant);
        snapshot.pending_drains = state.pending.len();
        if state.pending.is_empty() {
            snapshot.drained_generation = generation;
        }
        self.publish(&mut state, snapshot);
    }

    fn publish(&self, state: &mut GateState, snapshot: Snapshot) {
        state.snapshot = snapshot;
        self.snapshot.send_replace(snapshot);
    }
}

#[cfg(test)]
mod tests {
    use super::XdsSessionGate;

    #[test]
    fn every_proxy_manager_must_drain_before_gate_opens() {
        let gate = XdsSessionGate::new();
        let first = gate.register_drain_participant();
        let second = gate.register_drain_participant();

        let first_generation = gate.begin_session();
        gate.mark_snapshot_ready(first_generation);
        gate.mark_drained(first_generation, first);
        assert!(!gate.is_open(), "the second manager still has old streams");
        assert_eq!(gate.snapshot().pending_drains, 1);
        gate.mark_drained(first_generation, second);
        assert!(gate.is_open());

        let second_generation = gate.begin_session();
        gate.mark_snapshot_ready(second_generation);
        gate.mark_drained(first_generation, first);
        assert!(
            !gate.is_open(),
            "a stale generation cannot complete a drain"
        );
        gate.mark_drained(second_generation, first);
        assert!(!gate.is_open(), "the second manager still has old streams");
        gate.mark_drained(second_generation, second);
        assert!(gate.is_open());

        gate.mark_stale(second_generation);
        assert!(
            !gate.is_open(),
            "a stale xDS session always closes admission"
        );
    }

    #[test]
    fn participant_joining_an_open_session_must_drain_before_admission() {
        let gate = XdsSessionGate::new();
        let generation = gate.begin_session();
        gate.mark_snapshot_ready(generation);
        assert!(gate.is_open());

        let participant = gate.register_drain_participant();
        assert!(!gate.is_open());
        assert!(gate.needs_drain(generation, participant));
        gate.mark_drained(generation, participant);
        assert!(gate.is_open());
    }

    #[test]
    fn late_snapshot_completion_cannot_resurrect_a_revoked_generation() {
        let gate = XdsSessionGate::new();
        let participant = gate.register_drain_participant();
        let generation = gate.begin_session();
        gate.mark_snapshot_ready(generation);
        gate.mark_drained(generation, participant);
        assert!(gate.is_open());

        gate.mark_stale(generation);
        gate.mark_snapshot_ready(generation);
        gate.mark_drained(generation, participant);
        assert!(!gate.is_open());
        assert!(!gate.snapshot().ready);

        let next_generation = gate.begin_session();
        gate.mark_snapshot_ready(next_generation);
        assert!(!gate.is_open());
        gate.mark_drained(next_generation, participant);
        assert!(gate.is_open());
    }
}
