// Copyright Istio Authors
// SPDX-License-Identifier: Apache-2.0

//! Original-ADD ownership and native task-drain receipt correlation. No state
//! here survives a proxy execution. A new process cannot prove an old drain.
use super::netns::NetnsID;
use super::{
    WorkloadUid,
    istio::zds::{DrainWorkload, WorkloadBinding, WorkloadDrained},
};
use std::collections::HashMap;

const MAX_OWNERS: usize = 4096;
#[derive(Clone)]
struct Owner {
    binding: WorkloadBinding,
    generation: u64,
    completed: bool,
}
#[derive(Default)]
pub(super) struct DrainOwners {
    owners: HashMap<WorkloadUid, Owner>,
}
fn canonical_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| (33..=126).contains(&b))
}
pub(super) fn validate_binding(
    b: &WorkloadBinding,
    epoch: &[u8],
    uid: &WorkloadUid,
    netns: NetnsID,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        b.version == 1
            && canonical_id(&b.source_epoch)
            && canonical_id(&b.namespace_uid)
            && canonical_id(&b.pod_uid),
        "invalid ADD binding identifiers"
    );
    anyhow::ensure!(
        b.endpoint_id > 0
            && b.endpoint_id <= 65535
            && b.incarnation > 0
            && b.capture_generation > 0
            && b.netns_ino > 0,
        "invalid ADD binding generation or cookie"
    );
    anyhow::ensure!(
        b.proxy_epoch.len() == 32 && b.proxy_epoch == epoch && b.pod_uid == uid.0,
        "ADD belongs to another workload or proxy execution"
    );
    anyhow::ensure!(
        b.netns_dev == netns.dev && b.netns_ino == netns.inode,
        "ADD binding does not match actual SCM_RIGHTS FD"
    );
    Ok(())
}
impl DrainOwners {
    pub(super) fn contains(&self, uid: &WorkloadUid) -> bool {
        self.owners.contains_key(uid)
    }
    pub(super) fn check_add(&self, uid: &WorkloadUid, b: &WorkloadBinding) -> anyhow::Result<()> {
        if let Some(old) = self.owners.get(uid) {
            if old.completed {
                anyhow::ensure!(
                    old.binding != *b
                        && (old.binding.source_epoch != b.source_epoch
                            || old.binding.incarnation != b.incarnation),
                    "completed incarnation cannot be revived"
                );
            } else {
                let mut refreshed = old.binding.clone();
                refreshed.capture_generation = b.capture_generation;
                anyhow::ensure!(
                    old.generation == 0
                        && refreshed == *b
                        && b.capture_generation >= old.binding.capture_generation,
                    "old workload must complete its exact drain before replacement"
                );
            }
        } else {
            anyhow::ensure!(
                self.owners.len() < MAX_OWNERS,
                "original ADD ownership capacity exhausted"
            );
        }
        anyhow::ensure!(
            !self.owners.iter().any(|(other, owner)| other != uid
                && !owner.completed
                && owner.binding.netns_dev == b.netns_dev
                && owner.binding.netns_ino == b.netns_ino),
            "sandbox already belongs to another workload"
        );
        Ok(())
    }
    pub(super) fn installed(&mut self, uid: WorkloadUid, binding: WorkloadBinding) {
        self.owners.insert(
            uid,
            Owner {
                binding,
                generation: 0,
                completed: false,
            },
        );
    }
    pub(super) fn begin(
        &mut self,
        req: &DrainWorkload,
        epoch: &[u8],
    ) -> anyhow::Result<WorkloadUid> {
        let b = req
            .binding
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing original ADD binding"))?;
        anyhow::ensure!(
            req.nonce.len() == 32
                && req.drain_generation > 0
                && b.proxy_epoch.len() == 32
                && b.proxy_epoch == epoch,
            "invalid drain nonce/generation/proxy execution"
        );
        let uid = WorkloadUid::new(b.pod_uid.clone());
        let owner = self
            .owners
            .get_mut(&uid)
            .ok_or_else(|| anyhow::anyhow!("original proxy execution has no such ADD owner"))?;
        anyhow::ensure!(
            owner.binding == *b,
            "drain refers to another ADD incarnation"
        );
        anyhow::ensure!(
            owner.generation == 0 || owner.generation == req.drain_generation,
            "drain generation changed"
        );
        owner.generation = req.drain_generation;
        Ok(uid)
    }
    pub(super) fn complete(&mut self, req: &DrainWorkload) -> anyhow::Result<WorkloadDrained> {
        let b = req
            .binding
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing ADD binding"))?;
        let owner = self
            .owners
            .get_mut(&WorkloadUid::new(b.pod_uid.clone()))
            .ok_or_else(|| anyhow::anyhow!("missing ADD owner"))?;
        anyhow::ensure!(
            owner.binding == *b && owner.generation == req.drain_generation,
            "drain owner changed during task barrier"
        );
        owner.completed = true;
        Ok(WorkloadDrained {
            binding: Some(b.clone()),
            drain_generation: req.drain_generation,
            nonce: req.nonce.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn binding() -> WorkloadBinding {
        WorkloadBinding {
            version: 1,
            source_epoch: "source-epoch".into(),
            cluster_id: 1,
            namespace_uid: "namespace-uid".into(),
            pod_uid: "pod-uid".into(),
            endpoint_id: 17,
            incarnation: 1,
            capture_generation: 7,
            netns_dev: 1,
            netns_ino: 2,
            proxy_epoch: vec![3; 32],
        }
    }
    fn request() -> DrainWorkload {
        DrainWorkload {
            binding: Some(binding()),
            drain_generation: 9,
            nonce: vec![4; 32],
        }
    }
    #[test]
    fn actual_fd_cookie_and_execution_must_match() {
        let b = binding();
        let uid = WorkloadUid::new(b.pod_uid.clone());
        validate_binding(&b, &[3; 32], &uid, NetnsID { dev: 1, inode: 2 }).unwrap();
        assert!(validate_binding(&b, &[8; 32], &uid, NetnsID { dev: 1, inode: 2 }).is_err());
        assert!(validate_binding(&b, &[3; 32], &uid, NetnsID { dev: 1, inode: 3 }).is_err());
    }
    #[test]
    fn original_binding_and_generation_cannot_be_replaced_by_retry() {
        let b = binding();
        let uid = WorkloadUid::new(b.pod_uid.clone());
        let mut owners = DrainOwners::default();
        owners.installed(uid.clone(), b.clone());
        let req = request();
        owners.begin(&req, &[3; 32]).unwrap();
        let mut wrong = req.clone();
        wrong.binding.as_mut().unwrap().namespace_uid = "replacement".into();
        assert!(owners.begin(&wrong, &[3; 32]).is_err());
        wrong = req.clone();
        wrong.drain_generation += 1;
        assert!(owners.begin(&wrong, &[3; 32]).is_err());
        assert!(owners.check_add(&uid, &b).is_err());
        let receipt = owners.complete(&req).unwrap();
        assert_eq!(receipt.nonce, req.nonce);
        assert!(owners.check_add(&uid, &b).is_err());
        let mut next = b;
        next.incarnation += 1;
        assert!(owners.check_add(&uid, &next).is_ok());
        let mut retry = req.clone();
        retry.nonce = vec![5; 32];
        owners.begin(&retry, &[3; 32]).unwrap();
        assert_eq!(owners.complete(&retry).unwrap().nonce, retry.nonce);
        assert!(DrainOwners::default().begin(&req, &[3; 32]).is_err()); // restarted proxy, no old-owner proof
        assert!(owners.begin(&req, &[8; 32]).is_err());
    }
    #[test]
    fn capacity_preserves_completed_owner_and_fails_closed_without_eviction() {
        let mut owners = DrainOwners::default();
        for index in 0..MAX_OWNERS {
            let mut b = binding();
            b.pod_uid = format!("pod-{index}");
            b.netns_ino = 2 + index as u64;
            let uid = WorkloadUid::new(b.pod_uid.clone());
            owners.check_add(&uid, &b).unwrap();
            owners.installed(uid, b);
        }
        let mut b = binding();
        b.pod_uid = "pod-0".into();
        let req = DrainWorkload {
            binding: Some(b.clone()),
            drain_generation: 9,
            nonce: vec![4; 32],
        };
        owners.begin(&req, &[3; 32]).unwrap();
        owners.complete(&req).unwrap();
        let mut extra = binding();
        extra.pod_uid = "overflow-pod".into();
        extra.netns_ino = 999999;
        assert!(
            owners
                .check_add(&WorkloadUid::new(extra.pod_uid.clone()), &extra)
                .is_err()
        );
        assert_eq!(owners.owners.len(), MAX_OWNERS);
        // Completed owners still carry exact old-generation proof; pressure
        // cannot evict them and then manufacture a new same-incarnation ADD.
        owners.begin(&req, &[3; 32]).unwrap();
        assert!(
            owners
                .check_add(&WorkloadUid::new(b.pod_uid.clone()), &b)
                .is_err()
        );
        // A live known owner can still refresh its capture generation at the cap.
        let mut live = binding();
        live.pod_uid = "pod-1".into();
        live.netns_ino = 3;
        live.capture_generation += 1;
        assert!(
            owners
                .check_add(&WorkloadUid::new(live.pod_uid.clone()), &live)
                .is_ok()
        );
    }
}
