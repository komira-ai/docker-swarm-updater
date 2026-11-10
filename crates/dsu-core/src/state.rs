//! The per-service state file (`services/<name>.json`, docs/design.md section 3.6): the
//! failed list, the converged digests, what the updater pushed, the signed-time floor and the
//! pre-update Swarm snapshot a restart needs.

use std::collections::BTreeSet;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::ids::{DeployId, Digest};
use crate::swarm::Snapshot;

/// One converged release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvergedEntry {
    /// The manifest digest that converged.
    pub digest: Digest,
    /// The bundle's verified signing time.
    pub signed_time: Timestamp,
    /// The deploy that converged it.
    pub deploy: DeployId,
}

/// The Swarm snapshot of a deploy whose update was asked for (section 3.5 step 1), kept so a
/// restart can tell this update's `UpdateStatus` from an earlier one's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    /// The deploy waiting on Swarm.
    pub deploy: DeployId,
    /// The service's `Version.Index` before the update.
    pub version_index: u64,
    /// When the service was read.
    pub read_at: Timestamp,
}

impl Pending {
    /// The snapshot the Swarm rule compares an `UpdateStatus` with.
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            version_index: self.version_index,
            read_at: self.read_at,
        }
    }
}

/// The state file of one service.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceState {
    /// Digests refused with `previously_failed` until the operator clears them.
    #[serde(default)]
    pub failed: BTreeSet<Digest>,
    /// Converged releases, oldest first, one entry per digest.
    #[serde(default)]
    pub converged: Vec<ConvergedEntry>,
    /// Manifests the updater itself pushed to the registry (the only ones it deletes).
    #[serde(default)]
    pub pushed: BTreeSet<Digest>,
    /// The signing time of the last converged release.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub floor: Option<Timestamp>,
    /// The deploy waiting on Swarm, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<Pending>,
}

impl ServiceState {
    /// Whether `digest` is in the failed list.
    pub fn is_failed(&self, digest: &Digest) -> bool {
        self.failed.contains(digest)
    }

    /// Adds `digest` to the failed list.
    pub fn add_failed(&mut self, digest: Digest) {
        self.failed.insert(digest);
    }

    /// Removes `digest` from the failed list; false if it was not there.
    pub fn clear_failed(&mut self, digest: &Digest) -> bool {
        self.failed.remove(digest)
    }

    /// Section 3.3 step 5: whether a release signed at `signed_time` is earlier than the last
    /// converged release's.
    pub fn is_older_than_floor(&self, signed_time: Timestamp) -> bool {
        self.floor.is_some_and(|floor| signed_time < floor)
    }

    /// Notes a converged deploy: the digest moves to the end of the converged list and the
    /// floor becomes `signed_time`.
    pub fn record_converged(&mut self, digest: Digest, signed_time: Timestamp, deploy: DeployId) {
        self.converged.retain(|e| e.digest != digest);
        self.converged.push(ConvergedEntry {
            digest,
            signed_time,
            deploy,
        });
        self.floor = Some(signed_time);
    }

    /// The most recently converged release.
    pub fn last_converged(&self) -> Option<&ConvergedEntry> {
        self.converged.last()
    }

    /// The converged digests, oldest first.
    pub fn converged_digests(&self) -> Vec<Digest> {
        self.converged.iter().map(|e| e.digest.clone()).collect()
    }

    /// Notes a manifest the updater pushed.
    pub fn add_pushed(&mut self, digest: Digest) {
        self.pushed.insert(digest);
    }

    /// Forgets manifests that were deleted from the registry.
    pub fn forget_pushed(&mut self, deleted: &[Digest]) {
        self.pushed.retain(|d| !deleted.contains(d));
    }

    /// Keeps the Swarm snapshot of `deploy` for a restart.
    pub fn set_pending(&mut self, deploy: DeployId, snapshot: Snapshot) {
        self.pending = Some(Pending {
            deploy,
            version_index: snapshot.version_index,
            read_at: snapshot.read_at,
        });
    }

    /// Drops the snapshot once the deploy ended.
    pub fn clear_pending(&mut self) {
        self.pending = None;
    }

    /// The snapshot kept for `deploy`, if that deploy is the one pending.
    pub fn pending_for(&self, deploy: &DeployId) -> Option<&Pending> {
        self.pending.as_ref().filter(|p| &p.deploy == deploy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(n: u8) -> Digest {
        Digest::from_sha256([n; 32])
    }

    fn id(c: char) -> DeployId {
        DeployId::parse(&format!("d-{}", c.to_string().repeat(26))).unwrap()
    }

    fn t(secs: i64) -> Timestamp {
        Timestamp::from_second(1_790_000_000 + secs).unwrap()
    }

    #[test]
    fn failed_list() {
        let mut s = ServiceState::default();
        assert!(!s.is_failed(&d(1)));
        s.add_failed(d(1));
        s.add_failed(d(1));
        assert!(s.is_failed(&d(1)));
        assert_eq!(s.failed.len(), 1);
        assert!(s.clear_failed(&d(1)));
        assert!(!s.clear_failed(&d(1)));
        assert!(!s.is_failed(&d(1)));
    }

    #[test]
    fn floor_refuses_only_strictly_earlier_releases() {
        let mut s = ServiceState::default();
        assert!(!s.is_older_than_floor(t(-1000)));
        s.record_converged(d(1), t(10), id('a'));
        assert!(s.is_older_than_floor(t(9)));
        assert!(!s.is_older_than_floor(t(10)));
        assert!(!s.is_older_than_floor(t(11)));
    }

    #[test]
    fn converged_digests_are_unique_and_oldest_first() {
        let mut s = ServiceState::default();
        assert!(s.last_converged().is_none());
        s.record_converged(d(1), t(1), id('a'));
        s.record_converged(d(2), t(2), id('b'));
        s.record_converged(d(1), t(3), id('c'));
        assert_eq!(s.converged_digests(), [d(2), d(1)]);
        let last = s.last_converged().unwrap();
        assert_eq!(
            (last.digest.clone(), last.signed_time, last.deploy.clone()),
            (d(1), t(3), id('c'))
        );
        assert_eq!(s.floor, Some(t(3)));
        s.record_converged(d(3), t(2), id('d'));
        assert_eq!(s.floor, Some(t(2)));
    }

    #[test]
    fn pushed_digests_are_tracked_and_forgotten() {
        let mut s = ServiceState::default();
        s.add_pushed(d(1));
        s.add_pushed(d(2));
        s.add_pushed(d(2));
        s.add_pushed(d(3));
        s.forget_pushed(&[d(2), d(9)]);
        assert_eq!(s.pushed.iter().cloned().collect::<Vec<_>>(), [d(1), d(3)]);
    }

    #[test]
    fn pending_snapshot_belongs_to_one_deploy() {
        let mut s = ServiceState::default();
        assert!(s.pending_for(&id('a')).is_none());
        s.set_pending(
            id('a'),
            Snapshot {
                version_index: 41,
                read_at: t(5),
            },
        );
        let p = s.pending_for(&id('a')).unwrap();
        assert_eq!(
            p.snapshot(),
            Snapshot {
                version_index: 41,
                read_at: t(5)
            }
        );
        assert!(s.pending_for(&id('b')).is_none());
        s.clear_pending();
        assert!(s.pending.is_none());
    }

    #[test]
    fn json_round_trip_and_defaults() {
        let mut s = ServiceState::default();
        assert_eq!(
            serde_json::to_string(&s).unwrap(),
            r#"{"failed":[],"converged":[],"pushed":[]}"#
        );
        assert_eq!(serde_json::from_str::<ServiceState>("{}").unwrap(), s);
        s.add_failed(d(1));
        s.add_pushed(d(2));
        s.record_converged(d(2), t(1), id('a'));
        s.set_pending(
            id('b'),
            Snapshot {
                version_index: 7,
                read_at: t(2),
            },
        );
        let text = serde_json::to_string(&s).unwrap();
        assert!(text.contains("version_index"));
        assert_eq!(serde_json::from_str::<ServiceState>(&text).unwrap(), s);
    }
}
