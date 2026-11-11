//! Which manifests the updater deletes from the registry after a converge
//! (docs/design.md section 3.5 step 4).

use std::collections::BTreeSet;

use crate::ids::Digest;

/// The digests to delete: those the updater pushed (`pushed`) that are not running, not
/// Swarm's `PreviousSpec` image, and not among the `keep_previous` most recent converged
/// digests besides those two. `converged_newest_last` lists converged digests oldest first.
/// The result is in digest order.
pub fn to_delete(
    pushed: &BTreeSet<Digest>,
    running: &BTreeSet<Digest>,
    previous: Option<&Digest>,
    converged_newest_last: &[Digest],
    keep_previous: u32,
) -> Vec<Digest> {
    let always = |d: &Digest| running.contains(d) || previous == Some(d);
    let recent: BTreeSet<&Digest> = converged_newest_last
        .iter()
        .rev()
        .filter(|d| !always(d))
        .take(keep_previous as usize)
        .collect();
    pushed
        .iter()
        .filter(|d| !always(d) && !recent.contains(d))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(n: u8) -> Digest {
        Digest::from_sha256([n; 32])
    }

    fn set(ns: &[u8]) -> BTreeSet<Digest> {
        ns.iter().map(|n| d(*n)).collect()
    }

    #[test]
    fn five_earlier_digests_keep_running_previous_and_the_last_three() {
        // Converged 1..=5 earlier, 6 now running; 5 is Swarm's previous spec.
        let converged: Vec<Digest> = (1..=6).map(d).collect();
        let deleted = to_delete(
            &set(&[1, 2, 3, 4, 5, 6]),
            &set(&[6]),
            Some(&d(5)),
            &converged,
            3,
        );
        assert_eq!(deleted, [d(1)]);
    }

    #[test]
    fn keep_zero_keeps_only_running_and_previous() {
        let converged: Vec<Digest> = (1..=4).map(d).collect();
        let deleted = to_delete(&set(&[1, 2, 3, 4]), &set(&[4]), Some(&d(3)), &converged, 0);
        assert_eq!(deleted, [d(1), d(2)]);
    }

    #[test]
    fn only_pushed_digests_are_ever_deleted() {
        let converged: Vec<Digest> = (1..=4).map(d).collect();
        let deleted = to_delete(&set(&[1]), &set(&[4]), None, &converged, 1);
        assert_eq!(deleted, [d(1)]);
        assert!(to_delete(&set(&[]), &set(&[4]), None, &converged, 1).is_empty());
    }

    #[test]
    fn unconverged_pushed_digests_are_deleted_unless_running_or_previous() {
        let deleted = to_delete(&set(&[7, 8, 9]), &set(&[9]), Some(&d(8)), &[], 3);
        assert_eq!(deleted, [d(7)]);
        let deleted = to_delete(&set(&[7, 8, 9]), &set(&[]), None, &[], 3);
        assert_eq!(deleted, [d(7), d(8), d(9)]);
    }

    #[test]
    fn running_and_previous_do_not_use_up_the_keep_slots() {
        let converged: Vec<Digest> = (1..=5).map(d).collect();
        // 5 running, 4 previous: the three kept besides them are 3, 2 and 1.
        let deleted = to_delete(
            &set(&[1, 2, 3, 4, 5]),
            &set(&[5]),
            Some(&d(4)),
            &converged,
            3,
        );
        assert!(deleted.is_empty());
        let deleted = to_delete(
            &set(&[1, 2, 3, 4, 5]),
            &set(&[5]),
            Some(&d(4)),
            &converged,
            2,
        );
        assert_eq!(deleted, [d(1)]);
    }

    #[test]
    fn several_running_digests_are_all_kept() {
        let converged: Vec<Digest> = (1..=3).map(d).collect();
        let deleted = to_delete(&set(&[1, 2, 3]), &set(&[2, 3]), None, &converged, 0);
        assert_eq!(deleted, [d(1)]);
    }
}
