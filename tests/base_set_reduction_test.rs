use vouch::config::Action;
use vouch::engine::{BaseSet, CdState, Place};

#[test]
fn test_base_set_construction_and_invariants() {
    let s1 = CdState::Known("/a".to_string());
    let s2 = CdState::Known("/b".to_string());
    let set = BaseSet::from_states(vec![s1.clone(), s2.clone(), s1.clone()]);
    assert_eq!(set.states.len(), 2);
    assert_eq!(set.states[0], s1);
    assert_eq!(set.states[1], s2);

    let u = CdState::Unknown("gap".to_string());
    let set_with_u = BaseSet::from_states(vec![s1.clone(), u.clone(), s2.clone()]);
    assert_eq!(set_with_u.states.len(), 1);
    assert_eq!(set_with_u.states[0], u);
}

#[test]
fn test_reduce_restriction() {
    let places = vec![
        Place::Proven("/project/safe".to_string()),
        Place::Proven("/tmp/scratch".to_string()),
    ];
    let causes = vec!["safe".to_string(), "scratch".to_string()];

    // Neither is restricted -> None
    let res = BaseSet::reduce_restriction(&places, &causes, |_p, _c| None);
    assert_eq!(res, None);

    // Second candidate is restricted -> fires
    let res = BaseSet::reduce_restriction(&places, &causes, |p, c| match p {
        Place::Proven(d) if d.starts_with("/tmp") => {
            Some((Action::Ask, format!("restricted under /tmp ({c})")))
        }
        _ => None,
    });
    assert_eq!(
        res,
        Some((Action::Ask, "restricted under /tmp (scratch)".to_string()))
    );

    // Unproven candidate triggers restriction
    let unproven_places = vec![Place::Proven("/project/safe".to_string()), Place::Unproven];
    let unproven_causes = vec!["safe".to_string(), "loop gap".to_string()];
    let res = BaseSet::reduce_restriction(&unproven_places, &unproven_causes, |p, c| match p {
        Place::Unproven => Some((Action::Ask, format!("unproven place: {c}"))),
        _ => None,
    });
    assert_eq!(
        res,
        Some((Action::Ask, "unproven place: loop gap".to_string()))
    );
}

#[test]
fn test_reduce_grant() {
    let places = vec![
        Place::Proven("/workspace/a".to_string()),
        Place::Proven("/workspace/b".to_string()),
    ];

    // All candidates match -> returns Some(Vec<T>)
    let res: Option<Vec<String>> = BaseSet::reduce_grant(&places, |p| match p {
        Place::Proven(d) => Some(d.clone()),
        Place::Unproven => None,
    });
    assert_eq!(
        res,
        Some(vec![
            "/workspace/a".to_string(),
            "/workspace/b".to_string(),
        ])
    );

    // One candidate fails -> returns None (all-or-none)
    let mixed_places = vec![
        Place::Proven("/workspace/a".to_string()),
        Place::Proven("/outside/c".to_string()),
    ];
    let res: Option<Vec<String>> = BaseSet::reduce_grant(&mixed_places, |p| match p {
        Place::Proven(d) if d.starts_with("/workspace") => Some(d.clone()),
        _ => None,
    });
    assert_eq!(res, None);

    // Unproven candidate fails grant -> returns None
    let unproven_places = vec![
        Place::Proven("/workspace/a".to_string()),
        Place::Unproven,
    ];
    let res: Option<Vec<String>> = BaseSet::reduce_grant(&unproven_places, |p| match p {
        Place::Proven(d) => Some(d.clone()),
        Place::Unproven => None,
    });
    assert_eq!(res, None);
}

#[test]
fn test_fold_ranked() {
    // Highest rank wins (Deny > Ask > Allow)
    let candidates = vec![
        (Action::Allow, Some("allowed by rule A".to_string())),
        (Action::Ask, Some("asked by rule B".to_string())),
        (Action::Allow, Some("allowed by rule C".to_string())),
    ];
    let folded = BaseSet::fold_ranked(candidates, |(act, sent)| (act, sent));
    assert_eq!(
        folded,
        Some((Action::Ask, vec!["asked by rule B".to_string()]))
    );

    // Equal highest rank collects and dedupes sentences
    let candidates_equal = vec![
        (Action::Ask, Some("override 1".to_string())),
        (Action::Ask, Some("override 2".to_string())),
        (Action::Ask, Some("override 1".to_string())),
    ];
    let folded_equal = BaseSet::fold_ranked(candidates_equal, |(act, sent)| (act, sent));
    assert_eq!(
        folded_equal,
        Some((
            Action::Ask,
            vec!["override 1".to_string(), "override 2".to_string()]
        ))
    );
}
