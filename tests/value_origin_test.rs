use vouch::syntax::{CallArguments, Cmd, ValueOrigin};

#[test]
fn command_origins_default_unknown_and_remain_structural() {
    let cmd = Cmd::default();
    assert_eq!(cmd.receiver_origin, ValueOrigin::Unknown);

    let origin = ValueOrigin::Call {
        head: "python:module.load".to_string(),
        receiver: Some(Box::new(ValueOrigin::Aggregate(vec![
            ValueOrigin::Literal,
            ValueOrigin::Unknown,
        ]))),
        arguments: CallArguments {
            positional: 2,
            keywords: vec!["hook".to_string()],
            starred: false,
            keyword_unpack: true,
        },
    };

    assert_eq!(origin.clone(), origin);
}
