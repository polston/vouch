use vouch::config::load;
use vouch::engine::decide_command_in;
use vouch::protocol::Decision;

const HOME: &str = "C:/Users/dev";

fn decide(source: &str) -> Decision {
    let config = load(
        "version = 1\n[lang.bash]\ndefault = \"allow\"\n[lang.bash.constructs]\nunmodeled_command = \"allow\"\n\
         [lang.python]\ndefault = \"allow\"\n[lang.python.constructs]\nunmodeled_command = \"ask\"\n\
         [write]\ndefault = \"ask\"\nallow_paths = [\"C:/work/**\"]\n",
    )
    .expect("config parses");
    let command = format!("python -c \"{source}\"");
    decide_command_in(&config, "bash", &command, Some(HOME), None)
}

fn assert_allow(source: &str) {
    match decide(source) {
        Decision::Allow(_) => {}
        other => panic!("expected Allow for {source}, got {other:?}"),
    }
}

fn assert_unmodeled_ask(source: &str) {
    match decide(source) {
        Decision::Ask(reason) => assert!(reason.contains("unmodeled_command"), "{reason}"),
        other => panic!("expected unmodeled Ask for {source}, got {other:?}"),
    }
}

#[test]
fn identical_branch_origins_survive_but_ambiguous_or_one_sided_origins_do_not() {
    assert_allow(
        "import json\nif condition:\n    value = json.loads('{}')\nelse:\n    value = json.loads('{}')\nprint(value.get('name'))",
    );
    assert_unmodeled_ask(
        "import json\nif condition:\n    value = json.loads('{}')\nelse:\n    value = custom()\nprint(value.get('name'))",
    );
    assert_unmodeled_ask(
        "import json\nif condition:\n    value = json.loads('{}')\nprint(value.get('name'))",
    );
}

#[test]
fn a_function_parameter_shadows_an_outer_known_value() {
    assert_unmodeled_ask(
        "import json\nvalue = json.loads('{}')\ndef read(value):\n    return value.get('name')",
    );
}

#[test]
fn deferred_bodies_do_not_borrow_outer_value_provenance() {
    assert_unmodeled_ask(
        "import json\nvalue = json.loads('{}')\ndef read():\n    return value.get('name')\nvalue = external",
    );
    assert_unmodeled_ask(
        "import json\nvalue = json.loads('{}')\nreader = lambda: value.get('name')\nvalue = external",
    );
    assert_unmodeled_ask(
        "import json\nvalue = json.loads('{}')\nreader = (value.get('name') for item in items)\nvalue = external",
    );
    assert_allow("import json\ndef read():\n    value = json.loads('{}')\n    return value.get('name')");
    assert_allow("import json\ndef read():\n    return json.loads('{}').get('name')");
}

#[test]
fn an_uncurated_call_result_never_mints_data() {
    assert_unmodeled_ask("value = custom_source()\nprint(value.get('name'))");
}

#[test]
fn literal_destructuring_and_iteration_propagate_data_inside_their_suites() {
    assert_allow(
        "import json\nleft, right = (json.loads('{}'), json.loads('{}'))\nprint(left.get('x'), right.get('y'))",
    );
    assert_allow("import json\nfor item in json.loads('[{}]'):\n    print(item.get('name'))");
}

#[test]
fn a_method_call_invalidates_a_named_receiver_after_that_call() {
    assert_unmodeled_ask(
        "import json\nvalue = json.loads('{}')\nvalue.get('first')\nprint(value.get('second'))",
    );
}

#[test]
fn assigning_through_a_known_receiver_invalidates_its_origin() {
    assert_unmodeled_ask(
        "import json\nvalue = json.loads('{}')\nvalue['name'] = external\nprint(value.get('name').strip())",
    );
}

#[test]
fn mutation_invalidates_every_name_that_may_alias_the_receiver() {
    assert_unmodeled_ask(
        "import json\nsource = json.loads('{}')\nalias = source\nalias['name'] = external\nprint(source.get('name').strip())",
    );
}

#[test]
fn mutation_of_a_derived_member_invalidates_its_source_container() {
    assert_unmodeled_ask(
        "import json\nsource = json.loads('{\"items\": []}')\nitems = source['items']\nitems.append(external)\nfor item in source.get('items'):\n    print(item.get('name'))",
    );
}

#[test]
fn direct_nested_and_comprehension_member_mutation_invalidate_their_sources() {
    assert_unmodeled_ask(
        "import json\nsource = json.loads('{\"items\": []}')\nsource['items'].append(external)\nprint(source.get('items'))",
    );
    assert_unmodeled_ask(
        "import json\nsource = json.loads('{\"items\": [[]]}')\nprint([(item.append(external), source.get('items')) for item in source['items']])",
    );
}

#[test]
fn calling_a_bound_method_alias_invalidates_its_source_receiver() {
    assert_unmodeled_ask(
        "import json\nsource = json.loads('{}')\nmethod = source.get\nmethod('first')\nprint(source.get('second'))",
    );
}

#[test]
fn an_inner_call_invalidates_the_enclosing_receiver_before_invocation() {
    assert_unmodeled_ask(
        "import json\nsource = json.loads('{}')\nprint(source.get(source.get('key')))",
    );
    assert_unmodeled_ask(
        "import json\nsource = json.loads('{}')\nmethod = source.get\nprint(method(source.get('key')))",
    );
}

#[test]
fn invalidating_one_receiver_preserves_an_independent_value() {
    assert_allow(
        "import json\nleft = json.loads('{}')\nright = json.loads('{}')\nleft.get('first')\nprint(right.get('second'))",
    );
}

#[test]
fn an_alias_from_a_parameter_remains_rebound() {
    match decide("def invoke(parameter):\n    alias = parameter\n    return alias('x')") {
        Decision::Ask(reason) => assert!(reason.contains("rebound_name"), "{reason}"),
        other => panic!("parameter alias should retain rebound refusal, got {other:?}"),
    }
}

#[test]
fn exception_and_match_branches_do_not_leak_one_paths_origin() {
    assert_unmodeled_ask(
        "import json\ntry:\n    value = json.loads('{}')\nexcept Exception:\n    value = custom()\nprint(value.get('name'))",
    );
    assert_unmodeled_ask(
        "import json\nmatch subject:\n    case 1:\n        value = json.loads('{}')\n    case _:\n        value = custom()\nprint(value.get('name'))",
    );
    assert_unmodeled_ask(
        "import json\ntry:\n    value = custom()\nexcept Exception:\n    value = json.loads('{}')\nprint(value.get('name'))",
    );
    assert_unmodeled_ask(
        "import json\nmatch subject:\n    case 1:\n        value = custom()\n    case _:\n        value = json.loads('{}')\nprint(value.get('name'))",
    );
}

#[test]
fn a_try_prefix_rebinding_does_not_leak_the_old_origin_into_a_handler() {
    assert_unmodeled_ask(
        "import json\nvalue = json.loads('{}')\ntry:\n    value = external\n    raise RuntimeError\nexcept RuntimeError:\n    print(value.get('name'))",
    );
}

#[test]
fn a_finally_body_includes_exceptional_prefix_states() {
    assert_unmodeled_ask(
        "import json\nvalue = json.loads('{}')\ntry:\n    value = external\n    raise RuntimeError\n    value = json.loads('{}')\nfinally:\n    print(value.get('name'))",
    );
}

#[test]
fn comprehension_targets_shadow_outer_known_values() {
    assert_unmodeled_ask(
        "import json\nitem = json.loads('{}')\nprint([item.get('name') for item in external])",
    );
}

#[test]
fn a_loop_target_does_not_escape_a_loop_that_may_not_run() {
    assert_unmodeled_ask(
        "import json\nfor item in json.loads('[{}]'):\n    pass\nprint(item.get('name'))",
    );
}

#[test]
fn loop_bodies_do_not_reuse_a_fact_mutated_by_an_earlier_iteration() {
    assert_unmodeled_ask(
        "import json\nvalue = json.loads('{}')\nwhile condition:\n    print(value.get('name'))\n    value = external",
    );
    assert_unmodeled_ask(
        "import json\nvalue = json.loads('{}')\nfor item in items:\n    print(value.get('name'))\n    value = external",
    );
}

#[test]
fn comprehension_outputs_do_not_reuse_a_fact_mutated_by_an_earlier_item() {
    assert_unmodeled_ask(
        "import json\nvalue = json.loads('{}')\nprint([(value.get('name'), (value := external)) for item in items])",
    );
}
