//! Compatibility and malformed-record checks at the public parser interface.

use rea_core::linux_proc::stat::{Lifecycle, ParseError, ProcessStat, parse};

// Native fields 3 through 22. Expected facts below are independent of the parser.
fn record(state: &str, flags: &str, start_time: &str) -> String {
    format!(
        "42 (worker ) old (name)\n) {state} 17 18 19 0 0 {flags} 0 0 0 0 0 0 0 0 0 0 0 0 {start_time}"
    )
}

#[test]
fn retains_exact_identity_and_relations_across_ambiguous_command_text() {
    let input = record("S", "0", "000184467440737095516160");
    assert_eq!(
        parse(&input),
        Ok(ProcessStat {
            pid: 42,
            start_time: "000184467440737095516160",
            lifecycle: Some(Lifecycle::NonZombie),
            parent_pid: 17,
            process_group_id: 18,
            session_id: 19,
        })
    );
    let input = input.replace("17 18 19", "0 0 0");
    let facts = parse(&input).unwrap();
    assert_eq!(
        (facts.parent_pid, facts.process_group_id, facts.session_id),
        (0, 0, 0)
    );
}

#[test]
fn terminal_state_precedes_flags_and_exiting_is_not_dead() {
    for (state, expected) in [
        ("Z", Lifecycle::Zombie),
        ("X", Lifecycle::Dead),
        ("x", Lifecycle::Dead),
    ] {
        assert_eq!(
            parse(&record(state, "invalid", "1")).unwrap().lifecycle,
            Some(expected)
        );
    }
    for state in ["R", "S", "D", "Q"] {
        for (flags, expected) in [
            ("4194316", Lifecycle::Exiting),
            ("4194312", Lifecycle::NonZombie),
        ] {
            assert_eq!(
                parse(&record(state, flags, "1")).unwrap().lifecycle,
                Some(expected)
            );
        }
    }
    for flags in [
        "invalid",
        "-1",
        "4.1",
        "+4",
        "9007199254740992",
        "184467440737095516160",
    ] {
        let input = record("S", flags, "001");
        assert_eq!(
            parse(&input),
            Ok(ProcessStat {
                pid: 42,
                start_time: "001",
                lifecycle: None,
                parent_pid: 17,
                process_group_id: 18,
                session_id: 19,
            })
        );
    }
}

#[test]
fn rejects_missing_malformed_and_out_of_range_identity_fields() {
    for input in ["", "42 worker)", "42 (worker", "(worker) S", "42 )worker("] {
        assert!(parse(input).is_err(), "{input:?}");
    }
    let valid = record("S", "0", "1");
    for pid in [
        "0",
        "-1",
        "+42",
        "4.2",
        "9007199254740992",
        "184467440737095516160",
    ] {
        assert_eq!(parse(&valid.replacen("42", pid, 1)), Err(ParseError::Pid));
    }
    for state in ["??", "12", "é"] {
        assert_eq!(
            parse(&record(state, "0", "1")),
            Err(ParseError::InvalidField(3))
        );
    }
    for (old, field) in [("17", 4), ("18", 5), ("19", 6)] {
        for invalid in ["-1", "1.5", "9007199254740992"] {
            assert_eq!(
                parse(&valid.replacen(old, invalid, 1)),
                Err(ParseError::InvalidField(field))
            );
        }
    }
    for start in ["-1", "1e3", "+1", "NaN"] {
        assert_eq!(
            parse(&record("S", "0", start)),
            Err(ParseError::InvalidField(22))
        );
    }
    assert_eq!(
        parse(&record("S", "0", "")),
        Err(ParseError::MissingField(22))
    );
    // Every truncated prefix is rejected, rather than borrowing a different field.
    for (offset, _) in valid
        .match_indices(' ')
        .filter(|(offset, _)| *offset > valid.rfind(')').unwrap())
    {
        assert!(parse(&valid[..offset]).is_err());
    }
}

#[test]
fn preserves_existing_numeric_and_whitespace_compatibility() {
    let input = record("S", "4294967300", "001").replacen("42", "0009007199254740991", 1);
    assert_eq!(parse(&input).unwrap().pid, 9_007_199_254_740_991);
    assert_eq!(parse(&input).unwrap().lifecycle, Some(Lifecycle::Exiting));
    for separator in ["\t", "\r\n", "\u{feff}", "\u{a0}", "\u{2028}"] {
        let separated = input.replace(' ', separator);
        assert_eq!(parse(&separated), parse(&input));
    }
    assert!(parse(&input.replace(' ', "\u{85}")).is_err());
    let extended = format!("{input} 999 888 777\n");
    assert_eq!(parse(&extended), parse(&input));
}
