//! Native status interpretation through the production parser interface.

use rea_core::linux_proc::status::{ParseError, effective_uid};

#[test]
fn selects_effective_uid_and_validates_the_entire_record() {
    assert_eq!(
        effective_uid("Name:\tworker\nUid:\t1000\t1001\t1002\t1003\nGid:\t20\n"),
        Ok(1001)
    );
    assert_eq!(effective_uid("Uid: 0 0000 0 0\r\n"), Ok(0));
    assert_eq!(
        effective_uid("Uid:\u{feff}0\u{a0}9007199254740991 0 0"),
        Ok(9_007_199_254_740_991)
    );
    assert_eq!(effective_uid(" Uid: 0 1 2 3\nUid: 4 5 6 7"), Ok(5));
    assert_eq!(
        effective_uid("Uid: 0 0 0 0\nName: other\nUid: 0 0 0 0"),
        Err(ParseError::DuplicateUid)
    );
    assert_eq!(
        effective_uid("Uid: 0 1 2 3\nUid: broken"),
        Err(ParseError::DuplicateUid)
    );
}

#[test]
fn malformed_uid_rows_remain_unknown_not_zero_or_foreign() {
    for input in ["", "Name: worker\n", " Uid: 0 1 2 3", "uid: 0 1 2 3"] {
        assert_eq!(
            effective_uid(input),
            Err(ParseError::MissingUid),
            "{input:?}"
        );
    }
    for input in [
        "Uid:",
        "Uid:0 1 2 3",
        "Uid: 0 1 2",
        "Uid: 0 1 2 3 4",
        "Uid:\u{85}0 1 2 3",
    ] {
        assert_eq!(
            effective_uid(input),
            Err(ParseError::InvalidUid),
            "{input:?}"
        );
    }
    for index in 0..4 {
        for invalid in [
            "-1",
            "+1",
            "1.5",
            "1e3",
            "9007199254740992",
            "184467440737095516160",
        ] {
            let mut fields = ["0", "1", "2", "3"];
            fields[index] = invalid;
            assert_eq!(
                effective_uid(&format!("Uid: {}", fields.join(" "))),
                Err(ParseError::InvalidUid)
            );
        }
    }
}
