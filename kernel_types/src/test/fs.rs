use alloc::{string::String, vec::Vec};

use crate::fs::{Components64, FileAttribute, OpenFlags, OpenFlagsMask, Path, Span};

#[test]
fn file_attributes_convert_from_raw_directory_values() {
    let cases = [
        (0x01, FileAttribute::ReadOnly),
        (0x02, FileAttribute::Hidden),
        (0x04, FileAttribute::System),
        (0x08, FileAttribute::VolumeLabel),
        (0x0F, FileAttribute::LFN),
        (0x10, FileAttribute::Directory),
        (0x20, FileAttribute::Archive),
        (0xAA, FileAttribute::Unknown),
    ];

    for (raw, attr) in cases {
        assert_eq!(FileAttribute::try_from(raw), Ok(attr));
        if attr != FileAttribute::Unknown {
            assert_eq!(u8::from(attr), raw);
        }
    }
}

#[test]
fn open_flags_masks_are_const_friendly_and_composable() {
    const READ_CREATE: OpenFlagsMask = OpenFlagsMask::new()
        .with(OpenFlags::ReadOnly)
        .with(OpenFlags::Create);

    assert!(READ_CREATE.contains(OpenFlags::ReadOnly));
    assert!(READ_CREATE.contains(OpenFlags::Create));
    assert!(!READ_CREATE.contains(OpenFlags::WriteOnly));

    let mask = OpenFlags::ReadWrite | OpenFlags::Open | OpenFlags::WriteThrough;
    assert!(mask.contains(OpenFlags::ReadWrite));
    assert!(mask.contains(OpenFlags::Open));
    assert!(mask.contains(OpenFlags::WriteThrough));
}

#[test]
fn path_from_string_normalizes_separators_and_tracks_components() {
    let path = Path::from_string("C:\\alpha//beta\\gamma\\");

    assert_eq!(path.symlink, Some('C'));
    assert_eq!(path.as_str(), "C:/alpha/beta/gamma");
    assert_eq!(path.to_string(), String::from("C:/alpha/beta/gamma"));
    assert_eq!(path.file_name(), Some("gamma"));
    assert_eq!(path.components.len(), 3);

    let spans: Vec<Span> = path.components.into_iter().collect();
    assert_eq!(
        spans,
        alloc::vec![
            Span { start: 3, end: 8 },
            Span { start: 9, end: 13 },
            Span { start: 14, end: 19 },
        ]
    );
}

#[test]
fn path_parse_join_parent_pop_and_symlink_rewrite_work_together() {
    let base = Path::from_string("D:/root/child");

    let joined = Path::parse("E:leaf/file.txt", Some(&base));
    assert_eq!(joined.as_str(), "E:/root/child/leaf/file.txt");
    assert_eq!(joined.parent().unwrap().as_str(), "E:/root/child/leaf");

    let root_relative = Path::parse("/logs/today", Some(&base));
    assert_eq!(root_relative.as_str(), "D:/logs/today");

    let mut mutable = root_relative.with_symlink(Some('Z'));
    assert_eq!(mutable.as_str(), "Z:/logs/today");
    mutable.push("archive");
    assert_eq!(mutable.as_str(), "Z:/logs/today/archive");
    assert_eq!(mutable.pop().as_deref(), Some("archive"));
    assert_eq!(mutable.as_str(), "Z:/logs/today");
}

#[test]
fn path_normalize_removes_dot_segments_without_losing_prefix() {
    let mut path = Path::from_string("C:/a/./b/../c");
    path.normalize();

    assert_eq!(path.as_str(), "C:/a/c");
    assert_eq!(path.file_name(), Some("c"));

    let mut relative = Path::from_string("a/./b/../../c");
    relative.normalize();
    assert_eq!(relative.as_str(), "c");
}

#[test]
fn components_iterator_reports_exact_remaining_length() {
    let mut components = Components64::new();
    assert!(components.is_empty());

    let path = Path::from_string("one/two/three");
    components = path.components;

    let mut iter = components.into_iter();
    assert_eq!(iter.len(), 3);
    assert_eq!(iter.size_hint(), (3, Some(3)));
    assert_eq!(iter.next(), Some(Span { start: 0, end: 3 }));
    assert_eq!(iter.len(), 2);
    assert_eq!(iter.next(), Some(Span { start: 4, end: 7 }));
    assert_eq!(iter.next(), Some(Span { start: 8, end: 13 }));
    assert_eq!(iter.next(), None);
}
