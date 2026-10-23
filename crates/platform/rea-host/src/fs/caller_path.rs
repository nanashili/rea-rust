//! POSIX caller spelling, independent of filesystem canonical lookup identity.
use std::io;

pub fn absolute(original: &str) -> io::Result<String> {
    let absolute = if original.starts_with('/') {
        original.to_owned()
    } else {
        format!(
            "{}/{original}",
            std::env::current_dir()?
                .to_str()
                .ok_or_else(|| io::Error::other("cwd is not Unicode"))?
        )
    };
    let parts = absolute
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect::<Vec<_>>();
    let directory = (absolute.ends_with('/') || absolute.ends_with("/.")) && !parts.is_empty();
    Ok(format!(
        "/{}{}",
        parts.join("/"),
        if directory { "/" } else { "" }
    ))
}
