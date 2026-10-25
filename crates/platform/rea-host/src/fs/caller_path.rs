//! POSIX caller spelling, independent of filesystem canonical lookup identity.
use std::io;

#[cfg(unix)]
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

#[cfg(windows)]
pub fn absolute(original: &str) -> io::Result<String> {
    let path = std::path::Path::new(original);
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    absolute
        .into_os_string()
        .into_string()
        .map_err(|_| io::Error::other("path is not valid Unicode"))
}
