//! The WHATWG `URL` surface the resolver uses, backed by Ada (the parser
//! Node.js embeds). `url` 2.5.8 follows older spec text for `file:` URLs: it
//! never pops a trailing drive-letter segment (`file:///x/C:/a/../..` keeps
//! `C:`) and drops the host of `file://host/C:/x`; Node does neither.

/// One parsed URL with the JavaScript `URL` accessors.
#[derive(Clone, Debug)]
pub struct WebUrl(ada_url::Url);

/// `URL.parse(input, base)`.
pub fn parse(input: &str, base: Option<&WebUrl>) -> Option<WebUrl> {
    ada_url::Url::parse(input, base.map(WebUrl::href))
        .ok()
        .map(WebUrl)
}

/// `URL.canParse(input)`.
pub fn can_parse(input: &str) -> bool {
    ada_url::Url::can_parse(input, None)
}

impl WebUrl {
    pub fn href(&self) -> &str {
        self.0.href()
    }
    pub fn pathname(&self) -> &str {
        self.0.pathname()
    }
    pub fn hostname(&self) -> &str {
        self.0.hostname()
    }
    /// Hostname plus `:port` when the port is not the scheme default.
    pub fn host(&self) -> &str {
        self.0.host()
    }
    pub fn protocol(&self) -> &str {
        self.0.protocol()
    }
}
