//! What the judge is allowed to see.
//!
//! Deliberately narrow. The request goes to a third-party API, so anything shown to it is a
//! potential leak: the body is excluded entirely (it is exactly where a credential or
//! proprietary content would be), and header *values* are excluded for the same reason — only
//! their names travel, matching the same boundary the CEL `rules` layer already enforces for
//! the same reason.

#[derive(Debug, Clone)]
pub struct JudgeRequest {
    pub method: String,
    pub host: String,
    pub path: String,
    /// Names only, sorted. Never values.
    pub header_names: Vec<String>,
}

impl JudgeRequest {
    /// A cache key. The path is used verbatim rather than templated (e.g. collapsing
    /// `/repos/x/y/123` to `/repos/x/y/{id}`) — simpler, and conservative: it costs cache hit
    /// rate on paths that vary by id, never correctness.
    pub fn cache_key(&self) -> String {
        format!("{} {} {} [{}]", self.method, self.host, self.path, self.header_names.join(","))
    }
}
