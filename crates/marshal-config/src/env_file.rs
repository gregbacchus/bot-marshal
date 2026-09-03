//! The `.env` file: `KEY=value` lines read at startup and installed as
//! [`marshal_core::env`]'s overlay, so a `{ type: env, var: ... }` secret source can be fed
//! from a file next to the config rather than from whatever exported the variable.
//!
//! This is deliberately a *small* dialect rather than a bug-compatible clone of any
//! particular shell or dotenv library. The values here are credentials, and every convenience
//! feature of the larger dialects is a way to silently mangle one: inline `#` comments would
//! truncate a password containing a hash, `${VAR}` interpolation would rewrite a secret that
//! happens to contain `$`, and unquoted backslash escapes would eat one. So: no interpolation,
//! no inline comments, no unquoted escapes, and anything ambiguous is an error naming the
//! line rather than a guess.
//!
//! Parsing is separate from applying, and nothing here touches the environment at all — this
//! module reads a file and returns pairs. What is done with them, and why the process
//! environment is left alone, is `marshal_core::env`'s business.

use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum EnvFileError {
    // The source is not interpolated into any of these: callers print with anyhow's `{:#}`,
    // which appends the chain itself, and a doubled "No such file or directory" reads like a
    // bug in the tool.
    #[error("reading env file {path}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "`env_file: {named}` names {path}, which does not exist. Create it, or drop the \
         `env_file:` key to fall back to an optional `.env` beside the config."
    )]
    Missing { path: PathBuf, named: String },

    #[error("{path}:{line}: {message}")]
    Syntax { path: PathBuf, line: usize, message: String },
}

/// Which file to load, if any — `env_file:` in the config.
///
/// Absent means [`DEFAULT_ENV_FILE`] *if it exists*; a named path must exist, because someone
/// who typed it is depending on it and a missing file would otherwise surface much later as
/// "environment variable `X` is not set" from whichever swap needed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Requested {
    /// Load `path` if present, silently skip it if not.
    IfPresent(PathBuf),
    /// Load `path`, and fail if it is missing. `named` is what the config actually said, kept
    /// so the error can quote the key rather than only the resolved path.
    Required { path: PathBuf, named: String },
    /// `env_file: false` — load nothing.
    Disabled,
}

pub const DEFAULT_ENV_FILE: &str = ".env";

/// Resolve `env_file:` against the base config file's own directory, the same way
/// `profiles_path` and friends resolve — the env file belongs to the config that names it,
/// not to whatever directory the operator happened to be standing in.
pub fn requested(config_path: &Path, setting: Option<&crate::model::EnvFileSetting>) -> Requested {
    use crate::model::EnvFileSetting;
    let dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    match setting {
        None => Requested::IfPresent(crate::resolve_dir(dir, DEFAULT_ENV_FILE)),
        Some(EnvFileSetting::Enabled(true)) => {
            Requested::IfPresent(crate::resolve_dir(dir, DEFAULT_ENV_FILE))
        }
        Some(EnvFileSetting::Enabled(false)) => Requested::Disabled,
        Some(EnvFileSetting::Path(p)) => {
            Requested::Required { path: crate::resolve_dir(dir, p), named: p.clone() }
        }
    }
}

/// What the config at `config_path` asks for, read from that file alone.
///
/// A full [`crate::load`] cannot serve here: applying the env file has to happen before
/// anything else in the process (see the binary's `load_env_file`), while loading properly is
/// each subcommand's own job a moment later. So this reads the base document and looks at one
/// key, ignoring every other field.
///
/// An unreadable or unparseable config yields [`Requested::Disabled`] rather than an error:
/// the caller is about to load it for real and report the problem with the position and
/// context this cannot give, and there is nothing useful to apply an env file *to* in the
/// meantime.
pub fn requested_for(config_path: &Path) -> Requested {
    #[derive(serde::Deserialize)]
    struct JustEnvFile {
        #[serde(default)]
        env_file: Option<crate::model::EnvFileSetting>,
    }

    let Ok(text) = std::fs::read_to_string(config_path) else {
        return Requested::Disabled;
    };
    match serde_yaml_ng::from_str::<JustEnvFile>(&text) {
        Ok(base) => requested(config_path, base.env_file.as_ref()),
        Err(_) => Requested::Disabled,
    }
}

/// The file that was read, and its assignments in file order.
pub type Loaded = (PathBuf, Vec<(String, String)>);

/// Read and parse the requested file. `Ok(None)` means there was nothing to load — either
/// `env_file: false`, or the default `.env` is simply not there.
pub fn read(requested: &Requested) -> Result<Option<Loaded>, EnvFileError> {
    let (path, named) = match requested {
        Requested::Disabled => return Ok(None),
        Requested::IfPresent(p) => (p, None),
        Requested::Required { path, named } => (path, Some(named)),
    };

    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => match named {
            // Named explicitly and absent: say what to do about it, rather than handing back
            // an ENOENT for a path whose origin the operator then has to work out.
            Some(named) => {
                return Err(EnvFileError::Missing { named: named.clone(), path: path.clone() });
            }
            None => return Ok(None),
        },
        Err(source) => return Err(EnvFileError::Io { path: path.clone(), source }),
    };

    Ok(Some((path.clone(), parse(path, &text)?)))
}

/// Parse `.env` text into ordered `(key, value)` pairs.
///
/// The dialect, in full:
///
/// * blank lines, and lines whose first non-blank character is `#`, are ignored;
/// * `KEY=value`, optionally prefixed `export `;
/// * keys match `[A-Za-z_][A-Za-z0-9_]*`;
/// * an unquoted value is taken verbatim after trimming surrounding whitespace — a `#` in it
///   is part of the value, not the start of a comment;
/// * `'single quoted'` is literal, with no escapes at all;
/// * `"double quoted"` understands `\n`, `\r`, `\t`, `\\` and `\"`, and nothing else;
/// * a quoted value ends on its closing quote and must be the last thing on the line.
///
/// A later line wins over an earlier one with the same key — the last assignment is the one a
/// reader of the file would expect to take effect.
pub fn parse(path: &Path, text: &str) -> Result<Vec<(String, String)>, EnvFileError> {
    let err = |line: usize, message: &str| EnvFileError::Syntax {
        path: path.to_path_buf(),
        line,
        message: message.to_owned(),
    };

    let mut out: Vec<(String, String)> = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = i + 1;
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let assignment = trimmed.strip_prefix("export ").unwrap_or(trimmed).trim_start();
        let Some((key, value)) = assignment.split_once('=') else {
            return Err(err(line, "expected KEY=value"));
        };

        let key = key.trim_end();
        if key.is_empty() {
            return Err(err(line, "empty variable name"));
        }
        if !key.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(err(
                line,
                &format!(
                    "`{key}` is not a usable variable name — expected letters, digits and \
                     underscores, not starting with a digit"
                ),
            ));
        }

        let value = parse_value(value.trim(), line, &err)?;

        // Last assignment wins, but keep the original position so the applied order still
        // reads like the file.
        match out.iter_mut().find(|(k, _)| k == key) {
            Some(slot) => slot.1 = value,
            None => out.push((key.to_owned(), value)),
        }
    }
    Ok(out)
}

fn parse_value(
    value: &str,
    line: usize,
    err: &impl Fn(usize, &str) -> EnvFileError,
) -> Result<String, EnvFileError> {
    let mut chars = value.chars();
    let quote = match chars.next() {
        Some(q @ ('"' | '\'')) => q,
        // Unquoted: verbatim, already trimmed by the caller. No comment stripping, so a `#`
        // inside a credential survives.
        _ => return Ok(value.to_owned()),
    };

    let mut out = String::new();
    let mut closed = false;
    while let Some(c) = chars.next() {
        match c {
            c if c == quote => {
                closed = true;
                break;
            }
            // Single quotes are literal all the way through, backslash included.
            '\\' if quote == '"' => match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some(other) => {
                    return Err(err(
                        line,
                        &format!(
                            "unknown escape `\\{other}` — only \\n \\r \\t \\\\ \\\" are understood"
                        ),
                    ));
                }
                None => return Err(err(line, "value ends in a trailing backslash")),
            },
            c => out.push(c),
        }
    }

    if !closed {
        return Err(err(line, &format!("unterminated {quote} quote")));
    }
    // Trailing junk after the closing quote is a typo often enough — and an attempt at an
    // inline comment often enough — that guessing which is worse than saying so.
    let rest: String = chars.collect();
    if !rest.trim().is_empty() {
        return Err(err(line, "unexpected text after the closing quote"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(text: &str) -> Vec<(String, String)> {
        parse(Path::new("t.env"), text).unwrap()
    }

    fn e(text: &str) -> String {
        parse(Path::new("t.env"), text).unwrap_err().to_string()
    }

    #[test]
    fn parses_the_ordinary_shapes() {
        let vars = p("\
# a comment
FOO=bar
export BAZ=qux

  SPACED  =  padded value
EMPTY=
");
        assert_eq!(
            vars,
            vec![
                ("FOO".into(), "bar".into()),
                ("BAZ".into(), "qux".into()),
                ("SPACED".into(), "padded value".into()),
                ("EMPTY".into(), String::new()),
            ]
        );
    }

    #[test]
    fn a_hash_in_an_unquoted_value_is_part_of_the_secret() {
        // The whole reason inline comments are not supported: this is a valid password.
        assert_eq!(p("PASSWORD=hunter2#not-a-comment")[0].1, "hunter2#not-a-comment");
    }

    #[test]
    fn quoting_rules() {
        assert_eq!(p(r#"A="line\none""#)[0].1, "line\none");
        assert_eq!(p(r"B='raw\nliteral'")[0].1, r"raw\nliteral");
        assert_eq!(p(r#"C="has = and # inside""#)[0].1, "has = and # inside");
        assert_eq!(p(r#"D="quoted \"inner\"""#)[0].1, r#"quoted "inner""#);
    }

    #[test]
    fn no_interpolation() {
        // A value containing `$` is a value containing `$`.
        assert_eq!(p("A=${HOME}/x")[0].1, "${HOME}/x");
    }

    #[test]
    fn the_last_assignment_wins() {
        assert_eq!(p("A=1\nA=2"), vec![("A".to_owned(), "2".to_owned())]);
    }

    #[test]
    fn syntax_errors_name_the_line() {
        assert!(e("A=1\nnot an assignment").starts_with("t.env:2: expected KEY=value"));
        assert!(e("1BAD=x").contains("not a usable variable name"));
        assert!(e("=x").contains("empty variable name"));
        assert!(e("A=\"unterminated").contains("unterminated \" quote"));
        assert!(e(r#"A="x" # comment"#).contains("unexpected text after the closing quote"));
        assert!(e(r#"A="\q""#).contains("unknown escape"));
    }

    #[test]
    fn a_missing_default_file_is_not_an_error_but_a_missing_named_one_is() {
        let dir = std::env::temp_dir().join(format!("marshal-env-file-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        assert!(read(&Requested::IfPresent(dir.join(".env"))).unwrap().is_none());
        let err = read(&Requested::Required {
            path: dir.join("secrets.env"),
            named: "secrets.env".to_owned(),
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("`env_file: secrets.env`"), "{err}");
        assert!(err.contains("which does not exist"), "{err}");
        assert!(read(&Requested::Disabled).unwrap().is_none());

        std::fs::write(dir.join(".env"), "A=1\n").unwrap();
        let (path, vars) = read(&Requested::IfPresent(dir.join(".env"))).unwrap().unwrap();
        assert_eq!(path, dir.join(".env"));
        assert_eq!(vars, vec![("A".to_owned(), "1".to_owned())]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reads_only_the_env_file_key_from_the_config() {
        let dir =
            std::env::temp_dir().join(format!("marshal-env-requested-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("marshal.yaml");

        // A document full of fields this struct does not have, which must not get in the way.
        std::fs::write(
            &cfg,
            "listeners:\n  explicit:\n    listen: \"127.0.0.1:8080\"\nenv_file: secrets.env\n",
        )
        .unwrap();
        assert_eq!(
            requested_for(&cfg),
            Requested::Required { path: dir.join("secrets.env"), named: "secrets.env".to_owned() }
        );

        std::fs::write(&cfg, "env_file: false\n").unwrap();
        assert_eq!(requested_for(&cfg), Requested::Disabled);

        std::fs::write(&cfg, "profiles_path: elsewhere\n").unwrap();
        assert_eq!(requested_for(&cfg), Requested::IfPresent(dir.join(".env")));

        // A broken config is the next load's problem to report, not this one's.
        std::fs::write(&cfg, "env_file: [not, a, path]\n").unwrap();
        assert_eq!(requested_for(&cfg), Requested::Disabled);
        assert_eq!(requested_for(&dir.join("absent.yaml")), Requested::Disabled);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolves_relative_to_the_config_file() {
        use crate::model::EnvFileSetting;
        let cfg = Path::new("/etc/bot-marshal/marshal.yaml");
        assert_eq!(
            requested(cfg, None),
            Requested::IfPresent(PathBuf::from("/etc/bot-marshal/.env"))
        );
        assert_eq!(
            requested(cfg, Some(&EnvFileSetting::Path("secrets/agent.env".into()))),
            Requested::Required {
                path: PathBuf::from("/etc/bot-marshal/secrets/agent.env"),
                named: "secrets/agent.env".to_owned()
            }
        );
        assert_eq!(
            requested(cfg, Some(&EnvFileSetting::Path("/run/secrets/x.env".into()))),
            Requested::Required {
                path: PathBuf::from("/run/secrets/x.env"),
                named: "/run/secrets/x.env".to_owned()
            }
        );
        assert_eq!(requested(cfg, Some(&EnvFileSetting::Enabled(false))), Requested::Disabled);
    }
}
