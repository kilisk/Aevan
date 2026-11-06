//! Terminal secret input.
//!
//! Passwords and tokens are never accepted in argv or the environment. On a TTY
//! they are read with echo disabled; when stdin is redirected (scripts, tests)
//! they are read as newline-delimited input. Nothing here writes the secret to
//! stdout, stderr or a log.

use std::io::{self, IsTerminal, Write};

/// Whether stdin is attached to a terminal.
pub fn stdin_is_terminal() -> bool {
    io::stdin().is_terminal()
}

/// Read one line from stdin, stripping the line ending.
pub fn read_line() -> io::Result<String> {
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    Ok(trim_line_ending(value))
}

/// Read a non-secret line from the terminal.
pub fn read_visible(prompt: &str) -> io::Result<String> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    read_line()
}

/// Read a secret without echoing it when stdin is a terminal.
///
/// When stdin is redirected the secret is read as a plain line, so a caller can
/// pipe it in; it still never reaches argv, the environment or a log.
pub fn read_secret(prompt: &str) -> io::Result<String> {
    if !stdin_is_terminal() {
        return read_line();
    }

    rpassword::prompt_password(prompt).map(trim_line_ending)
}

fn trim_line_ending(mut value: String) -> String {
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    } else if value.ends_with('\r') {
        value.pop();
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_endings_are_stripped() {
        assert_eq!(trim_line_ending("secret\n".into()), "secret");
        assert_eq!(trim_line_ending("secret\r\n".into()), "secret");
        assert_eq!(trim_line_ending("secret\r".into()), "secret");
        assert_eq!(trim_line_ending("secret".into()), "secret");
        assert_eq!(trim_line_ending("\n".into()), "");
    }
}
