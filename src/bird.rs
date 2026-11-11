// Client for Bird's control socket, the same line protocol birdc speaks
use crate::prefix::Prefix;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

pub struct Session {
    pub local_as: u32,
    pub neighbor_as: u32,
    pub multihop: bool,
}

pub struct BirdClient {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl BirdClient {
    pub fn connect(socket_path: &Path) -> std::io::Result<Self> {
        let stream = UnixStream::connect(socket_path)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut client = Self { reader: BufReader::new(stream.try_clone()?), writer: stream };

        // Bird greets every new connection before taking commands
        client.read_reply()?;
        Ok(client)
    }

    pub fn command(&mut self, command: &str) -> std::io::Result<Vec<String>> {
        writeln!(self.writer, "{}", command)?;
        self.read_reply()
    }

    pub fn exported_prefixes(&mut self, protocol: &str) -> std::io::Result<Vec<Prefix>> {

        // Each route's line starts with its prefix, and its other paths and attributes follow on indented lines
        Ok(self
            .command(&format!("show route export {}", protocol))?
            .iter()
            .filter(|line| !line.starts_with(char::is_whitespace))
            .filter_map(|line| line.split_whitespace().next()?.parse().ok())
            .collect())
    }

    pub fn session(&mut self, protocol: &str) -> std::io::Result<Session> {

        // The session's details are indented "<label>: <value>" lines, and its kind reads like "external multihop AS4"
        let lines = self.command(&format!("show protocols all {}", protocol))?;
        let field = |label: &str| {
            lines
                .iter()
                .find_map(|line| Some(line.trim_start().strip_prefix(label)?.trim().to_string()))
                .ok_or_else(|| std::io::Error::other(format!("Bird lists no {} for {}", label, protocol)))
        };
        let parse_as = |label: &str| field(label)?.parse().map_err(|_| std::io::Error::other(format!("Bird's {} for {} isn't a number", label, protocol)));
        Ok(Session {
            local_as: parse_as("Local AS:")?,
            neighbor_as: parse_as("Neighbor AS:")?,
            multihop: field("Session:")?.split_whitespace().any(|word| word == "multihop"),
        })
    }

    fn read_reply(&mut self) -> std::io::Result<Vec<String>> {

        // Every line is a four digit code then a separator, or a space to continue the line before it. Codes below 1000 end a reply,
        // codes from 8000 are errors, and everything in between carries data
        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            if self.reader.read_line(&mut line)? == 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "Bird closed its control socket"));
            }
            let line = line.trim_end_matches('\n');
            if let Some(text) = line.strip_prefix(' ') {
                lines.push(text.to_string());
                continue;
            }
            let code: u16 = line
                .get(..4)
                .and_then(|code| code.parse().ok())
                .ok_or_else(|| std::io::Error::other(format!("Unexpected line from Bird: {:?}", line)))?;
            let text = line.get(5..).unwrap_or_default();
            match code {
                0..1000 => return Ok(lines),
                8000.. => return Err(std::io::Error::other(format!("Bird error {}: {}", code, text))),
                _ => lines.push(text.to_string()),
            }
        }
    }
}
