use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEFAULT_BIND: &str = "127.0.0.1:7113";
const DEFAULT_STATE_DIR: &str = "state/identity";

#[derive(Debug)]
struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
}

fn main() -> io::Result<()> {
    let bind = env::var("VAPOR_IDENTITY_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_string());
    let state_dir = PathBuf::from(
        env::var("VAPOR_IDENTITY_STATE").unwrap_or_else(|_| DEFAULT_STATE_DIR.to_string()),
    );
    fs::create_dir_all(&state_dir)?;

    let listener = TcpListener::bind(&bind)?;
    eprintln!("vapor-identity-server listening on {bind}");

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                if let Err(error) = handle_connection(&mut stream, &state_dir) {
                    eprintln!("request failed: {error}");
                }
            }
            Err(error) => eprintln!("connection failed: {error}"),
        }
    }

    Ok(())
}

fn handle_connection(stream: &mut TcpStream, state_dir: &Path) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let Some(request) = read_request(stream)? else {
        return Ok(());
    };

    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/healthz") => respond_text(stream, "200 OK", "ok\n"),
        ("GET", "/v1/status") => status(stream, state_dir),
        ("POST", "/v1/init") => init(stream, state_dir, &request),
        ("GET", "/v1/export") => export_identity(stream, state_dir, &request),
        _ => respond_text(stream, "404 Not Found", "not found\n"),
    }
}

fn status(stream: &mut TcpStream, state_dir: &Path) -> io::Result<()> {
    let registry = state_dir.join("registry.toml");
    let initialized = registry.exists();
    let body = format!(
        "service = \"vapor-identity-server\"\ninitialized = {}\nsteam_identity = \"planned\"\ngithub_identity = \"planned\"\n",
        toml_bool(initialized)
    );
    respond_text(stream, "200 OK", &body)
}

fn init(stream: &mut TcpStream, state_dir: &Path, request: &Request) -> io::Result<()> {
    if !has_admin_token(request, "VAPOR_IDENTITY_ADMIN_TOKEN") {
        return respond_text(
            stream,
            "401 Unauthorized",
            "missing or invalid admin token\n",
        );
    }

    let registry = state_dir.join("registry.toml");
    if registry.exists() {
        return respond_text(
            stream,
            "409 Conflict",
            "identity registry already initialized\n",
        );
    }

    fs::create_dir_all(state_dir)?;
    fs::write(
        &registry,
        format!(
            "schema_version = 1\ninitialized_at_unix = {}\n\n[policy]\nplayers_require_github = false\ndevelopers_require_steam = true\ndevelopers_require_github = true\nroot_requires_role = true\n",
            unix_now()
        ),
    )?;

    respond_text(stream, "201 Created", "identity: initialized\n")
}

fn export_identity(stream: &mut TcpStream, state_dir: &Path, request: &Request) -> io::Result<()> {
    if !has_admin_token(request, "VAPOR_IDENTITY_ADMIN_TOKEN") {
        return respond_text(
            stream,
            "401 Unauthorized",
            "missing or invalid admin token\n",
        );
    }

    let registry = state_dir.join("registry.toml");
    let body = fs::read_to_string(registry).unwrap_or_else(|_| {
        "schema_version = 1\ninitialized = false\n# no identity registry has been initialized\n"
            .to_string()
    });
    respond_text(stream, "200 OK", &body)
}

fn has_admin_token(request: &Request, env_name: &str) -> bool {
    let Ok(expected) = env::var(env_name) else {
        return false;
    };
    if expected.is_empty() {
        return false;
    }

    request
        .headers
        .iter()
        .any(|(name, value)| name == "authorization" && value == &format!("Bearer {expected}"))
}

fn read_request(stream: &mut TcpStream) -> io::Result<Option<Request>> {
    let mut buffer = [0_u8; 8192];
    let read = stream.read(&mut buffer)?;
    if read == 0 {
        return Ok(None);
    }

    let text = String::from_utf8_lossy(&buffer[..read]);
    let mut lines = text.lines();
    let Some(request_line) = lines.next() else {
        return Ok(None);
    };

    let mut request_parts = request_line.split_whitespace();
    let Some(method) = request_parts.next() else {
        return Ok(None);
    };
    let Some(path) = request_parts.next() else {
        return Ok(None);
    };

    let headers = lines
        .take_while(|line| !line.is_empty())
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_ascii_lowercase(), value.trim().to_string()))
        })
        .collect();

    Ok(Some(Request {
        method: method.to_string(),
        path: path.to_string(),
        headers,
    }))
}

fn respond_text(stream: &mut TcpStream, status: &str, body: &str) -> io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn toml_bool(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
