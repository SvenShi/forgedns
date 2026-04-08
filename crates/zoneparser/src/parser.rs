use forgedns_proto::decode_rdata_from_wire;
use forgedns_proto::{
    A, AAAA, AFSDB, ANAME, AVC, CAA, CNAME, DNAME, DNSClass, HINFO, MB, MD, MF, MG, MINFO, MR, MX,
    NAPTR, NS, NSAPPTR, Name, PTR, RData, RESINFO, RP, RT, Record, RecordType, SOA, SPF, SRV, TXT,
};
use std::fmt;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct ParseOptions {
    pub initial_origin: Option<Name>,
    pub default_ttl: u32,
    pub base_dir: Option<PathBuf>,
    pub max_include_depth: usize,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            initial_origin: None,
            default_ttl: 3600,
            base_dir: None,
            max_include_depth: 16,
        }
    }
}

impl ParseOptions {
    pub fn with_initial_origin(mut self, origin: Name) -> Self {
        self.initial_origin = Some(origin);
        self
    }

    pub fn with_default_ttl(mut self, ttl: u32) -> Self {
        self.default_ttl = ttl;
        self
    }

    pub fn with_base_dir<P: Into<PathBuf>>(mut self, base_dir: P) -> Self {
        self.base_dir = Some(base_dir.into());
        self
    }

    pub fn with_max_include_depth(mut self, depth: usize) -> Self {
        self.max_include_depth = depth.max(1);
        self
    }
}

#[derive(Debug, Error)]
pub enum ZoneParseError {
    #[error("{location}:{line}: {message}")]
    Syntax {
        location: String,
        line: usize,
        message: String,
    },

    #[error("failed to read zone source '{path}': {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("relative $INCLUDE is not supported for inline zone source")]
    RelativeIncludeWithoutBaseDir,

    #[error("$INCLUDE nesting exceeds configured max depth ({max_depth})")]
    IncludeDepthExceeded { max_depth: usize },
}

#[derive(Debug, Clone)]
struct ParserState {
    origin: Option<Name>,
    current_owner: Option<Name>,
    current_class: DNSClass,
    current_ttl: u32,
}

impl ParserState {
    fn new(options: &ParseOptions) -> Self {
        Self {
            origin: options.initial_origin.clone(),
            current_owner: None,
            current_class: DNSClass::IN,
            current_ttl: options.default_ttl,
        }
    }
}

#[derive(Debug, Clone)]
struct SourceContext {
    label: String,
    path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
struct LogicalLine {
    text: String,
    line: usize,
    leading_whitespace: bool,
}

#[derive(Debug, Clone)]
struct Token {
    raw: String,
    quoted: bool,
}

impl Token {
    fn upper(&self) -> String {
        self.raw.to_ascii_uppercase()
    }

    fn decode_include_path(&self) -> Result<String, String> {
        decode_include_path(&self.raw)
    }

    fn decode_text_bytes(&self) -> Result<Vec<u8>, String> {
        decode_escaped_bytes(&self.raw)
    }
}

pub fn parse_str(input: &str, options: &ParseOptions) -> Result<Vec<Record>, ZoneParseError> {
    let source = SourceContext {
        label: "<inline>".to_string(),
        path: None,
    };
    let mut state = ParserState::new(options);
    let mut out = Vec::new();
    parse_source(input, &source, options, 0, &mut state, &mut out)?;
    Ok(out)
}

pub fn parse_file(
    path: impl AsRef<Path>,
    options: &ParseOptions,
) -> Result<Vec<Record>, ZoneParseError> {
    let path = path.as_ref();
    let input = fs::read_to_string(path).map_err(|source| ZoneParseError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    let mut effective = options.clone();
    if effective.base_dir.is_none() {
        effective.base_dir = path.parent().map(Path::to_path_buf);
    }

    let source = SourceContext {
        label: path.display().to_string(),
        path: Some(path.to_path_buf()),
    };
    let mut state = ParserState::new(&effective);
    let mut out = Vec::new();
    parse_source(&input, &source, &effective, 0, &mut state, &mut out)?;
    Ok(out)
}

fn parse_source(
    input: &str,
    source: &SourceContext,
    options: &ParseOptions,
    include_depth: usize,
    state: &mut ParserState,
    out: &mut Vec<Record>,
) -> Result<(), ZoneParseError> {
    for line in logical_lines(input, source)? {
        let tokens = tokenize_logical_line(&line, source)?;
        if tokens.is_empty() {
            continue;
        }

        if tokens[0].raw.starts_with('$') {
            handle_directive(&line, &tokens, source, options, include_depth, state, out)?;
        } else {
            parse_record_line(&line, &tokens, source, state, out)?;
        }
    }

    Ok(())
}

fn handle_directive(
    line: &LogicalLine,
    tokens: &[Token],
    source: &SourceContext,
    options: &ParseOptions,
    include_depth: usize,
    state: &mut ParserState,
    out: &mut Vec<Record>,
) -> Result<(), ZoneParseError> {
    match tokens[0].upper().as_str() {
        "$ORIGIN" => {
            if tokens.len() != 2 {
                return Err(syntax_error(
                    source,
                    line.line,
                    "$ORIGIN requires exactly one argument",
                ));
            }
            state.origin = Some(parse_name_token(&tokens[1], state.origin.as_ref()).map_err(
                |message| {
                    syntax_error(
                        source,
                        line.line,
                        format!("invalid $ORIGIN value: {}", message),
                    )
                },
            )?);
            state.current_owner = None;
            Ok(())
        }
        "$TTL" => {
            if tokens.len() != 2 {
                return Err(syntax_error(
                    source,
                    line.line,
                    "$TTL requires exactly one argument",
                ));
            }
            state.current_ttl = parse_ttl(&tokens[1].raw)
                .map_err(|message| syntax_error(source, line.line, message))?;
            Ok(())
        }
        "$INCLUDE" => handle_include(line, tokens, source, options, include_depth, state, out),
        "$GENERATE" => handle_generate(line, tokens, source, state, out),
        _ => Err(syntax_error(
            source,
            line.line,
            format!("unsupported directive '{}'", tokens[0].raw),
        )),
    }
}

fn handle_include(
    line: &LogicalLine,
    tokens: &[Token],
    source: &SourceContext,
    options: &ParseOptions,
    include_depth: usize,
    state: &mut ParserState,
    out: &mut Vec<Record>,
) -> Result<(), ZoneParseError> {
    if include_depth >= options.max_include_depth {
        return Err(ZoneParseError::IncludeDepthExceeded {
            max_depth: options.max_include_depth,
        });
    }
    if tokens.len() < 2 || tokens.len() > 3 {
        return Err(syntax_error(
            source,
            line.line,
            "$INCLUDE requires a path and optional origin",
        ));
    }

    let include_path = tokens[1]
        .decode_include_path()
        .map_err(|message| syntax_error(source, line.line, message))?;
    let include_path = resolve_include_path(source, options, &include_path)?;
    let include_text =
        fs::read_to_string(&include_path).map_err(|source_error| ZoneParseError::Io {
            path: include_path.clone(),
            source: source_error,
        })?;

    let mut child_state = ParserState {
        origin: if let Some(origin) = tokens.get(2) {
            Some(
                parse_name_token(origin, state.origin.as_ref()).map_err(|message| {
                    syntax_error(
                        source,
                        line.line,
                        format!("invalid $INCLUDE origin: {}", message),
                    )
                })?,
            )
        } else {
            state.origin.clone()
        },
        current_owner: None,
        current_class: state.current_class,
        current_ttl: state.current_ttl,
    };

    let child_source = SourceContext {
        label: include_path.display().to_string(),
        path: Some(include_path),
    };
    parse_source(
        &include_text,
        &child_source,
        options,
        include_depth + 1,
        &mut child_state,
        out,
    )
}

fn handle_generate(
    line: &LogicalLine,
    tokens: &[Token],
    source: &SourceContext,
    state: &mut ParserState,
    out: &mut Vec<Record>,
) -> Result<(), ZoneParseError> {
    if tokens.len() < 5 {
        return Err(syntax_error(
            source,
            line.line,
            "$GENERATE requires at least '<range> <lhs> <type> <rhs>'",
        ));
    }

    let range = parse_generate_range(&tokens[1].raw)
        .map_err(|message| syntax_error(source, line.line, message))?;
    let lhs = tokens[2].raw.clone();

    let mut idx = 3usize;
    let mut ttl = None;
    let mut class = None;
    let rr_type;

    loop {
        let token = tokens
            .get(idx)
            .ok_or_else(|| syntax_error(source, line.line, "$GENERATE missing record type"))?;
        let upper = token.upper();
        if let Ok(value) = parse_record_type(&upper) {
            rr_type = value;
            idx += 1;
            break;
        }
        if let Ok(value) = parse_dns_class(&upper) {
            class = Some(value);
            idx += 1;
            continue;
        }
        if let Ok(value) = parse_ttl(&token.raw) {
            ttl = Some(value);
            idx += 1;
            continue;
        }
        return Err(syntax_error(
            source,
            line.line,
            format!("unexpected token '{}' in $GENERATE header", token.raw),
        ));
    }

    if idx >= tokens.len() {
        return Err(syntax_error(
            source,
            line.line,
            "$GENERATE requires RDATA template",
        ));
    }

    let rdata_template = tokens[idx..]
        .iter()
        .map(|token| token.raw.as_str())
        .collect::<Vec<_>>()
        .join(" ");

    for value in range.iter() {
        let owner = expand_generate_template(&lhs, value)
            .map_err(|message| syntax_error(source, line.line, message))?;
        let rdata = expand_generate_template(&rdata_template, value)
            .map_err(|message| syntax_error(source, line.line, message))?;

        let mut generated = owner;
        if let Some(ttl) = ttl {
            generated.push(' ');
            generated.push_str(&ttl.to_string());
        }
        if let Some(class) = class {
            generated.push(' ');
            generated.push_str(class.to_string().as_str());
        }
        generated.push(' ');
        generated.push_str(<&str>::from(rr_type));
        generated.push(' ');
        generated.push_str(&rdata);

        let generated_line = LogicalLine {
            text: generated,
            line: line.line,
            leading_whitespace: false,
        };
        let generated_tokens = tokenize_logical_line(&generated_line, source)?;
        parse_record_line(&generated_line, &generated_tokens, source, state, out)?;
    }

    Ok(())
}

fn parse_record_line(
    line: &LogicalLine,
    tokens: &[Token],
    source: &SourceContext,
    state: &mut ParserState,
    out: &mut Vec<Record>,
) -> Result<(), ZoneParseError> {
    let mut idx = 0usize;
    let owner = if line.leading_whitespace {
        state.current_owner.clone().ok_or_else(|| {
            syntax_error(
                source,
                line.line,
                "record owner omitted before any owner was established",
            )
        })?
    } else {
        let owner = parse_name_token(&tokens[0], state.origin.as_ref())
            .map_err(|message| syntax_error(source, line.line, message))?;
        idx = 1;
        owner
    };

    let mut ttl = None;
    let mut explicit_ttl = false;
    let mut class = None;
    let mut explicit_class = false;
    let rr_type;

    loop {
        let token = tokens
            .get(idx)
            .ok_or_else(|| syntax_error(source, line.line, "record is missing type and RDATA"))?;
        let upper = token.upper();

        if let Ok(value) = parse_record_type(&upper) {
            rr_type = value;
            idx += 1;
            break;
        }
        if let Ok(value) = parse_dns_class(&upper) {
            class = Some(value);
            explicit_class = true;
            idx += 1;
            continue;
        }
        if let Ok(value) = parse_ttl(&token.raw) {
            ttl = Some(value);
            explicit_ttl = true;
            idx += 1;
            continue;
        }

        return Err(syntax_error(
            source,
            line.line,
            format!("unexpected token '{}' before record type", token.raw),
        ));
    }

    let ttl = ttl.unwrap_or(state.current_ttl);
    let class = class.unwrap_or(state.current_class);
    let rdata = parse_record_rdata(rr_type, &tokens[idx..], state.origin.as_ref())
        .map_err(|message| syntax_error(source, line.line, message))?;

    if explicit_ttl {
        state.current_ttl = ttl;
    }
    if explicit_class {
        state.current_class = class;
    }
    state.current_owner = Some(owner.clone());

    out.push(Record::from_rdata_with_class(owner, ttl, class, rdata));
    Ok(())
}

fn parse_record_rdata(
    rr_type: RecordType,
    fields: &[Token],
    origin: Option<&Name>,
) -> Result<RData, String> {
    if let Some(rdata) = try_parse_generic_rdata(rr_type, fields)? {
        return Ok(rdata);
    }

    match rr_type {
        RecordType::A => {
            let field = require_exact_fields(fields, 1, "A")?;
            let ip: IpAddr = field[0]
                .raw
                .parse()
                .map_err(|e| format!("invalid A address '{}': {}", field[0].raw, e))?;
            match ip {
                IpAddr::V4(ip) => Ok(RData::A(A(ip))),
                IpAddr::V6(_) => Err("A record requires an IPv4 address".to_string()),
            }
        }
        RecordType::AAAA => {
            let field = require_exact_fields(fields, 1, "AAAA")?;
            let ip: IpAddr = field[0]
                .raw
                .parse()
                .map_err(|e| format!("invalid AAAA address '{}': {}", field[0].raw, e))?;
            match ip {
                IpAddr::V6(ip) => Ok(RData::AAAA(AAAA(ip))),
                IpAddr::V4(_) => Err("AAAA record requires an IPv6 address".to_string()),
            }
        }
        RecordType::CNAME => Ok(RData::CNAME(CNAME(parse_name_token(&fields[0], origin)?))),
        RecordType::NS => Ok(RData::NS(NS(parse_name_token(&fields[0], origin)?))),
        RecordType::PTR => Ok(RData::PTR(PTR(parse_name_token(&fields[0], origin)?))),
        RecordType::DNAME => Ok(RData::DNAME(DNAME(parse_name_token(&fields[0], origin)?))),
        RecordType::ANAME => Ok(RData::ANAME(ANAME(parse_name_token(&fields[0], origin)?))),
        RecordType::MD => Ok(RData::MD(MD(parse_name_token(&fields[0], origin)?))),
        RecordType::MF => Ok(RData::MF(MF(parse_name_token(&fields[0], origin)?))),
        RecordType::MB => Ok(RData::MB(MB(parse_name_token(&fields[0], origin)?))),
        RecordType::MG => Ok(RData::MG(MG(parse_name_token(&fields[0], origin)?))),
        RecordType::MR => Ok(RData::MR(MR(parse_name_token(&fields[0], origin)?))),
        RecordType::NSAPPTR => Ok(RData::NSAPPTR(NSAPPTR(parse_name_token(
            &fields[0], origin,
        )?))),
        RecordType::MX => parse_u16_name_pair(fields, origin, "MX")
            .map(|value| RData::MX(MX::new(value.0, value.1))),
        RecordType::RT => parse_u16_name_pair(fields, origin, "RT")
            .map(|value| RData::RT(RT::new(value.0, value.1))),
        RecordType::AFSDB => parse_u16_name_pair(fields, origin, "AFSDB")
            .map(|value| RData::AFSDB(AFSDB::new(value.0, value.1))),
        RecordType::RP => {
            let fields = require_exact_fields(fields, 2, "RP")?;
            Ok(RData::RP(RP::new(
                parse_name_token(&fields[0], origin)?,
                parse_name_token(&fields[1], origin)?,
            )))
        }
        RecordType::MINFO => {
            let fields = require_exact_fields(fields, 2, "MINFO")?;
            Ok(RData::MINFO(MINFO::new(
                parse_name_token(&fields[0], origin)?,
                parse_name_token(&fields[1], origin)?,
            )))
        }
        RecordType::HINFO => {
            let fields = require_exact_fields(fields, 2, "HINFO")?;
            Ok(RData::HINFO(HINFO::new(
                fields[0].decode_text_bytes()?.into_boxed_slice(),
                fields[1].decode_text_bytes()?.into_boxed_slice(),
            )))
        }
        RecordType::TXT => parse_txt_like(fields).map(RData::TXT),
        RecordType::SPF => parse_txt_like(fields).map(|value| RData::SPF(SPF(value))),
        RecordType::AVC => parse_txt_like(fields).map(|value| RData::AVC(AVC(value))),
        RecordType::RESINFO => parse_txt_like(fields).map(|value| RData::RESINFO(RESINFO(value))),
        RecordType::SOA => {
            let fields = require_exact_fields(fields, 7, "SOA")?;
            Ok(RData::SOA(SOA::new(
                parse_name_token(&fields[0], origin)?,
                parse_name_token(&fields[1], origin)?,
                parse_u32(&fields[2].raw, "SOA serial")?,
                parse_i32(&fields[3].raw, "SOA refresh")?,
                parse_i32(&fields[4].raw, "SOA retry")?,
                parse_i32(&fields[5].raw, "SOA expire")?,
                parse_u32(&fields[6].raw, "SOA minimum")?,
            )))
        }
        RecordType::SRV => {
            let fields = require_exact_fields(fields, 4, "SRV")?;
            Ok(RData::SRV(SRV::new(
                parse_u16(&fields[0].raw, "SRV priority")?,
                parse_u16(&fields[1].raw, "SRV weight")?,
                parse_u16(&fields[2].raw, "SRV port")?,
                parse_name_token(&fields[3], origin)?,
            )))
        }
        RecordType::NAPTR => {
            let fields = require_exact_fields(fields, 6, "NAPTR")?;
            Ok(RData::NAPTR(NAPTR::new(
                parse_u16(&fields[0].raw, "NAPTR order")?,
                parse_u16(&fields[1].raw, "NAPTR preference")?,
                fields[2].decode_text_bytes()?.into_boxed_slice(),
                fields[3].decode_text_bytes()?.into_boxed_slice(),
                fields[4].decode_text_bytes()?.into_boxed_slice(),
                parse_name_token(&fields[5], origin)?,
            )))
        }
        RecordType::CAA => {
            let fields = require_exact_fields(fields, 3, "CAA")?;
            Ok(RData::CAA(CAA::new(
                parse_u8(&fields[0].raw, "CAA flag")?,
                fields[1].decode_text_bytes()?.into_boxed_slice(),
                fields[2].decode_text_bytes()?.into_boxed_slice(),
            )))
        }
        _ => Err(format!(
            "record type '{}' requires RFC3597 generic syntax ('\\# <len> <hex>') in zoneparser",
            <&str>::from(rr_type)
        )),
    }
}

fn try_parse_generic_rdata(rr_type: RecordType, fields: &[Token]) -> Result<Option<RData>, String> {
    if fields.len() < 3 {
        return Ok(None);
    }
    if fields[0].raw != "#" && fields[0].raw != "\\#" {
        return Ok(None);
    }

    let expected_len = parse_usize(&fields[1].raw, "RFC3597 length")?;
    let hex = fields[2..]
        .iter()
        .map(|field| field.raw.as_str())
        .collect::<Vec<_>>()
        .join("");
    let bytes = decode_hex(&hex)?;

    if bytes.len() != expected_len {
        return Err(format!(
            "RFC3597 length mismatch: declared {}, actual {}",
            expected_len,
            bytes.len()
        ));
    }

    decode_rdata_from_wire(rr_type, &bytes)
        .map(Some)
        .map_err(|e| e.to_string())
}

fn parse_txt_like(fields: &[Token]) -> Result<TXT, String> {
    if fields.is_empty() {
        return Err("TXT-like record requires at least one character-string".to_string());
    }

    let mut wire = Vec::new();
    for field in fields {
        let bytes = field.decode_text_bytes()?;
        if bytes.len() > u8::MAX as usize {
            return Err("TXT chunk exceeds 255 bytes".to_string());
        }
        wire.push(bytes.len() as u8);
        wire.extend_from_slice(&bytes);
    }
    Ok(TXT::new(wire.into_boxed_slice()))
}

fn parse_u16_name_pair(
    fields: &[Token],
    origin: Option<&Name>,
    kind: &str,
) -> Result<(u16, Name), String> {
    let fields = require_exact_fields(fields, 2, kind)?;
    Ok((
        parse_u16(&fields[0].raw, &format!("{} preference", kind))?,
        parse_name_token(&fields[1], origin)?,
    ))
}

fn require_exact_fields<'a>(
    fields: &'a [Token],
    expected: usize,
    kind: &str,
) -> Result<&'a [Token], String> {
    if fields.len() != expected {
        return Err(format!(
            "{} record requires {} field(s), got {}",
            kind,
            expected,
            fields.len()
        ));
    }
    Ok(fields)
}

fn parse_name_token(token: &Token, origin: Option<&Name>) -> Result<Name, String> {
    if token.quoted {
        return Err("domain names cannot be quoted".to_string());
    }

    let raw = token.raw.trim();
    if raw == "@" {
        return origin
            .cloned()
            .ok_or_else(|| "relative name '@' requires an origin".to_string());
    }

    let fqdn = if raw.ends_with('.') {
        raw.to_string()
    } else if let Some(origin) = origin {
        format!("{}.{}", raw, origin.to_fqdn())
    } else {
        return Err(format!(
            "relative name '{}' requires an origin; set it via $ORIGIN or ParseOptions",
            raw
        ));
    };

    Name::from_ascii(&fqdn).map_err(|e| format!("invalid name '{}': {}", raw, e))
}

fn parse_dns_class(raw: &str) -> Result<DNSClass, String> {
    DNSClass::from_str(raw).map_err(|_| format!("unsupported DNS class '{}'", raw))
}

fn parse_record_type(raw: &str) -> Result<RecordType, String> {
    if let Some(code) = raw.strip_prefix("TYPE") {
        return parse_u16(code, "TYPE value").map(RecordType::from);
    }
    RecordType::from_str(raw).map_err(|_| format!("unsupported record type '{}'", raw))
}

fn parse_ttl(raw: &str) -> Result<u32, String> {
    if raw.is_empty() {
        return Err("TTL cannot be empty".to_string());
    }

    let bytes = raw.as_bytes();
    let mut idx = 0usize;
    let mut total = 0u32;

    while idx < bytes.len() {
        let start = idx;
        while idx < bytes.len() && bytes[idx].is_ascii_digit() {
            idx += 1;
        }
        if start == idx {
            return Err(format!("invalid TTL '{}'", raw));
        }
        let number = raw[start..idx]
            .parse::<u32>()
            .map_err(|e| format!("invalid TTL '{}': {}", raw, e))?;

        let multiplier = if idx == bytes.len() {
            1
        } else {
            let unit = bytes[idx].to_ascii_lowercase();
            idx += 1;
            match unit {
                b's' => 1,
                b'm' => 60,
                b'h' => 3600,
                b'd' => 86400,
                b'w' => 604800,
                _ => return Err(format!("invalid TTL unit '{}'", bytes[idx - 1] as char)),
            }
        };

        total = total
            .checked_add(
                number
                    .checked_mul(multiplier)
                    .ok_or_else(|| format!("TTL '{}' exceeds u32 range", raw))?,
            )
            .ok_or_else(|| format!("TTL '{}' exceeds u32 range", raw))?;
    }

    Ok(total)
}

fn logical_lines(input: &str, source: &SourceContext) -> Result<Vec<LogicalLine>, ZoneParseError> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut line_number = 1usize;
    let mut logical_start = 1usize;
    let mut paren_depth = 0usize;
    let mut in_quote = false;
    let mut escaped = false;
    let mut in_comment = false;
    let mut leading_whitespace = false;
    let mut saw_content = false;
    let mut physical_line_start = true;

    for ch in input.chars() {
        if in_comment {
            if ch == '\n' {
                in_comment = false;
                physical_line_start = true;
                line_number += 1;
                if paren_depth == 0 {
                    push_logical_line(&mut out, &mut current, logical_start, leading_whitespace);
                    logical_start = line_number;
                    leading_whitespace = false;
                    saw_content = false;
                } else if !current.ends_with([' ', '\t']) {
                    current.push(' ');
                }
            }
            continue;
        }

        if physical_line_start && !saw_content && matches!(ch, ' ' | '\t') {
            leading_whitespace = true;
        }

        if in_quote {
            current.push(ch);
            match ch {
                '"' if !escaped => in_quote = false,
                '\\' if !escaped => escaped = true,
                _ => escaped = false,
            }
            if ch == '\n' {
                line_number += 1;
                physical_line_start = true;
            } else {
                physical_line_start = false;
                saw_content = true;
            }
            continue;
        }

        if escaped {
            current.push(ch);
            escaped = false;
            if ch == '\n' {
                line_number += 1;
                physical_line_start = true;
            } else {
                physical_line_start = false;
                saw_content = true;
            }
            continue;
        }

        match ch {
            '\\' => {
                current.push(ch);
                escaped = true;
                physical_line_start = false;
                saw_content = true;
            }
            '"' => {
                current.push(ch);
                in_quote = true;
                physical_line_start = false;
                saw_content = true;
            }
            ';' | '#' => in_comment = true,
            '(' => {
                paren_depth += 1;
                if !current.ends_with([' ', '\t']) {
                    current.push(' ');
                }
                physical_line_start = false;
                saw_content = true;
            }
            ')' => {
                if paren_depth == 0 {
                    return Err(syntax_error(source, line_number, "unexpected ')'"));
                }
                paren_depth -= 1;
                if !current.ends_with([' ', '\t']) {
                    current.push(' ');
                }
                physical_line_start = false;
                saw_content = true;
            }
            '\r' => {}
            '\n' => {
                line_number += 1;
                physical_line_start = true;
                if paren_depth == 0 {
                    push_logical_line(&mut out, &mut current, logical_start, leading_whitespace);
                    logical_start = line_number;
                    leading_whitespace = false;
                    saw_content = false;
                } else if !current.ends_with([' ', '\t']) {
                    current.push(' ');
                }
            }
            _ => {
                current.push(ch);
                physical_line_start = false;
                if !ch.is_whitespace() {
                    saw_content = true;
                }
            }
        }
    }

    if escaped {
        return Err(syntax_error(
            source,
            line_number,
            "unterminated escape sequence",
        ));
    }
    if in_quote {
        return Err(syntax_error(
            source,
            line_number,
            "unterminated quoted string",
        ));
    }
    if paren_depth != 0 {
        return Err(syntax_error(
            source,
            line_number,
            "unterminated parenthesized list",
        ));
    }

    push_logical_line(&mut out, &mut current, logical_start, leading_whitespace);
    Ok(out)
}

fn push_logical_line(
    out: &mut Vec<LogicalLine>,
    current: &mut String,
    line: usize,
    leading_whitespace: bool,
) {
    let text = current.trim();
    if !text.is_empty() {
        out.push(LogicalLine {
            text: text.to_string(),
            line,
            leading_whitespace,
        });
    }
    current.clear();
}

fn tokenize_logical_line(
    line: &LogicalLine,
    source: &SourceContext,
) -> Result<Vec<Token>, ZoneParseError> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escaping = false;
    let mut just_closed_quote = false;

    for ch in line.text.chars() {
        if quoted {
            current.push(ch);
            if escaping {
                escaping = false;
            } else if ch == '\\' {
                escaping = true;
            } else if ch == '"' {
                current.pop();
                tokens.push(Token {
                    raw: std::mem::take(&mut current),
                    quoted: true,
                });
                quoted = false;
                just_closed_quote = true;
            }
            continue;
        }

        if escaping {
            current.push(ch);
            escaping = false;
            continue;
        }

        if just_closed_quote {
            if ch.is_whitespace() {
                just_closed_quote = false;
                continue;
            }
            return Err(syntax_error(
                source,
                line.line,
                "quoted token must be followed by whitespace",
            ));
        }

        match ch {
            '\\' => {
                current.push(ch);
                escaping = true;
            }
            '"' => {
                if !current.is_empty() {
                    return Err(syntax_error(
                        source,
                        line.line,
                        "unexpected quote in unquoted token",
                    ));
                }
                quoted = true;
            }
            c if c.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(Token {
                        raw: std::mem::take(&mut current),
                        quoted: false,
                    });
                }
            }
            _ => current.push(ch),
        }
    }

    if quoted {
        return Err(syntax_error(
            source,
            line.line,
            "unterminated quoted string",
        ));
    }
    if escaping {
        return Err(syntax_error(
            source,
            line.line,
            "unterminated escape sequence",
        ));
    }
    if !current.is_empty() {
        tokens.push(Token {
            raw: current,
            quoted: false,
        });
    }
    Ok(tokens)
}

fn resolve_include_path(
    source: &SourceContext,
    options: &ParseOptions,
    include_path: &str,
) -> Result<PathBuf, ZoneParseError> {
    let path = Path::new(include_path);
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    if let Some(parent) = source.path.as_ref().and_then(|path| path.parent()) {
        return Ok(parent.join(include_path));
    }
    if let Some(base_dir) = options.base_dir.as_ref() {
        return Ok(base_dir.join(include_path));
    }
    Err(ZoneParseError::RelativeIncludeWithoutBaseDir)
}

fn decode_include_path(raw: &str) -> Result<String, String> {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }

        let Some(next) = chars.next() else {
            return Err("unterminated escape sequence".to_string());
        };

        match next {
            ' ' | '\t' | '"' | '\\' | ';' | '(' | ')' => out.push(next),
            _ => {
                out.push('\\');
                out.push(next);
            }
        }
    }
    Ok(out)
}

fn decode_escaped_bytes(raw: &str) -> Result<Vec<u8>, String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut idx = 0usize;
    while idx < bytes.len() {
        if bytes[idx] != b'\\' {
            out.push(bytes[idx]);
            idx += 1;
            continue;
        }
        idx += 1;
        if idx >= bytes.len() {
            return Err("unterminated escape sequence".to_string());
        }
        if idx + 2 < bytes.len()
            && bytes[idx].is_ascii_digit()
            && bytes[idx + 1].is_ascii_digit()
            && bytes[idx + 2].is_ascii_digit()
        {
            let value =
                (bytes[idx] - b'0') * 100 + (bytes[idx + 1] - b'0') * 10 + (bytes[idx + 2] - b'0');
            out.push(value);
            idx += 3;
        } else {
            out.push(bytes[idx]);
            idx += 1;
        }
    }
    Ok(out)
}

fn decode_hex(raw: &str) -> Result<Vec<u8>, String> {
    if !raw.len().is_multiple_of(2) {
        return Err("hex payload must have even length".to_string());
    }
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut idx = 0usize;
    while idx < bytes.len() {
        let hi = hex_nibble(bytes[idx])
            .ok_or_else(|| format!("invalid hex character '{}'", bytes[idx] as char))?;
        let lo = hex_nibble(bytes[idx + 1])
            .ok_or_else(|| format!("invalid hex character '{}'", bytes[idx + 1] as char))?;
        out.push((hi << 4) | lo);
        idx += 2;
    }
    Ok(out)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn parse_u8(raw: &str, field: &str) -> Result<u8, String> {
    raw.parse::<u8>()
        .map_err(|e| format!("invalid {} '{}': {}", field, raw, e))
}

fn parse_u16(raw: &str, field: &str) -> Result<u16, String> {
    raw.parse::<u16>()
        .map_err(|e| format!("invalid {} '{}': {}", field, raw, e))
}

fn parse_u32(raw: &str, field: &str) -> Result<u32, String> {
    raw.parse::<u32>()
        .map_err(|e| format!("invalid {} '{}': {}", field, raw, e))
}

fn parse_i32(raw: &str, field: &str) -> Result<i32, String> {
    raw.parse::<i32>()
        .map_err(|e| format!("invalid {} '{}': {}", field, raw, e))
}

fn parse_usize(raw: &str, field: &str) -> Result<usize, String> {
    raw.parse::<usize>()
        .map_err(|e| format!("invalid {} '{}': {}", field, raw, e))
}

fn syntax_error(source: &SourceContext, line: usize, message: impl Into<String>) -> ZoneParseError {
    ZoneParseError::Syntax {
        location: source.label.clone(),
        line,
        message: message.into(),
    }
}

#[derive(Debug, Clone, Copy)]
struct GenerateRange {
    start: i64,
    end: i64,
    step: i64,
}

impl GenerateRange {
    fn iter(self) -> impl Iterator<Item = i64> {
        (self.start..=self.end).step_by(self.step as usize)
    }
}

fn parse_generate_range(raw: &str) -> Result<GenerateRange, String> {
    let (range, step) = if let Some((range, step)) = raw.split_once('/') {
        (
            range,
            step.parse::<i64>()
                .map_err(|e| format!("invalid $GENERATE step '{}': {}", step, e))?,
        )
    } else {
        (raw, 1)
    };
    if step <= 0 {
        return Err("$GENERATE step must be positive".to_string());
    }

    let (start, end) = range
        .split_once('-')
        .ok_or_else(|| "$GENERATE range must be 'start-end[/step]'".to_string())?;
    let start = start
        .parse::<i64>()
        .map_err(|e| format!("invalid $GENERATE start '{}': {}", start, e))?;
    let end = end
        .parse::<i64>()
        .map_err(|e| format!("invalid $GENERATE end '{}': {}", end, e))?;
    if end < start {
        return Err("$GENERATE end must be >= start".to_string());
    }

    Ok(GenerateRange { start, end, step })
}

fn expand_generate_template(template: &str, value: i64) -> Result<String, String> {
    let bytes = template.as_bytes();
    let mut out = String::with_capacity(template.len() + 16);
    let mut idx = 0usize;

    while idx < bytes.len() {
        if bytes[idx] != b'$' {
            out.push(bytes[idx] as char);
            idx += 1;
            continue;
        }
        idx += 1;
        if idx < bytes.len() && bytes[idx] == b'{' {
            idx += 1;
            let start = idx;
            while idx < bytes.len() && bytes[idx] != b'}' {
                idx += 1;
            }
            if idx >= bytes.len() {
                return Err("unterminated ${...} in $GENERATE template".to_string());
            }
            out.push_str(&format_generate_value(value, &template[start..idx])?);
            idx += 1;
        } else {
            out.push_str(&format_generate_value(value, "")?);
        }
    }

    Ok(out)
}

fn format_generate_value(value: i64, spec: &str) -> Result<String, String> {
    let mut offset = 0i64;
    let mut width = 0usize;
    let mut base = 'd';

    if !spec.is_empty() {
        let parts = spec.split(',').collect::<Vec<_>>();
        offset = parts[0]
            .parse::<i64>()
            .map_err(|e| format!("invalid $GENERATE offset '{}': {}", parts[0], e))?;
        if let Some(width_part) = parts.get(1) {
            width = width_part
                .parse::<usize>()
                .map_err(|e| format!("invalid $GENERATE width '{}': {}", width_part, e))?;
        }
        if let Some(base_part) = parts.get(2) {
            let mut chars = base_part.chars();
            base = chars
                .next()
                .ok_or_else(|| "empty $GENERATE base modifier".to_string())?;
            if chars.next().is_some() {
                return Err(format!("invalid $GENERATE base modifier '{}'", base_part));
            }
        }
    }

    let actual = value + offset;
    let formatted = match base {
        'd' | 'D' => actual.to_string(),
        'o' | 'O' => format!("{:o}", actual),
        'x' => format!("{:x}", actual),
        'X' => format!("{:X}", actual),
        _ => {
            return Err(format!(
                "unsupported $GENERATE base '{}'; supported: d, o, x, X",
                base
            ));
        }
    };

    if width == 0 || formatted.len() >= width {
        Ok(formatted)
    } else {
        Ok(format!("{:0>width$}", formatted, width = width))
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir() -> PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("zoneparser-test-{}", nanos));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("test_data")
            .join(name)
    }

    fn parse_fixture_file(name: &str) -> Vec<Record> {
        parse_file(fixture_path(name), &ParseOptions::default()).unwrap()
    }

    fn txt_chunks(record: &Record) -> Vec<String> {
        let RData::TXT(txt) = record.data() else {
            panic!("expected TXT record, got {:?}", record.data());
        };
        txt.txt_data_utf8()
            .map(|part| {
                part.expect("fixture TXT data must be valid utf-8")
                    .to_string()
            })
            .collect()
    }

    #[test]
    fn parses_simple_fixture() {
        let records = parse_fixture_file("simple.zn");
        assert_eq!(records.len(), 6);
        assert_eq!(records[0].name().to_fqdn(), "simple.zn.");
        assert_eq!(records[0].rr_type(), RecordType::SOA);
        assert_eq!(records[1].rr_type(), RecordType::NS);
        assert_eq!(records[2].rr_type(), RecordType::NS);
        let RData::MX(mx) = records[3].data() else {
            panic!("expected MX record");
        };
        assert_eq!(mx.preference(), 10);
        assert_eq!(mx.exchange().to_fqdn(), "mail.simple.zn.");
        assert_eq!(records[4].rr_type(), RecordType::A);
        assert_eq!(records[5].rr_type(), RecordType::AAAA);
    }

    #[test]
    fn parses_directives_fixture() {
        let records = parse_fixture_file("directives.zn");
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].rr_type(), RecordType::SOA);
        assert_eq!(records[0].ttl(), 7200);
        assert_eq!(records[1].rr_type(), RecordType::NS);
        assert_eq!(records[1].ttl(), 300);
        assert_eq!(records[2].rr_type(), RecordType::NS);
        assert_eq!(records[2].ttl(), 300);
        assert_eq!(records[2].name().to_fqdn(), "simple.zn.");
    }

    #[test]
    fn parses_relative_fixture() {
        let records = parse_fixture_file("relative.zn");
        assert_eq!(records.len(), 4);
        assert_eq!(records[0].name().to_fqdn(), "simple.zn.");
        assert_eq!(records[1].name().to_fqdn(), "simple.zn.");
        assert_eq!(records[2].name().to_fqdn(), "info.simple.zn.");
        let RData::MX(mx) = records[2].data() else {
            panic!("expected MX record");
        };
        assert_eq!(mx.preference(), 10);
        assert_eq!(mx.exchange().to_fqdn(), "mail.simple.zn.");
        assert_eq!(records[3].name().to_fqdn(), "mail.simple.zn.");
    }

    #[test]
    fn parses_brackets_and_comments_fixture() {
        let records = parse_fixture_file("brackets_and_comments.zn");
        assert_eq!(records.len(), 1);
        let RData::SOA(soa) = records[0].data() else {
            panic!("expected SOA record");
        };
        assert_eq!(soa.mname().to_fqdn(), "ns1.simple.zn.");
        assert_eq!(soa.rname().to_fqdn(), "hostmaster.simple.zn.");
        assert_eq!(soa.serial(), 2024090906);
    }

    #[test]
    fn rejects_escape_error_fixture() {
        let err = parse_file(fixture_path("escape_error.zn"), &ParseOptions::default())
            .expect_err("fixture should be rejected");
        assert!(
            err.to_string()
                .contains("quoted token must be followed by whitespace")
        );
    }

    #[test]
    fn parses_escaped_data_fixture() {
        let records = parse_fixture_file("escaped_data.zn");
        assert_eq!(records.len(), 3);
        assert_eq!(txt_chunks(&records[0]), vec!["foo bar\"baz", "foo bar"]);
        assert_eq!(txt_chunks(&records[1]), vec!["foo\"", "foo", ""]);
        assert_eq!(
            txt_chunks(&records[2]),
            vec!["\"", "\\foo", "foobar", "foo bar"]
        );
    }

    #[test]
    fn parses_case_insensitive_fixture() {
        let records = parse_fixture_file("lc_and_uc.zn");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].class(), DNSClass::IN);
        assert_eq!(records[0].rr_type(), RecordType::SOA);
        assert!(
            records[0]
                .name()
                .to_fqdn()
                .eq_ignore_ascii_case("simple.zn.")
        );
    }

    #[test]
    fn parses_quotes_fixture() {
        let records = parse_fixture_file("quotes.zn");
        assert_eq!(records.len(), 1);
        assert_eq!(
            txt_chunks(&records[0]),
            vec!["first quote", "Second QUOTE", "3. qt"]
        );
    }

    #[test]
    fn parses_anonymous_type_fixture() {
        let records = parse_fixture_file("anonymous_type.zn");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].rr_type(), RecordType::Unknown(65535));
        assert_eq!(records[1].rr_type(), RecordType::Unknown(65534));
        assert!(matches!(
            records[0].data(),
            RData::Unknown { rr_type: 65535, data } if data == &vec![0x01, 0x02, 0xFF, 0xFE, 0xFC]
        ));
        assert!(matches!(
            records[1].data(),
            RData::Unknown { rr_type: 65534, data } if data == &vec![0x01, 0x02, 0x03, 0x04, 0xAB, 0xCD]
        ));
    }

    #[test]
    fn supports_hash_comments_and_owner_inheritance() {
        let input = "example.com. 60 IN TXT \"a\" # comment\n\tIN TXT \"b\"\n";
        let records = parse_str(input, &ParseOptions::default()).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].name().to_fqdn(), "example.com.");
    }

    #[test]
    fn supports_include_and_generate() {
        let dir = temp_dir();
        let child = dir.join("child.zone");
        fs::write(&child, "$ORIGIN child.example.\napi 60 IN A 1.1.1.2\n").unwrap();

        let input = format!(
            "$ORIGIN example.com.\n$INCLUDE {}\n$GENERATE 1-2 host$ 60 IN A 192.0.2.$\n",
            child.display()
        );
        let records = parse_str(&input, &ParseOptions::default()).unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].name().to_fqdn(), "api.child.example.");
        assert_eq!(records[1].name().to_fqdn(), "host1.example.com.");
        assert_eq!(records[2].name().to_fqdn(), "host2.example.com.");
    }

    #[test]
    fn preserves_windows_backslashes_in_include_path() {
        let token = Token {
            raw: r"C:\Users\tester\AppData\Local\Temp\child.zone".to_string(),
            quoted: false,
        };
        assert_eq!(
            token.decode_include_path().unwrap(),
            r"C:\Users\tester\AppData\Local\Temp\child.zone"
        );
    }

    #[test]
    fn decodes_escaped_spaces_in_include_path() {
        let token = Token {
            raw: r"dir\ with\ spaces/child.zone".to_string(),
            quoted: false,
        };
        assert_eq!(
            token.decode_include_path().unwrap(),
            "dir with spaces/child.zone"
        );
    }

    #[test]
    fn supports_parse_options_initial_origin_and_default_ttl() {
        let options = ParseOptions::default()
            .with_initial_origin(Name::from_ascii("example.com.").unwrap())
            .with_default_ttl(1234);

        let records = parse_str("www IN A 1.1.1.1\n", &options).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name().to_fqdn(), "www.example.com.");
        assert_eq!(records[0].ttl(), 1234);
    }

    #[test]
    fn supports_parse_options_base_dir_for_relative_include() {
        let dir = temp_dir();
        let child = dir.join("child.zone");
        fs::write(&child, "$ORIGIN child.example.\napi IN A 192.0.2.10\n").unwrap();

        let input = "$INCLUDE child.zone\n";
        let options = ParseOptions::default().with_base_dir(dir);
        let records = parse_str(input, &options).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name().to_fqdn(), "api.child.example.");
        assert_eq!(records[0].ttl(), 3600);
    }

    #[test]
    fn supports_relative_include_from_source_file_parent() {
        let dir = temp_dir();
        let root = dir.join("root.zone");
        let child = dir.join("child.zone");
        fs::write(&child, "$ORIGIN child.example.\napi IN A 192.0.2.20\n").unwrap();
        fs::write(&root, "$INCLUDE child.zone\n").unwrap();

        let records = parse_file(root, &ParseOptions::default()).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name().to_fqdn(), "api.child.example.");
    }

    #[test]
    fn supports_include_origin_override_argument() {
        let dir = temp_dir();
        let child = dir.join("child.zone");
        fs::write(&child, "api IN A 192.0.2.30\n").unwrap();

        let input = "$ORIGIN example.com.\n$INCLUDE child.zone child.example.\n";
        let options = ParseOptions::default().with_base_dir(dir);
        let records = parse_str(input, &options).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name().to_fqdn(), "api.child.example.");
    }

    #[test]
    fn rejects_relative_include_without_base_dir() {
        let err =
            parse_str("$INCLUDE child.zone\n", &ParseOptions::default()).expect_err("must fail");
        assert!(matches!(err, ZoneParseError::RelativeIncludeWithoutBaseDir));
    }

    #[test]
    fn rejects_include_depth_over_limit() {
        let dir = temp_dir();
        let root = dir.join("root.zone");
        let child = dir.join("child.zone");
        let grandchild = dir.join("grandchild.zone");
        fs::write(&root, "$INCLUDE child.zone\n").unwrap();
        fs::write(&child, "$INCLUDE grandchild.zone\n").unwrap();
        fs::write(&grandchild, "$ORIGIN deep.example.\napi IN A 192.0.2.40\n").unwrap();

        let err = parse_file(root, &ParseOptions::default().with_max_include_depth(1))
            .expect_err("nested include should exceed the configured limit");
        assert!(matches!(
            err,
            ZoneParseError::IncludeDepthExceeded { max_depth: 1 }
        ));
    }

    #[test]
    fn supports_generate_step_and_format_modifiers() {
        let input = r#"
$ORIGIN example.com.
$GENERATE 1-3/2 host${0,3,d} 1h IN A 192.0.2.$
$GENERATE 15-16 hex${0,2,x} IN A 192.0.2.$
"#;
        let records = parse_str(input, &ParseOptions::default()).unwrap();
        assert_eq!(records.len(), 4);
        assert_eq!(records[0].name().to_fqdn(), "host001.example.com.");
        assert_eq!(records[1].name().to_fqdn(), "host003.example.com.");
        assert_eq!(records[0].ttl(), 3600);
        assert_eq!(records[2].name().to_fqdn(), "hex0f.example.com.");
        assert_eq!(records[3].name().to_fqdn(), "hex10.example.com.");
    }

    #[test]
    fn supports_compound_ttl_units_and_explicit_zero_ttl() {
        let input = r#"
$ORIGIN example.com.
long 1w2d3h4m5s IN A 192.0.2.1
zero 0 IN A 192.0.2.2
"#;
        let records = parse_str(input, &ParseOptions::default()).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].ttl(), 788645);
        assert_eq!(records[1].ttl(), 0);
    }

    #[test]
    fn supports_rfc3597_generic_known_type() {
        let input = "example.com. 60 IN A \\# 4 01020304\n";
        let records = parse_str(input, &ParseOptions::default()).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].rr_type(), RecordType::A);
    }
}
