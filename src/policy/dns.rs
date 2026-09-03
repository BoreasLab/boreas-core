//! Pure DNS parsing, policy, provenance, and ECH/ALPN response rewriting.
//! Names use fixed storage, pointers move strictly backwards, verdict
//! provenance travels with answers, and ECH policy is per host. Upstream I/O
//! lives in the shell.

use std::{
    collections::HashSet,
    error::Error,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::Range,
};

use crate::wire::{Bounded, Reader};

/// UDP and TCP port served by DNS interception.
pub const DNS_PORT: u16 = 53;

/// RFC 1035 section 2.3.4 presentation-form limit.
pub const MAX_NAME_CHARS: usize = 253;

/// RFC 1035 section 2.3.4 label limit.
const MAX_LABEL_LEN: usize = 63;

const HEADER_BYTES: usize = 12;

/// Header offset of `ANCOUNT`, patched after answer emission.
const ANCOUNT_AT: usize = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsError {
    /// The message ended inside a field.
    Truncated,
    /// A label length byte used a reserved prefix.
    ReservedLabel,
    /// A compression pointer did not point strictly backwards, so decoding would not be bounded.
    ForwardPointer,
    /// The decoded name exceeds the RFC 1035 limit.
    NameTooLong,
    /// A label contains `.`, making normalized suffix matching ambiguous.
    SeparatorInLabel,
    /// OPCODE is not QUERY; an UPDATE or NOTIFY is not a question to plan.
    NotAQuery,
    /// The message carries no question.
    NoQuestion,
    /// More than one question; RFC 9619 section 4 forbids this for `OPCODE=0`.
    MultipleQuestions(u16),
    /// The question uses compression and cannot be copied verbatim safely.
    CompressedQuestion,
    /// SvcParam keys are not strictly increasing as RFC 9460 section 2.2 requires.
    SvcParamsOutOfOrder,
    /// An `alpn` value carries a zero-length identifier.
    EmptyAlpnIdentifier,
    /// The output buffer cannot hold the message.
    OutputTooSmall,
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "message ended inside a field",
            Self::ReservedLabel => "reserved label length prefix",
            Self::NotAQuery => "opcode is not a standard query",
            Self::ForwardPointer => "compression pointer does not point backwards",
            Self::NameTooLong => "name exceeds 253 characters",
            Self::SeparatorInLabel => "label contains the presentation separator",
            Self::NoQuestion => "message carries no question",
            Self::MultipleQuestions(count) => {
                return write!(f, "message carries {count} questions, not one");
            }
            Self::CompressedQuestion => "question name uses compression",
            Self::SvcParamsOutOfOrder => "SvcParam keys are not strictly increasing",
            Self::EmptyAlpnIdentifier => "ALPN list carries a zero-length identifier",
            Self::OutputTooSmall => "output buffer is too small",
        })
    }
}

impl Error for DnsError {}

/// Normalized domain name in fixed inline storage.
///
/// ASCII is lowercased per RFC 4343; labels use `.`, the root is empty, and
/// non-ASCII bytes compare bytewise without text-encoding assumptions.
#[derive(Clone, Copy)]
pub struct Name {
    bytes: [u8; MAX_NAME_CHARS],
    len: u8,
}

impl Name {
    pub const ROOT: Self = Self {
        bytes: [0; MAX_NAME_CHARS],
        len: 0,
    };

    /// Normalizes a presentation-form name, rejecting values wire decoding cannot represent.
    pub fn parse(text: &str) -> Option<Self> {
        let trimmed = text.strip_suffix('.').unwrap_or(text);
        if trimmed.len() > MAX_NAME_CHARS {
            return None;
        }
        // An empty label would be the wire terminator and could collapse `a..b` to `a`.
        if !trimmed.is_empty()
            && trimmed
                .split('.')
                .any(|label| label.is_empty() || label.len() > MAX_LABEL_LEN)
        {
            return None;
        }
        let mut bytes = [0; MAX_NAME_CHARS];
        bytes[..trimmed.len()].copy_from_slice(trimmed.as_bytes());
        bytes.make_ascii_lowercase();
        Some(Self {
            bytes,
            len: trimmed.len() as u8,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    pub fn is_root(&self) -> bool {
        self.len == 0
    }

    /// Yields the name and its parent suffixes, most specific first. O(labels).
    pub fn suffixes(&self) -> impl Iterator<Item = &[u8]> {
        let full = self.as_bytes();
        std::iter::successors(
            (!full.is_empty()).then_some(full),
            |suffix: &&[u8]| -> Option<&[u8]> {
                suffix
                    .iter()
                    .position(|byte| *byte == b'.')
                    .map(|dot| &suffix[dot + 1..])
            },
        )
    }

    /// Rebuilds a suffix already normalized by [`Name::suffixes`].
    fn from_normalized(normalized: &[u8]) -> Self {
        let mut bytes = [0; MAX_NAME_CHARS];
        bytes[..normalized.len()].copy_from_slice(normalized);
        Self {
            bytes,
            len: normalized.len() as u8,
        }
    }

    /// Wire length including label prefixes and the root terminator.
    pub fn wire_len(&self) -> usize {
        if self.is_root() {
            1
        } else {
            usize::from(self.len) + 2
        }
    }

    /// Decodes a name and returns bytes consumed at its original position.
    fn read(message: &[u8], at: usize) -> Result<(Self, usize), DnsError> {
        let mut bytes = [0; MAX_NAME_CHARS];
        let mut len = 0usize;
        let mut reader = Reader::at(message, at).ok_or(DnsError::Truncated)?;
        let mut consumed: Option<usize> = None;

        loop {
            let cursor = reader.position();
            let length = reader.u8().ok_or(DnsError::Truncated)?;
            match length & 0xc0 {
                0x00 if length == 0 => break,
                0x00 => {
                    let label = reader
                        .take(usize::from(length))
                        .ok_or(DnsError::Truncated)?;
                    if label.contains(&b'.') {
                        return Err(DnsError::SeparatorInLabel);
                    }
                    let separator = usize::from(len > 0);
                    if len + separator + label.len() > MAX_NAME_CHARS {
                        return Err(DnsError::NameTooLong);
                    }
                    if separator == 1 {
                        bytes[len] = b'.';
                        len += 1;
                    }
                    bytes[len..len + label.len()].copy_from_slice(label);
                    bytes[len..len + label.len()].make_ascii_lowercase();
                    len += label.len();
                }
                0xc0 => {
                    let low = reader.u8().ok_or(DnsError::Truncated)?;
                    let target = usize::from(u16::from_be_bytes([length & 0x3f, low]));
                    // Strict decrease bounds traversal without a visited set.
                    if target >= cursor {
                        return Err(DnsError::ForwardPointer);
                    }
                    consumed.get_or_insert(reader.position());
                    reader = Reader::at(message, target).ok_or(DnsError::Truncated)?;
                }
                _ => return Err(DnsError::ReservedLabel),
            }
        }

        Ok((
            Self {
                bytes,
                len: len as u8,
            },
            consumed.unwrap_or(reader.position()) - at,
        ))
    }

    fn write(&self, out: &mut [u8], at: usize) -> Result<usize, DnsError> {
        let mut writer = Bounded::at(out, at).ok_or(DnsError::OutputTooSmall)?;
        if !self.is_root() {
            for label in self.as_bytes().split(|byte| *byte == b'.') {
                writer.vector_u8(label);
            }
        }
        writer.u8(0);
        writer.finish().ok_or(DnsError::OutputTooSmall)
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Name {}

impl std::hash::Hash for Name {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

/// RFC 1035 section 5.1 presentation form with control bytes escaped as `\DDD`.
impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            return f.write_str(".");
        }
        for byte in self.as_bytes() {
            match byte {
                0x21..=0x5b | 0x5d..=0x7e => f.write_str(std::str::from_utf8(&[*byte]).unwrap())?,
                _ => write!(f, "\\{byte:03}")?,
            }
        }
        Ok(())
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Name({self})")
    }
}

/// Record types relevant to policy, plus an open `Other` case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RecordType {
    A,
    Aaaa,
    /// RFC 9460 HTTPS record carrying ALPN and ECH parameters.
    Https,
    /// RFC 9460 SVCB record carrying the same parameter shape.
    Svcb,
    Other(u16),
}

impl RecordType {
    pub fn from_wire(value: u16) -> Self {
        match value {
            1 => Self::A,
            28 => Self::Aaaa,
            64 => Self::Svcb,
            65 => Self::Https,
            other => Self::Other(other),
        }
    }

    pub fn to_wire(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Aaaa => 28,
            Self::Svcb => 64,
            Self::Https => 65,
            Self::Other(other) => other,
        }
    }

    pub fn carries_svc_params(self) -> bool {
        matches!(self, Self::Https | Self::Svcb)
    }
}

const FLAG_RESPONSE: u16 = 0x8000;
const FLAG_RECURSION_DESIRED: u16 = 0x0100;
const FLAG_RECURSION_AVAILABLE: u16 = 0x0080;
const FLAG_TRUNCATED: u16 = 0x0200;
const FLAG_AUTHENTIC_DATA: u16 = 0x0020;
const FLAG_CHECKING_DISABLED: u16 = 0x0010;
const OPCODE_MASK: u16 = 0x7800;
/// RFC 6891 OPT pseudo-record type.
const OPT: u16 = 41;
const RCODE_MASK: u16 = 0x000f;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rcode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    Other(u16),
}

impl Rcode {
    pub fn from_wire(value: u16) -> Self {
        match value & RCODE_MASK {
            0 => Self::NoError,
            1 => Self::FormatError,
            2 => Self::ServerFailure,
            3 => Self::NameError,
            other => Self::Other(other),
        }
    }

    pub fn to_wire(self) -> u16 {
        match self {
            Self::NoError => 0,
            Self::FormatError => 1,
            Self::ServerFailure => 2,
            Self::NameError => 3,
            Self::Other(other) => other & RCODE_MASK,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Question {
    pub name: Name,
    pub qtype: RecordType,
    pub qclass: u16,
}

/// Resource record with borrowed RDATA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceRecord<'a> {
    pub name: Name,
    pub rtype: RecordType,
    pub class: u16,
    pub ttl: u32,
    pub rdata: &'a [u8],
}

/// Parsed DNS message with borrowed, lazily walked answers.
#[derive(Clone, Copy, Debug)]
pub struct Message<'a> {
    bytes: &'a [u8],
    id: u16,
    flags: u16,
    answer_count: u16,
    authority_count: u16,
    additional_count: u16,
    question: Question,
    /// Original question bytes; compressed questions are refused before copying.
    question_bytes: &'a [u8],
    answers_at: usize,
}

impl<'a> Message<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, DnsError> {
        let mut reader = Reader::new(bytes);
        let (Some(id), Some(flags), Some(question_count), Some(answer_count)) =
            (reader.u16(), reader.u16(), reader.u16(), reader.u16())
        else {
            return Err(DnsError::Truncated);
        };
        let (Some(authority_count), Some(additional_count)) = (reader.u16(), reader.u16()) else {
            return Err(DnsError::Truncated);
        };
        if flags & OPCODE_MASK != 0 {
            return Err(DnsError::NotAQuery);
        }
        match question_count {
            0 => return Err(DnsError::NoQuestion),
            1 => {}
            count => return Err(DnsError::MultipleQuestions(count)),
        }

        let question_at = reader.position();
        let (name, name_len) = Name::read(bytes, question_at)?;
        if name_len != name.wire_len() {
            return Err(DnsError::CompressedQuestion);
        }
        reader.skip(name_len).ok_or(DnsError::Truncated)?;
        let (Some(qtype), Some(qclass)) = (reader.u16(), reader.u16()) else {
            return Err(DnsError::Truncated);
        };

        Ok(Self {
            bytes,
            id,
            flags,
            answer_count,
            authority_count,
            additional_count,
            question: Question {
                name,
                qtype: RecordType::from_wire(qtype),
                qclass,
            },
            question_bytes: &bytes[question_at..reader.position()],
            answers_at: reader.position(),
        })
    }

    pub fn id(&self) -> u16 {
        self.id
    }

    pub fn question(&self) -> &Question {
        &self.question
    }

    pub fn rcode(&self) -> Rcode {
        Rcode::from_wire(self.flags)
    }

    pub fn is_response(&self) -> bool {
        self.flags & FLAG_RESPONSE != 0
    }

    pub fn is_truncated(&self) -> bool {
        self.flags & FLAG_TRUNCATED != 0
    }

    pub fn recursion_desired(&self) -> bool {
        self.flags & FLAG_RECURSION_DESIRED != 0
    }

    /// RFC 4035 section 3.2.3: the resolver validated the answer.
    pub fn authentic_data(&self) -> bool {
        self.flags & FLAG_AUTHENTIC_DATA != 0
    }

    /// RFC 4035 section 3.2.2: the client wants no validation done for it.
    pub fn checking_disabled(&self) -> bool {
        self.flags & FLAG_CHECKING_DISABLED != 0
    }

    /// Lazily walks borrowed answer records; malformed records yield errors.
    pub fn answers(&self) -> Answers<'a> {
        Answers {
            message: self.bytes,
            cursor: self.answers_at,
            remaining: self.answer_count,
        }
    }

    /// The UDP payload size the sender's OPT record advertises (RFC 6891
    /// section 6.2.3), or `None` without one. O(records).
    pub fn udp_payload_size(&self) -> Option<u16> {
        let additional_at = Answers {
            message: self.bytes,
            cursor: self.answers_at,
            remaining: self.answer_count.checked_add(self.authority_count)?,
        }
        .end()
        .ok()?;
        Answers {
            message: self.bytes,
            cursor: additional_at,
            remaining: self.additional_count,
        }
        .find_map(|record| {
            record
                .ok()
                .filter(|record| record.rtype.to_wire() == OPT)
                .map(|record| record.class)
        })
    }
}

pub struct Answers<'a> {
    message: &'a [u8],
    cursor: usize,
    remaining: u16,
}

impl<'a> Iterator for Answers<'a> {
    type Item = Result<ResourceRecord<'a>, DnsError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        Some(self.read())
    }
}

impl<'a> Answers<'a> {
    /// The offset just past the last record.
    fn end(mut self) -> Result<usize, DnsError> {
        while self.remaining > 0 {
            self.remaining -= 1;
            self.read()?;
        }
        Ok(self.cursor)
    }

    fn read(&mut self) -> Result<ResourceRecord<'a>, DnsError> {
        let (name, name_len) = Name::read(self.message, self.cursor)?;
        let mut reader =
            Reader::at(self.message, self.cursor + name_len).ok_or(DnsError::Truncated)?;
        let (Some(rtype), Some(class), Some(ttl)) = (reader.u16(), reader.u16(), reader.u32())
        else {
            return Err(DnsError::Truncated);
        };
        let rdata = reader.vector_u16().ok_or(DnsError::Truncated)?;
        self.cursor = reader.position();

        Ok(ResourceRecord {
            name,
            rtype: RecordType::from_wire(rtype),
            class,
            ttl,
            rdata,
        })
    }
}

/// RFC 9460 section 14.3.2 `ech` SvcParam key.
pub const SVCPARAM_ECH: u16 = 5;
/// RFC 9460 section 14.3.2 `alpn` SvcParam key.
pub const SVCPARAM_ALPN: u16 = 1;
/// RFC 9460 section 14.3.2 `no-default-alpn` SvcParam key.
pub const SVCPARAM_NO_DEFAULT_ALPN: u16 = 2;

/// Whether an ALPN identifier names HTTP/3, including draft `h3-*` identifiers.
fn is_h3(identifier: &[u8]) -> bool {
    identifier == b"h3" || identifier.starts_with(b"h3-")
}

/// Returns the contiguous removal range for an HTTPS/SVCB HTTP/3 ALPN.
/// O(parameters + ALPN identifiers), allocation-free.
pub fn h3_alpn_param(rdata: &[u8]) -> Result<Option<Range<usize>>, DnsError> {
    let mut found: Option<Range<usize>> = None;
    for param in svc_params(rdata)? {
        let param = param?;
        match param.key {
            SVCPARAM_ALPN if alpn_offers_h3(param.value)? => found = Some(param.at),
            SVCPARAM_NO_DEFAULT_ALPN => {
                if let Some(range) = found.as_mut() {
                    range.end = param.at.end;
                }
            }
            _ => {}
        }
    }
    Ok(found)
}

/// Parses RFC 9460 section 7.1 length-prefixed ALPN identifiers.
fn alpn_offers_h3(value: &[u8]) -> Result<bool, DnsError> {
    let mut cursor = 0;
    while cursor < value.len() {
        let length = usize::from(value[cursor]);
        if length == 0 {
            return Err(DnsError::EmptyAlpnIdentifier);
        }
        let identifier = value
            .get(cursor + 1..cursor + 1 + length)
            .ok_or(DnsError::Truncated)?;
        if is_h3(identifier) {
            return Ok(true);
        }
        cursor += 1 + length;
    }
    Ok(false)
}

/// SvcParam and its occupied RDATA range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SvcParam<'a> {
    pub key: u16,
    pub value: &'a [u8],
    pub at: Range<usize>,
}

/// Walks SvcParams in HTTPS/SVCB RDATA. RFC 9460 section 2.2 makes TargetName
/// uncompressible, so RDATA is sufficient input.
pub fn svc_params(rdata: &[u8]) -> Result<SvcParams<'_>, DnsError> {
    let mut cursor = 2;
    if rdata.len() < cursor {
        return Err(DnsError::Truncated);
    }
    loop {
        let length = usize::from(*rdata.get(cursor).ok_or(DnsError::Truncated)?);
        if length & 0xc0 != 0 {
            return Err(DnsError::ReservedLabel);
        }
        cursor += 1 + length;
        if length == 0 {
            break;
        }
    }
    if cursor > rdata.len() {
        return Err(DnsError::Truncated);
    }
    Ok(SvcParams {
        rdata,
        cursor,
        previous: None,
    })
}

pub struct SvcParams<'a> {
    rdata: &'a [u8],
    cursor: usize,
    previous: Option<u16>,
}

impl<'a> Iterator for SvcParams<'a> {
    type Item = Result<SvcParam<'a>, DnsError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor >= self.rdata.len() {
            return None;
        }
        Some(self.read())
    }
}

impl<'a> SvcParams<'a> {
    fn read(&mut self) -> Result<SvcParam<'a>, DnsError> {
        let start = self.cursor;
        let mut reader = Reader::at(self.rdata, start).ok_or(DnsError::Truncated)?;
        let Some(key) = reader.u16() else {
            return Err(DnsError::Truncated);
        };
        let value = reader.vector_u16().ok_or(DnsError::Truncated)?;
        let end = reader.position();
        if self.previous.is_some_and(|previous| key <= previous) {
            return Err(DnsError::SvcParamsOutOfOrder);
        }
        self.previous = Some(key);
        self.cursor = end;
        Ok(SvcParam {
            key,
            value,
            at: start..end,
        })
    }
}

/// Returns the `ech` SvcParam range after validating all parameters.
pub fn ech_param(rdata: &[u8]) -> Result<Option<Range<usize>>, DnsError> {
    let mut found = None;
    for param in svc_params(rdata)? {
        let param = param?;
        if param.key == SVCPARAM_ECH {
            found = Some(param.at);
        }
    }
    Ok(found)
}

/// DNS action for one host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostVerdict {
    /// Refuse without consulting upstream.
    Blocked,
    /// Resolve without rewriting ECH.
    Allowed,
    /// Resolve while stripping ECH for local TLS interception.
    Inspected,
}

/// Host verdict and matching rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Judgment {
    pub verdict: HostVerdict,
    /// Matching suffix, if any.
    pub matched: Option<Name>,
}

/// Host rules indexed by normalized suffix. Exceptions win, then the most
/// specific rule, with blocking before inspection at equal specificity.
/// Lookup is O(labels) expected time; storage is O(distinct rule hosts).
#[derive(Default)]
pub struct HostPolicy {
    allowed: HashSet<Box<[u8]>>,
    blocked: HashSet<Box<[u8]>>,
    inspected: HashSet<Box<[u8]>>,
}

impl HostPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a blocking rule; returns `false` for an unrepresentable name.
    pub fn block(&mut self, name: &str) -> bool {
        Self::insert(&mut self.blocked, name)
    }

    /// Adds an exception overriding matching block and inspection rules.
    pub fn allow(&mut self, name: &str) -> bool {
        Self::insert(&mut self.allowed, name)
    }

    /// Adds an inspection rule.
    pub fn inspect(&mut self, name: &str) -> bool {
        Self::insert(&mut self.inspected, name)
    }

    pub fn len(&self) -> RuleCounts {
        RuleCounts {
            allowed: self.allowed.len(),
            blocked: self.blocked.len(),
            inspected: self.inspected.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.allowed.is_empty() && self.blocked.is_empty() && self.inspected.is_empty()
    }

    fn insert(set: &mut HashSet<Box<[u8]>>, name: &str) -> bool {
        match Name::parse(name) {
            Some(parsed) if !parsed.is_root() => {
                set.insert(parsed.as_bytes().into());
                true
            }
            _ => false,
        }
    }

    /// Adds an already-normalized name without reparsing it.
    pub(crate) fn insert_name(&mut self, verdict: HostVerdict, name: &Name) {
        let set = match verdict {
            HostVerdict::Allowed => &mut self.allowed,
            HostVerdict::Blocked => &mut self.blocked,
            HostVerdict::Inspected => &mut self.inspected,
        };
        set.insert(name.as_bytes().into());
    }

    pub fn judge(&self, name: &Name) -> Judgment {
        let mut decided = None;
        for suffix in name.suffixes() {
            if self.allowed.contains(suffix) {
                return Judgment {
                    verdict: HostVerdict::Allowed,
                    matched: Some(Name::from_normalized(suffix)),
                };
            }
            if decided.is_none() {
                for (set, verdict) in [
                    (&self.blocked, HostVerdict::Blocked),
                    (&self.inspected, HostVerdict::Inspected),
                ] {
                    if set.contains(suffix) {
                        decided = Some(Judgment {
                            verdict,
                            matched: Some(Name::from_normalized(suffix)),
                        });
                        break;
                    }
                }
            }
        }
        decided.unwrap_or(Judgment {
            verdict: HostVerdict::Allowed,
            matched: None,
        })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RuleCounts {
    pub allowed: usize,
    pub blocked: usize,
    pub inspected: usize,
}

/// ECH rewrite policy for a host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EchPolicy {
    /// Preserve the published ECH configuration.
    Preserve,
    /// Remove ECH from this host's answers.
    Strip,
}

/// ALPN rewrite policy for a host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlpnPolicy {
    /// Preserve the published ALPN.
    Preserve,
    /// Remove HTTP/3 so inspected traffic reaches the TLS interceptor over HTTP/2.
    StripH3,
}

/// Strips ECH if and only if the host is inspected.
pub fn ech_policy(verdict: HostVerdict) -> EchPolicy {
    match verdict {
        HostVerdict::Inspected => EchPolicy::Strip,
        HostVerdict::Allowed | HostVerdict::Blocked => EchPolicy::Preserve,
    }
}

/// Strips HTTP/3 ALPN if and only if the host is inspected.
pub fn alpn_policy(verdict: HostVerdict) -> AlpnPolicy {
    match verdict {
        HostVerdict::Inspected => AlpnPolicy::StripH3,
        HostVerdict::Allowed | HostVerdict::Blocked => AlpnPolicy::Preserve,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnswerPolicy {
    pub ech: EchPolicy,
    pub alpn: AlpnPolicy,
}

impl AnswerPolicy {
    /// Whether resolved addresses require the UDP/443 steering backstop.
    pub fn steers(self) -> bool {
        matches!(self.alpn, AlpnPolicy::StripH3)
    }
}

pub fn answer_policy(verdict: HostVerdict) -> AnswerPolicy {
    AnswerPolicy {
        ech: ech_policy(verdict),
        alpn: alpn_policy(verdict),
    }
}

/// Action for one intercepted query, chosen before upstream access.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryPlan {
    /// Answer locally with [`write_refusal`]; no query leaves the device.
    Refuse { rule: Name },
    /// Send it upstream, then run [`write_response`] with this policy.
    Forward { policy: AnswerPolicy },
}

/// Plans one intercepted query.
pub fn plan_query(question: &Question, policy: &HostPolicy) -> QueryPlan {
    let judgment = policy.judge(&question.name);
    match judgment.verdict {
        HostVerdict::Blocked => QueryPlan::Refuse {
            rule: judgment.matched.unwrap_or(Name::ROOT),
        },
        verdict => QueryPlan::Forward {
            policy: answer_policy(verdict),
        },
    }
}

/// Upstream transport used for resolution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Upstream {
    Do53,
    DoT,
    DoH,
    DoQ,
}

impl fmt::Display for Upstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Do53 => "Do53",
            Self::DoT => "DoT",
            Self::DoH => "DoH",
            Self::DoQ => "DoQ",
        })
    }
}

/// Answer provenance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provenance {
    /// Synthesized locally.
    Policy,
    /// Resolved upstream.
    Upstream(Upstream),
    /// Served from a reply this upstream gave earlier, within its TTL.
    Cached(Upstream),
}

/// ECH outcome for one response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EchOutcome {
    /// No answer carried ECH.
    Absent,
    /// Published and preserved.
    Preserved,
    /// Removed from `count` answers.
    Stripped { count: u16 },
}

/// HTTP/3 ALPN outcome for one response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlpnOutcome {
    /// No answer advertised HTTP/3.
    Absent,
    /// Advertised and preserved.
    Preserved,
    /// Removed from `count` answers.
    Steered { count: u16 },
}

/// Resolution result and policy provenance for one query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resolution {
    pub name: Name,
    pub qtype: RecordType,
    pub rcode: Rcode,
    pub answers: u16,
    pub provenance: Provenance,
    /// Matching rule, if any.
    pub rule: Option<Name>,
    pub ech: EchOutcome,
    pub alpn: AlpnOutcome,
}

/// Borrowed RDATA represented as up to three slices after two removals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rdata<'a> {
    parts: [&'a [u8]; 3],
}

impl<'a> Rdata<'a> {
    pub fn verbatim(bytes: &'a [u8]) -> Self {
        Self {
            parts: [bytes, &[], &[]],
        }
    }

    /// Returns `None` when `cut` is outside `bytes`.
    pub fn without(bytes: &'a [u8], cut: Range<usize>) -> Option<Self> {
        Some(Self {
            parts: [bytes.get(..cut.start)?, bytes.get(cut.end..)?, &[]],
        })
    }

    /// Removes two ordered, disjoint ranges.
    pub fn without_both(
        bytes: &'a [u8],
        first: Range<usize>,
        second: Range<usize>,
    ) -> Option<Self> {
        if first.end > second.start {
            return None;
        }
        Some(Self {
            parts: [
                bytes.get(..first.start)?,
                bytes.get(first.end..second.start)?,
                bytes.get(second.end..)?,
            ],
        })
    }

    /// Removes present ranges in source order.
    fn without_all(
        bytes: &'a [u8],
        first: Option<Range<usize>>,
        second: Option<Range<usize>>,
    ) -> Option<Self> {
        match (first, second) {
            (None, None) => Some(Self::verbatim(bytes)),
            (Some(only), None) | (None, Some(only)) => Self::without(bytes, only),
            (Some(left), Some(right)) if left.start <= right.start => {
                Self::without_both(bytes, left, right)
            }
            (Some(left), Some(right)) => Self::without_both(bytes, right, left),
        }
    }

    pub fn len(&self) -> usize {
        self.parts.iter().map(|part| part.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Summary of response rewriting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rewritten {
    pub len: usize,
    pub answers: u16,
    pub ech: EchOutcome,
    pub alpn: AlpnOutcome,
}

/// Writes a response using the client's transaction and the upstream result.
/// Names stay uncompressed because RDATA removal would invalidate downstream
/// compression pointers; stub clients need no authority or additional sections.
pub fn write_response(
    out: &mut [u8],
    query: &Message<'_>,
    upstream: &Message<'_>,
    policy: AnswerPolicy,
) -> Result<Rewritten, DnsError> {
    write_response_aged(out, query, upstream, policy, 0)
}

/// As [`write_response`], for an upstream reply remembered `age` seconds:
/// every TTL counts down by that much (RFC 2181 section 8).
pub fn write_response_aged(
    out: &mut [u8],
    query: &Message<'_>,
    upstream: &Message<'_>,
    policy: AnswerPolicy,
    age: u32,
) -> Result<Rewritten, DnsError> {
    let mut flags = FLAG_RESPONSE | FLAG_RECURSION_AVAILABLE | upstream.rcode().to_wire();
    if query.recursion_desired() {
        flags |= FLAG_RECURSION_DESIRED;
    }
    if query.checking_disabled() {
        flags |= FLAG_CHECKING_DISABLED;
    }
    if upstream.authentic_data() {
        flags |= FLAG_AUTHENTIC_DATA;
    }
    if upstream.is_truncated() {
        flags |= FLAG_TRUNCATED;
    }

    let mut cursor = write_header_and_question(out, query, flags)?;
    let mut answers = 0u16;
    let (mut ech_seen, mut ech_stripped) = (false, 0u16);
    let (mut h3_seen, mut h3_stripped) = (false, 0u16);

    for answer in upstream.answers() {
        let answer = answer?;
        // Only SVCB-shaped records carry these parameters.
        let (ech_at, h3_at) = if answer.rtype.carries_svc_params() {
            (ech_param(answer.rdata)?, h3_alpn_param(answer.rdata)?)
        } else {
            (None, None)
        };
        ech_seen |= ech_at.is_some();
        h3_seen |= h3_at.is_some();

        let ech_cut = ech_at.filter(|_| policy.ech == EchPolicy::Strip);
        let h3_cut = h3_at.filter(|_| policy.alpn == AlpnPolicy::StripH3);
        ech_stripped += u16::from(ech_cut.is_some());
        h3_stripped += u16::from(h3_cut.is_some());
        let rdata = Rdata::without_all(answer.rdata, h3_cut, ech_cut).ok_or(DnsError::Truncated)?;

        let aged = ResourceRecord {
            ttl: answer.ttl.saturating_sub(age),
            ..answer
        };
        cursor = write_record(out, cursor, &aged, rdata)?;
        answers += 1;
    }

    // Patch `ancount` after emitting answers.
    let mut ancount = Bounded::at(out, ANCOUNT_AT).ok_or(DnsError::OutputTooSmall)?;
    ancount.u16(answers);
    ancount.finish().ok_or(DnsError::OutputTooSmall)?;
    Ok(Rewritten {
        len: cursor,
        answers,
        ech: match (ech_seen, ech_stripped) {
            (false, _) => EchOutcome::Absent,
            (true, 0) => EchOutcome::Preserved,
            (true, count) => EchOutcome::Stripped { count },
        },
        alpn: match (h3_seen, h3_stripped) {
            (false, _) => AlpnOutcome::Absent,
            (true, 0) => AlpnOutcome::Preserved,
            (true, count) => AlpnOutcome::Steered { count },
        },
    })
}

/// Appends `A` and `AAAA` answer addresses to `out`.
pub fn answer_addresses(message: &Message<'_>, out: &mut Vec<IpAddr>) -> Result<(), DnsError> {
    for answer in message.answers() {
        let answer = answer?;
        match answer.rtype {
            RecordType::A => {
                if let Some(octets) = answer.rdata.first_chunk::<4>() {
                    out.push(IpAddr::V4(Ipv4Addr::from(*octets)));
                }
            }
            RecordType::Aaaa => {
                if let Some(octets) = answer.rdata.first_chunk::<16>() {
                    out.push(IpAddr::V6(Ipv6Addr::from(*octets)));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Writes the header and question with TC set and no answers: the whole
/// answer did not fit the client's payload size, so it asks again over TCP
/// (RFC 1035 section 4.2.1).
pub fn write_truncated(out: &mut [u8], query: &Message<'_>) -> Result<usize, DnsError> {
    let mut flags = FLAG_RESPONSE | FLAG_RECURSION_AVAILABLE | FLAG_TRUNCATED;
    if query.recursion_desired() {
        flags |= FLAG_RECURSION_DESIRED;
    }
    write_header_and_question(out, query, flags)
}

/// Writes an `NXDOMAIN` response with no answers.
pub fn write_refusal(out: &mut [u8], query: &Message<'_>) -> Result<usize, DnsError> {
    let mut flags = FLAG_RESPONSE | FLAG_RECURSION_AVAILABLE | Rcode::NameError.to_wire();
    if query.recursion_desired() {
        flags |= FLAG_RECURSION_DESIRED;
    }
    write_header_and_question(out, query, flags)
}

/// Writes a `FORMERR` for a query whose header could be read and whose rest
/// could not (RFC 1035 section 4.1.1). No question is echoed: none parsed.
pub fn write_format_error(out: &mut [u8], query: &[u8]) -> Result<usize, DnsError> {
    let (Some(id), Some(flags)) = (query.first_chunk::<2>(), query.get(2..4)) else {
        return Err(DnsError::Truncated);
    };
    let flags = (u16::from_be_bytes([flags[0], flags[1]]) & FLAG_RECURSION_DESIRED)
        | FLAG_RESPONSE
        | Rcode::FormatError.to_wire();
    let mut writer = Bounded::at(out, 0).ok_or(DnsError::OutputTooSmall)?;
    writer.bytes(id).u16(flags).zeros(HEADER_BYTES - 4);
    writer.finish().ok_or(DnsError::OutputTooSmall)
}

/// Writes a visible `SERVFAIL` response for an upstream failure.
pub fn write_failure(out: &mut [u8], query: &Message<'_>) -> Result<usize, DnsError> {
    let mut flags = FLAG_RESPONSE | FLAG_RECURSION_AVAILABLE | Rcode::ServerFailure.to_wire();
    if query.recursion_desired() {
        flags |= FLAG_RECURSION_DESIRED;
    }
    write_header_and_question(out, query, flags)
}

fn write_header_and_question(
    out: &mut [u8],
    query: &Message<'_>,
    flags: u16,
) -> Result<usize, DnsError> {
    let mut writer = Bounded::at(out, 0).ok_or(DnsError::OutputTooSmall)?;
    writer
        .u16(query.id)
        .u16(flags)
        .u16(1) // qdcount: `Message::parse` accepts exactly one question
        .zeros(6) // ancount, nscount, arcount; ancount is patched later
        .bytes(query.question_bytes);
    writer.finish().ok_or(DnsError::OutputTooSmall)
}

fn write_record(
    out: &mut [u8],
    at: usize,
    record: &ResourceRecord<'_>,
    rdata: Rdata<'_>,
) -> Result<usize, DnsError> {
    let length = u16::try_from(rdata.len()).map_err(|_| DnsError::OutputTooSmall)?;
    let at = record.name.write(out, at)?;
    let mut writer = Bounded::at(out, at).ok_or(DnsError::OutputTooSmall)?;
    writer
        .u16(record.rtype.to_wire())
        .u16(record.class)
        .u32(record.ttl)
        // Parts are separate in memory but contiguous on the wire.
        .u16(length);
    for part in rdata.parts {
        writer.bytes(part);
    }
    writer.finish().ok_or(DnsError::OutputTooSmall)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire_name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        if !name.is_empty() {
            for label in name.split('.') {
                out.push(label.len() as u8);
                out.extend_from_slice(label.as_bytes());
            }
        }
        out.push(0);
        out
    }

    fn query(name: &str, qtype: RecordType, id: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&FLAG_RECURSION_DESIRED.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        out.extend_from_slice(&[0; 6]); // an, ns, ar
        out.extend_from_slice(&wire_name(name));
        out.extend_from_slice(&qtype.to_wire().to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // IN
        out
    }

    /// RFC 2181 section 8: a remembered answer's TTLs count down. RFC 4035:
    /// AD comes from the resolver, CD from the client.
    #[test]
    fn a_remembered_answer_ages_and_the_dnssec_bits_pass_through() {
        let mut query = query("a.example", RecordType::A, 1);
        query[3] |= FLAG_CHECKING_DISABLED as u8;
        let query = Message::parse(&query).unwrap();
        let mut upstream = response(
            "a.example",
            RecordType::A,
            &[("a.example", RecordType::A, vec![192, 0, 2, 1])],
        );
        upstream[3] |= FLAG_AUTHENTIC_DATA as u8;
        let upstream = Message::parse(&upstream).unwrap();
        let mut out = [0u8; 256];

        for (age, expected) in [(0, 300), (100, 200), (301, 0)] {
            let written = write_response_aged(
                &mut out,
                &query,
                &upstream,
                answer_policy(HostVerdict::Allowed),
                age,
            )
            .unwrap();
            let reply = Message::parse(&out[..written.len]).unwrap();
            let ttl = reply.answers().next().unwrap().unwrap().ttl;
            assert_eq!(ttl, expected, "age {age}");
            assert!(reply.authentic_data());
            assert!(reply.checking_disabled());
        }
    }

    /// RFC 6891 section 6.2.3: the OPT record's class is the sender's UDP
    /// payload size; it lives in the additional section after the rest.
    #[test]
    fn the_client_s_payload_size_is_read_from_its_opt_record() {
        let plain = query("a.example", RecordType::A, 1);
        assert_eq!(Message::parse(&plain).unwrap().udp_payload_size(), None);

        let mut with_opt = plain.clone();
        with_opt[10..12].copy_from_slice(&1u16.to_be_bytes()); // arcount
        with_opt.push(0); // root name
        with_opt.extend_from_slice(&OPT.to_be_bytes());
        with_opt.extend_from_slice(&1232u16.to_be_bytes()); // class: payload size
        with_opt.extend_from_slice(&[0; 4]); // ttl: extended rcode and flags
        with_opt.extend_from_slice(&0u16.to_be_bytes()); // no options
        assert_eq!(
            Message::parse(&with_opt).unwrap().udp_payload_size(),
            Some(1232)
        );

        with_opt.truncate(with_opt.len() - 1);
        assert_eq!(
            Message::parse(&with_opt).unwrap().udp_payload_size(),
            None,
            "a torn record is no record"
        );
    }

    /// RFC 1035 section 4.2.1: what does not fit is truncated, not failed.
    #[test]
    fn an_answer_that_does_not_fit_is_truncated_not_failed() {
        let asked = query("a.example", RecordType::A, 1);
        let query = Message::parse(&asked).unwrap();
        let upstream = response(
            "a.example",
            RecordType::A,
            &[("a.example", RecordType::A, vec![192, 0, 2, 1])],
        );
        let upstream = Message::parse(&upstream).unwrap();
        let mut small = [0u8; 40];
        assert_eq!(
            write_response(
                &mut small,
                &query,
                &upstream,
                answer_policy(HostVerdict::Allowed)
            )
            .err(),
            Some(DnsError::OutputTooSmall)
        );
        let len = write_truncated(&mut small, &query).unwrap();
        let reply = Message::parse(&small[..len]).unwrap();
        assert!(reply.is_truncated());
        assert_eq!(reply.rcode(), Rcode::NoError);
        assert_eq!(reply.answers().count(), 0);
        assert_eq!(reply.question(), query.question());
    }

    /// RFC 2136 UPDATE and RFC 1996 NOTIFY share the header; neither is a
    /// question to forward, and a header we can read still earns a FORMERR.
    #[test]
    fn an_update_is_not_a_query_and_a_broken_query_gets_a_format_error() {
        let mut update = query("example.com", RecordType::A, 0x1234);
        update[2] |= 5 << 3; // OPCODE UPDATE
        assert_eq!(Message::parse(&update).err(), Some(DnsError::NotAQuery));

        let mut out = [0u8; 64];
        let len = write_format_error(&mut out, &update).unwrap();
        assert_eq!(len, HEADER_BYTES);
        assert_eq!(&out[..2], &[0x12, 0x34]);
        let flags = u16::from_be_bytes([out[2], out[3]]);
        assert_eq!(flags & FLAG_RESPONSE, FLAG_RESPONSE);
        assert_eq!(
            flags & FLAG_RECURSION_DESIRED,
            FLAG_RECURSION_DESIRED,
            "RD is echoed"
        );
        assert_eq!(Rcode::from_wire(flags), Rcode::FormatError);
        assert_eq!(&out[4..12], &[0; 8], "no sections: nothing parsed");
        assert_eq!(
            write_format_error(&mut out, &[1, 2, 3]),
            Err(DnsError::Truncated)
        );
    }

    /// RFC 9619 section 4 requires at most one question for `OPCODE = 0`.
    #[test]
    fn a_query_carries_exactly_one_question_or_none_at_all() {
        let one = query("example.com", RecordType::A, 0x1234);
        assert!(Message::parse(&one).is_ok());

        let mut none = one.clone();
        none[4..6].copy_from_slice(&0u16.to_be_bytes());
        assert_eq!(Message::parse(&none).err(), Some(DnsError::NoQuestion));

        let mut two = one.clone();
        two[4..6].copy_from_slice(&2u16.to_be_bytes());
        two.extend_from_slice(&wire_name("tracker.example"));
        two.extend_from_slice(&RecordType::A.to_wire().to_be_bytes());
        two.extend_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            Message::parse(&two).err(),
            Some(DnsError::MultipleQuestions(2))
        );
    }

    fn response(name: &str, qtype: RecordType, answers: &[(&str, RecordType, Vec<u8>)]) -> Vec<u8> {
        let mut out = query(name, qtype, 0x4242);
        out[2..4].copy_from_slice(&(FLAG_RESPONSE | FLAG_RECURSION_DESIRED).to_be_bytes());
        out[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes());
        for (owner, rtype, rdata) in answers {
            out.extend_from_slice(&wire_name(owner));
            out.extend_from_slice(&rtype.to_wire().to_be_bytes());
            out.extend_from_slice(&1u16.to_be_bytes());
            out.extend_from_slice(&300u32.to_be_bytes());
            out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            out.extend_from_slice(rdata);
        }
        out
    }

    /// Builds HTTPS RDATA with RFC 9460's ascending SvcParam keys.
    fn https_rdata(target: &str, alpn: Option<&[u8]>, ech: Option<&[u8]>) -> Vec<u8> {
        let mut out = 1u16.to_be_bytes().to_vec();
        out.extend_from_slice(&wire_name(target));
        for (key, value) in [(SVCPARAM_ALPN, alpn), (SVCPARAM_ECH, ech)] {
            if let Some(value) = value {
                out.extend_from_slice(&key.to_be_bytes());
                out.extend_from_slice(&(value.len() as u16).to_be_bytes());
                out.extend_from_slice(value);
            }
        }
        out
    }

    const ECH_CONFIG: &[u8] = b"\x00\x41\xfe\x0d\x00\x3d\x00\x00 fake ech configuration bytes ..";

    #[test]
    fn names_normalize_and_refuse_what_they_cannot_represent() {
        let name = Name::parse("Ads.Example.COM.").expect("a normal name");
        assert_eq!(name.as_bytes(), b"ads.example.com");
        assert_eq!(name.to_string(), "ads.example.com");
        assert_eq!(name, Name::parse("ads.example.com").unwrap());

        // The root is empty and is not a rule label.
        let root = Name::parse("").expect("the root");
        assert!(root.is_root());
        assert_eq!(root.to_string(), ".");
        assert_eq!(root.wire_len(), 1);
        assert_eq!(name.wire_len(), name.as_bytes().len() + 2);

        // Empty labels would collide with the wire terminator.
        assert_eq!(Name::parse("a..b"), None);
        assert_eq!(Name::parse(&"x".repeat(64)), None);
        assert_eq!(Name::parse(&"a.".repeat(200)), None);
    }

    #[test]
    fn suffixes_run_most_specific_first() {
        let name = Name::parse("a.b.c").unwrap();
        let suffixes: Vec<&[u8]> = name.suffixes().collect();
        assert_eq!(suffixes, vec![&b"a.b.c"[..], b"b.c", b"c"]);
        assert_eq!(Name::ROOT.suffixes().count(), 0);
    }

    #[test]
    fn compression_terminates_because_pointers_run_backwards() {
        let mut message = query("example.com", RecordType::A, 1);
        let name_at = HEADER_BYTES as u16;
        message.extend_from_slice(&(0xc000 | name_at).to_be_bytes());
        let (name, consumed) = Name::read(&message, message.len() - 2).unwrap();
        assert_eq!(name.as_bytes(), b"example.com");
        assert_eq!(consumed, 2, "a pointer costs two bytes where it appears");

        // Self-pointers would loop; strict backward targets reject them.
        let at = message.len();
        message.extend_from_slice(&(0xc000 | at as u16).to_be_bytes());
        assert_eq!(Name::read(&message, at), Err(DnsError::ForwardPointer));

        // Forward pointers and cycles are rejected by the same rule.
        let at = message.len();
        message.extend_from_slice(&(0xc000 | (at as u16 + 8)).to_be_bytes());
        assert_eq!(Name::read(&message, at), Err(DnsError::ForwardPointer));

        // Reserved prefixes and truncation return errors.
        assert_eq!(Name::read(&[0x80], 0), Err(DnsError::ReservedLabel));
        assert_eq!(Name::read(&[0x04, b'a'], 0), Err(DnsError::Truncated));
        assert_eq!(Name::read(&[0xc0], 0), Err(DnsError::Truncated));

        // A separator inside a label would make suffix matching ambiguous.
        assert_eq!(
            Name::read(&[0x03, b'a', b'.', b'b', 0x00], 0),
            Err(DnsError::SeparatorInLabel)
        );
    }

    #[test]
    fn a_compressed_question_is_refused_so_it_can_be_copied_verbatim() {
        let mut message = vec![0u8; HEADER_BYTES];
        message[4..6].copy_from_slice(&1u16.to_be_bytes());
        message.extend_from_slice(&[0xc0, 0x00]); // points into the header
        message.extend_from_slice(&[0, 1, 0, 1]);
        assert_eq!(
            Message::parse(&message).unwrap_err(),
            DnsError::CompressedQuestion
        );
    }

    #[test]
    fn record_type_round_trips_over_the_whole_wire_domain() {
        // `from_wire` and `to_wire` are inverse over all `u16` values.
        for value in 0..=u16::MAX {
            assert_eq!(RecordType::from_wire(value).to_wire(), value);
        }
        assert!(RecordType::Https.carries_svc_params());
        assert!(RecordType::Svcb.carries_svc_params());
        assert!(!RecordType::A.carries_svc_params());
    }

    #[test]
    fn the_most_specific_rule_wins_and_blocking_beats_inspection() {
        let mut policy = HostPolicy::new();
        assert!(policy.block("doubleclick.net"));
        assert!(policy.inspect("example.com"));
        assert!(policy.block("ads.example.com"));
        assert!(policy.inspect("example.com")); // idempotent
        assert!(!policy.block(""), "the root is not a rule");
        assert!(!policy.block("a..b"), "an unrepresentable name is refused");

        let judge = |name: &str| {
            let name = Name::parse(name).unwrap();
            let judgment = policy.judge(&name);
            (
                judgment.verdict,
                judgment.matched.map(|rule| rule.as_bytes().to_vec()),
            )
        };

        // A subdomain inherits its parent's rule and provenance.
        assert_eq!(
            judge("static.doubleclick.net"),
            (HostVerdict::Blocked, Some(b"doubleclick.net".to_vec()))
        );
        // A more-specific block wins over inspection.
        assert_eq!(
            judge("img.ads.example.com"),
            (HostVerdict::Blocked, Some(b"ads.example.com".to_vec()))
        );
        assert_eq!(
            judge("www.example.com"),
            (HostVerdict::Inspected, Some(b"example.com".to_vec()))
        );
        assert_eq!(judge("example.org"), (HostVerdict::Allowed, None));

        // Matching is label-based, never substring-based.
        assert_eq!(judge("notexample.com"), (HostVerdict::Allowed, None));
    }

    #[test]
    fn ech_is_stripped_for_inspected_hosts_and_for_nothing_else() {
        for verdict in [
            HostVerdict::Allowed,
            HostVerdict::Blocked,
            HostVerdict::Inspected,
        ] {
            assert_eq!(
                ech_policy(verdict) == EchPolicy::Strip,
                verdict == HostVerdict::Inspected,
                "{verdict:?} decided ECH globally rather than per host"
            );
        }
    }

    #[test]
    fn planning_refuses_blocked_names_without_consulting_an_upstream() {
        let mut policy = HostPolicy::new();
        policy.block("tracker.example");
        policy.inspect("shop.example");

        let plan = |name: &str| {
            let question = Question {
                name: Name::parse(name).unwrap(),
                qtype: RecordType::Https,
                qclass: 1,
            };
            match plan_query(&question, &policy) {
                QueryPlan::Refuse { rule } => Ok(rule.as_bytes().to_vec()),
                QueryPlan::Forward { policy } => Err(policy),
            }
        };
        assert_eq!(plan("a.tracker.example"), Ok(b"tracker.example".to_vec()));
        assert_eq!(
            plan("shop.example"),
            Err(answer_policy(HostVerdict::Inspected))
        );
        assert_eq!(
            plan("other.example"),
            Err(answer_policy(HostVerdict::Allowed))
        );
        assert!(answer_policy(HostVerdict::Inspected).steers());
        assert!(!answer_policy(HostVerdict::Allowed).steers());
    }

    #[test]
    fn svc_params_are_walked_in_order_and_out_of_order_is_refused() {
        let rdata = https_rdata("target.example", Some(b"\x02h2"), Some(ECH_CONFIG));
        let params: Vec<SvcParam<'_>> = svc_params(&rdata)
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            params.iter().map(|param| param.key).collect::<Vec<_>>(),
            vec![SVCPARAM_ALPN, SVCPARAM_ECH]
        );
        assert_eq!(params[1].value, ECH_CONFIG);
        assert_eq!(ech_param(&rdata).unwrap(), Some(params[1].at.clone()));
        assert_eq!(&rdata[params[1].at.clone()][4..], ECH_CONFIG);

        let plain = https_rdata("target.example", Some(b"\x02h2"), None);
        assert_eq!(ech_param(&plain).unwrap(), None);

        // Descending or duplicate keys violate RFC 9460 ordering.
        let mut reversed = 1u16.to_be_bytes().to_vec();
        reversed.extend_from_slice(&wire_name("target.example"));
        for key in [SVCPARAM_ECH, SVCPARAM_ALPN] {
            reversed.extend_from_slice(&key.to_be_bytes());
            reversed.extend_from_slice(&0u16.to_be_bytes());
        }
        assert_eq!(
            ech_param(&reversed).unwrap_err(),
            DnsError::SvcParamsOutOfOrder
        );

        // RFC 9460 forbids compression in TargetName.
        let pointered = [0x00, 0x01, 0xc0, 0x0c];
        assert_eq!(svc_params(&pointered).err(), Some(DnsError::ReservedLabel));
    }

    #[test]
    fn a_preserved_answer_is_byte_identical_and_a_stripped_one_loses_only_ech() {
        let client = query("shop.example", RecordType::Https, 0x1234);
        let client = Message::parse(&client).unwrap();
        let upstream_bytes = response(
            "shop.example",
            RecordType::Https,
            &[
                (
                    "shop.example",
                    RecordType::Https,
                    https_rdata("a.shop.example", Some(b"\x02h3"), Some(ECH_CONFIG)),
                ),
                ("shop.example", RecordType::A, vec![93, 184, 215, 14]),
            ],
        );
        let upstream = Message::parse(&upstream_bytes).unwrap();

        let mut out = [0u8; 1500];
        let preserved = write_response(
            &mut out,
            &client,
            &upstream,
            answer_policy(HostVerdict::Allowed),
        )
        .unwrap();
        assert_eq!(preserved.answers, 2);
        assert_eq!(preserved.ech, EchOutcome::Preserved);
        let parsed = Message::parse(&out[..preserved.len]).unwrap();
        // Transaction identity and question come from the client.
        assert_eq!(parsed.id(), 0x1234);
        assert_eq!(parsed.question(), client.question());
        assert!(parsed.is_response() && parsed.recursion_desired());
        assert_eq!(parsed.rcode(), Rcode::NoError);
        let answers: Vec<ResourceRecord<'_>> = parsed.answers().collect::<Result<_, _>>().unwrap();
        assert_eq!(answers.len(), 2);
        assert!(ech_param(answers[0].rdata).unwrap().is_some());
        assert_eq!(answers[1].rdata, &[93, 184, 215, 14]);

        let mut stripped_out = [0u8; 1500];
        let stripped = write_response(
            &mut stripped_out,
            &client,
            &upstream,
            answer_policy(HostVerdict::Inspected),
        )
        .unwrap();
        assert_eq!(stripped.ech, EchOutcome::Stripped { count: 1 });
        let parsed = Message::parse(&stripped_out[..stripped.len]).unwrap();
        let after: Vec<ResourceRecord<'_>> = parsed.answers().collect::<Result<_, _>>().unwrap();
        assert_eq!(after.len(), 2, "stripping removes a param, not a record");

        // Inspection removes both advertised ECH and HTTP/3 parameters.
        assert_eq!(stripped.alpn, AlpnOutcome::Steered { count: 1 });
        assert_eq!(ech_param(after[0].rdata).unwrap(), None);
        assert_eq!(h3_alpn_param(after[0].rdata).unwrap(), None);
        let remaining: Vec<u16> = svc_params(after[0].rdata)
            .unwrap()
            .map(|param| param.unwrap().key)
            .collect();
        assert!(remaining.is_empty(), "both parameters were removed");
        assert_eq!(
            after[0].rdata.len(),
            answers[0].rdata.len() - (4 + ECH_CONFIG.len()) - (4 + 3),
            "exactly the two parameters, and nothing between them"
        );
        assert_eq!(
            after[1].rdata, answers[1].rdata,
            "the A record is untouched"
        );
    }

    #[test]
    fn the_two_cuts_are_independent() {
        // Inspection strips ECH but preserves a non-HTTP/3 ALPN.
        let client = query("shop.example", RecordType::Https, 5);
        let client = Message::parse(&client).unwrap();
        let upstream_bytes = response(
            "shop.example",
            RecordType::Https,
            &[(
                "shop.example",
                RecordType::Https,
                https_rdata("a.shop.example", Some(b"\x02h2"), Some(ECH_CONFIG)),
            )],
        );
        let upstream = Message::parse(&upstream_bytes).unwrap();

        let mut out = [0u8; 1500];
        let written = write_response(
            &mut out,
            &client,
            &upstream,
            answer_policy(HostVerdict::Inspected),
        )
        .unwrap();
        assert_eq!(written.ech, EchOutcome::Stripped { count: 1 });
        assert_eq!(written.alpn, AlpnOutcome::Absent, "no h3 was advertised");

        let parsed = Message::parse(&out[..written.len]).unwrap();
        let answers: Vec<ResourceRecord<'_>> = parsed.answers().collect::<Result<_, _>>().unwrap();
        let remaining: Vec<u16> = svc_params(answers[0].rdata)
            .unwrap()
            .map(|param| param.unwrap().key)
            .collect();
        assert_eq!(remaining, vec![SVCPARAM_ALPN], "h2 keeps its advertisement");
    }

    #[test]
    fn h3_detection_covers_the_drafts_and_takes_no_default_alpn_with_it() {
        let with = |alpn: &[u8], no_default: bool| {
            let mut rdata = 1u16.to_be_bytes().to_vec();
            rdata.extend_from_slice(&wire_name("target.example"));
            rdata.extend_from_slice(&SVCPARAM_ALPN.to_be_bytes());
            rdata.extend_from_slice(&(alpn.len() as u16).to_be_bytes());
            rdata.extend_from_slice(alpn);
            if no_default {
                rdata.extend_from_slice(&SVCPARAM_NO_DEFAULT_ALPN.to_be_bytes());
                rdata.extend_from_slice(&0u16.to_be_bytes());
            }
            rdata
        };

        // Registered and draft HTTP/3 identifiers both count.
        for alpn in [&b"\x02h3"[..], b"\x05h3-29", b"\x02h2\x02h3"] {
            let rdata = with(alpn, false);
            assert!(
                h3_alpn_param(&rdata).unwrap().is_some(),
                "{alpn:?} advertises HTTP/3"
            );
        }
        for alpn in [&b"\x02h2"[..], b"\x08http/1.1", b"\x03h3x"] {
            let rdata = with(alpn, false);
            assert_eq!(h3_alpn_param(&rdata).unwrap(), None, "{alpn:?}");
        }

        // RFC 9460 section 7.1.1 makes this adjacent to `alpn`.
        let rdata = with(b"\x02h3", true);
        let range = h3_alpn_param(&rdata).unwrap().expect("h3 advertised");
        assert_eq!(range.end, rdata.len(), "the pair reaches the end together");
        let kept = Rdata::without(&rdata, range).unwrap();
        assert_eq!(kept.len(), rdata.len() - (4 + 3) - 4);

        // An unrelated `no-default-alpn` is left alone.
        let mut rdata = 1u16.to_be_bytes().to_vec();
        rdata.extend_from_slice(&wire_name("target.example"));
        rdata.extend_from_slice(&SVCPARAM_NO_DEFAULT_ALPN.to_be_bytes());
        rdata.extend_from_slice(&0u16.to_be_bytes());
        assert_eq!(h3_alpn_param(&rdata).unwrap(), None);

        // Empty identifiers are malformed.
        let rdata = with(b"\x00", false);
        assert_eq!(
            h3_alpn_param(&rdata).unwrap_err(),
            DnsError::EmptyAlpnIdentifier
        );
    }

    #[test]
    fn two_disjoint_cuts_compose_and_an_overlap_is_unconstructable() {
        let bytes = b"0123456789";
        assert_eq!(Rdata::verbatim(bytes).len(), 10);
        assert_eq!(Rdata::without(bytes, 2..4).unwrap().len(), 8);
        assert_eq!(Rdata::without_both(bytes, 1..3, 6..8).unwrap().len(), 6);
        // Adjacent ranges are valid; overlapping or out-of-bounds ranges fail.
        assert!(Rdata::without_both(bytes, 1..3, 3..5).is_some());
        assert!(Rdata::without_both(bytes, 1..4, 3..5).is_none());
        assert!(Rdata::without_both(bytes, 1..3, 20..30).is_none());
    }

    #[test]
    fn an_answer_without_ech_reports_absence_rather_than_preservation() {
        let client = query("plain.example", RecordType::Https, 7);
        let client = Message::parse(&client).unwrap();
        let upstream_bytes = response(
            "plain.example",
            RecordType::Https,
            &[(
                "plain.example",
                RecordType::Https,
                https_rdata("a.plain.example", Some(b"\x02h2"), None),
            )],
        );
        let upstream = Message::parse(&upstream_bytes).unwrap();
        let mut out = [0u8; 1500];
        for verdict in [HostVerdict::Allowed, HostVerdict::Inspected] {
            let written =
                write_response(&mut out, &client, &upstream, answer_policy(verdict)).unwrap();
            assert_eq!(written.ech, EchOutcome::Absent);
        }
    }

    #[test]
    fn a_refusal_is_an_immediate_name_error_with_the_question_echoed() {
        let client = query("tracker.example", RecordType::A, 0xbeef);
        let client = Message::parse(&client).unwrap();
        let mut out = [0u8; 512];
        let len = write_refusal(&mut out, &client).unwrap();
        let parsed = Message::parse(&out[..len]).unwrap();
        assert_eq!(parsed.rcode(), Rcode::NameError);
        assert_eq!(parsed.id(), 0xbeef);
        assert_eq!(parsed.question(), client.question());
        assert_eq!(parsed.answers().count(), 0);

        let len = write_failure(&mut out, &client).unwrap();
        assert_eq!(
            Message::parse(&out[..len]).unwrap().rcode(),
            Rcode::ServerFailure
        );
    }

    #[test]
    fn an_undersized_output_is_an_error_rather_than_a_truncated_answer() {
        let client = query("example.com", RecordType::A, 1);
        let client = Message::parse(&client).unwrap();
        let upstream_bytes = response(
            "example.com",
            RecordType::A,
            &[("example.com", RecordType::A, vec![1, 2, 3, 4])],
        );
        let upstream = Message::parse(&upstream_bytes).unwrap();
        let mut tiny = [0u8; 20];
        assert_eq!(
            write_response(
                &mut tiny,
                &client,
                &upstream,
                answer_policy(HostVerdict::Allowed)
            )
            .unwrap_err(),
            DnsError::OutputTooSmall
        );
    }
}
