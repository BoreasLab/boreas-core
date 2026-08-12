//! DNS interception, verdict provenance, and ECH policy.
//!
//! DNS is the first enforcement tier in [Filtering](../docs/filtering.md): it
//! reaches every application on the device, including the ones that reject the
//! Boreas CA and can therefore never be intercepted at TLS. It is also the
//! durable no-decryption signal now that ECH blinds passive SNI inspection.
//!
//! Everything in this module is pure. Messages are parsed from borrowed bytes
//! with no allocation, policy is a total function of a name and a rule set,
//! and responses are written into a caller-owned buffer. The upstream
//! transport — the socket that carries a query to a resolver — lives in the
//! shell, and the only thing it contributes to a verdict is which
//! [`Upstream`] it was.
//!
//! Three decisions carry the design.
//!
//! **A name is decoded once, into fixed storage.** RFC 1035 caps a name at 255
//! wire bytes, so a [`Name`] is an inline array and parsing a query allocates
//! nothing at all. Compression pointers must point strictly backwards, which
//! is what makes decoding terminate on adversarial input rather than needing a
//! visit set.
//!
//! **Provenance travels with the answer, not beside it.** A verdict that
//! cannot be explained after the fact is a verdict a user cannot argue with,
//! so every [`Resolution`] names the rule that matched, the transport the
//! bytes crossed, and what happened to ECH.
//!
//! **ECH policy is per host and never global.** Disabling ECH for the whole
//! session would hand every site's SNI back to the network for the sake of the
//! few hosts the session actually inspects. [`ech_policy`] therefore strips
//! only for [`HostVerdict::Inspected`], and the strip is a byte range removed
//! from one answer.

use std::{collections::HashSet, error::Error, fmt, ops::Range};

/// The UDP and TCP port DNS is served on. Interception keys on the port
/// rather than on a resolver address: the client's configured resolver lives
/// inside the tunnel, so every query on this port is one Boreas owns.
pub const DNS_PORT: u16 = 53;

/// RFC 1035 section 2.3.4: 255 octets of wire encoding, which is 253
/// characters of presentation form once the leading length byte and the root
/// label are accounted for.
pub const MAX_NAME_CHARS: usize = 253;

/// RFC 1035 section 2.3.4: 63 octets per label.
const MAX_LABEL_LEN: usize = 63;

const HEADER_BYTES: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsError {
    /// The message ended inside a field.
    Truncated,
    /// A label length byte used a reserved (0b01 or 0b10) prefix.
    ReservedLabel,
    /// A compression pointer did not point strictly backwards. Enforcing that
    /// is what makes decoding terminate: each pointer strictly decreases the
    /// cursor, so the chain is finite without tracking visited offsets.
    ForwardPointer,
    /// The decoded name exceeds the RFC 1035 length limit.
    NameTooLong,
    /// A label contained the presentation separator. Joining labels with `.`
    /// would make such a name ambiguous, and suffix matching — the whole basis
    /// of host policy — depends on the join being unambiguous. Legal on the
    /// wire, absent from anything a policy list addresses, refused here.
    SeparatorInLabel,
    /// The message declared no question. Every message Boreas handles is a
    /// query or its answer, and both carry one.
    NoQuestion,
    /// The question's name used compression. Nothing precedes the question but
    /// the fixed header, so a pointer there targets the header and is
    /// nonsense; refusing it is what lets the question section be copied
    /// verbatim into a response without rewriting a pointer.
    CompressedQuestion,
    /// SvcParam keys were not in strictly increasing order, which RFC 9460
    /// section 2.2 requires.
    SvcParamsOutOfOrder,
    /// The output buffer could not hold the message.
    OutputTooSmall,
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "message ended inside a field",
            Self::ReservedLabel => "reserved label length prefix",
            Self::ForwardPointer => "compression pointer does not point backwards",
            Self::NameTooLong => "name exceeds 253 characters",
            Self::SeparatorInLabel => "label contains the presentation separator",
            Self::NoQuestion => "message carries no question",
            Self::CompressedQuestion => "question name uses compression",
            Self::SvcParamsOutOfOrder => "SvcParam keys are not strictly increasing",
            Self::OutputTooSmall => "output buffer is too small",
        })
    }
}

impl Error for DnsError {}

/// A decoded, normalized domain name.
///
/// ASCII-lowercased, because RFC 4343 makes DNS comparison case-insensitive
/// over ASCII and only ASCII; labels joined by `.`; no trailing dot; the root
/// is the empty name. Bytes outside ASCII pass through unchanged and compare
/// bytewise, so internationalized and DNS-SD names are handled without this
/// module having an opinion about text encoding.
///
/// Fixed inline storage, so decoding a query allocates nothing.
#[derive(Clone, Copy)]
pub struct Name {
    bytes: [u8; MAX_NAME_CHARS],
    len: u8,
}

impl Name {
    /// The root name, which is what an empty wire name decodes to.
    pub const ROOT: Self = Self {
        bytes: [0; MAX_NAME_CHARS],
        len: 0,
    };

    /// Normalizes a presentation-form name. `None` when it is too long or a
    /// label carries the separator — the same refusals wire decoding makes,
    /// so a rule and a query cannot disagree about what a name is.
    pub fn parse(text: &str) -> Option<Self> {
        let trimmed = text.strip_suffix('.').unwrap_or(text);
        if trimmed.len() > MAX_NAME_CHARS {
            return None;
        }
        // An empty label would encode as a zero length byte, which is the
        // wire's name terminator: `a..b` would silently become `a`. Wire
        // decoding cannot produce one, so refusing it here gives both
        // constructors the same invariant.
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

    /// The name and every parent of it, most specific first: `a.b.c` yields
    /// `a.b.c`, `b.c`, `c`. This is the lookup order host policy uses, so the
    /// first match is the most specific rule.
    ///
    /// O(labels), and a name's length limit bounds labels at 127.
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

    /// Rebuilds a name from bytes that are already normalized.
    ///
    /// Only reachable from [`Name::suffixes`], whose output is by construction
    /// a suffix of an already-normalized name and therefore normalized itself,
    /// so there is nothing left to check.
    fn from_normalized(normalized: &[u8]) -> Self {
        let mut bytes = [0; MAX_NAME_CHARS];
        bytes[..normalized.len()].copy_from_slice(normalized);
        Self {
            bytes,
            len: normalized.len() as u8,
        }
    }

    /// Wire length: one length byte per label plus the root's terminating
    /// zero. The separators become length bytes, so a non-root name costs its
    /// presentation length plus two.
    pub fn wire_len(&self) -> usize {
        if self.is_root() {
            1
        } else {
            usize::from(self.len) + 2
        }
    }

    /// Decodes a name at `at`, returning it with the number of bytes it
    /// occupies *at that position* — following a pointer consumes the two
    /// pointer bytes and nothing more.
    fn read(message: &[u8], at: usize) -> Result<(Self, usize), DnsError> {
        let mut bytes = [0; MAX_NAME_CHARS];
        let mut len = 0usize;
        let mut cursor = at;
        // Set by the first pointer: everything after it is elsewhere in the
        // message and costs nothing at the original position.
        let mut consumed: Option<usize> = None;

        loop {
            let length = *message.get(cursor).ok_or(DnsError::Truncated)?;
            match length & 0xc0 {
                0x00 if length == 0 => {
                    cursor += 1;
                    break;
                }
                0x00 => {
                    let start = cursor + 1;
                    let end = start + usize::from(length);
                    let label = message.get(start..end).ok_or(DnsError::Truncated)?;
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
                    cursor = end;
                }
                0xc0 => {
                    let low = *message.get(cursor + 1).ok_or(DnsError::Truncated)?;
                    let target = usize::from(u16::from_be_bytes([length & 0x3f, low]));
                    // Strictly backwards, so the cursor strictly decreases and
                    // the chain is finite. This is the whole loop defense.
                    if target >= cursor {
                        return Err(DnsError::ForwardPointer);
                    }
                    consumed.get_or_insert(cursor + 2);
                    cursor = target;
                }
                _ => return Err(DnsError::ReservedLabel),
            }
        }

        Ok((
            Self {
                bytes,
                len: len as u8,
            },
            consumed.unwrap_or(cursor) - at,
        ))
    }

    /// Writes the wire encoding at `at`, returning the new offset. Never
    /// compressed: see [`write_response`] for why.
    fn write(&self, out: &mut [u8], at: usize) -> Result<usize, DnsError> {
        let mut cursor = at;
        if !self.is_root() {
            for label in self.as_bytes().split(|byte| *byte == b'.') {
                let end = cursor + 1 + label.len();
                let slot = out.get_mut(cursor..end).ok_or(DnsError::OutputTooSmall)?;
                slot[0] = label.len() as u8;
                slot[1..].copy_from_slice(label);
                cursor = end;
            }
        }
        *out.get_mut(cursor).ok_or(DnsError::OutputTooSmall)? = 0;
        Ok(cursor + 1)
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

/// RFC 1035 section 5.1 presentation form: printable ASCII verbatim,
/// everything else escaped as `\DDD`, so a log line is unambiguous and cannot
/// carry a control sequence.
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

/// The record types host policy and steering act on, plus everything else.
///
/// `Other` keeps the sum total without pretending the list is closed: a query
/// for `MX` is forwarded and answered like any other, it simply has no policy
/// attached. The wire encoding round-trips, which is the law the tests check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordType {
    A,
    Aaaa,
    /// RFC 9460 HTTPS record: the ALPN and ECH carrier, and therefore the
    /// record both steering and ECH policy act on.
    Https,
    /// RFC 9460 SVCB record, the general form of the same shape.
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

    /// Whether this record carries SvcParams, and so whether ECH policy has
    /// anything to act on.
    pub fn carries_svc_params(self) -> bool {
        matches!(self, Self::Https | Self::Svcb)
    }
}

/// The four header bits Boreas reads or sets. The rest of the flags word is
/// copied through, because a resolver that reinvents an upstream's header is a
/// resolver that disagrees with it.
const FLAG_RESPONSE: u16 = 0x8000;
const FLAG_RECURSION_DESIRED: u16 = 0x0100;
const FLAG_RECURSION_AVAILABLE: u16 = 0x0080;
const FLAG_TRUNCATED: u16 = 0x0200;
const RCODE_MASK: u16 = 0x000f;

/// RFC 1035 response codes this module produces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rcode {
    NoError,
    ServerFailure,
    NameError,
    Other(u16),
}

impl Rcode {
    pub fn from_wire(value: u16) -> Self {
        match value & RCODE_MASK {
            0 => Self::NoError,
            2 => Self::ServerFailure,
            3 => Self::NameError,
            other => Self::Other(other),
        }
    }

    pub fn to_wire(self) -> u16 {
        match self {
            Self::NoError => 0,
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

/// One resource record, with its RDATA still borrowed from the message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceRecord<'a> {
    pub name: Name,
    pub rtype: RecordType,
    pub class: u16,
    pub ttl: u32,
    pub rdata: &'a [u8],
}

/// A parsed DNS message. The header and the question are decoded eagerly
/// because every caller needs both; the answer section stays borrowed and is
/// walked lazily, so a message with a hundred answers costs one pass and no
/// allocation.
#[derive(Clone, Copy, Debug)]
pub struct Message<'a> {
    bytes: &'a [u8],
    id: u16,
    flags: u16,
    answer_count: u16,
    question: Question,
    /// The question section exactly as it arrived, copied verbatim into a
    /// response so a client using 0x20 case randomization still recognizes its
    /// own query. Safe to copy because a compressed question name is refused.
    question_bytes: &'a [u8],
    answers_at: usize,
}

impl<'a> Message<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, DnsError> {
        let header = bytes.get(..HEADER_BYTES).ok_or(DnsError::Truncated)?;
        let word = |at: usize| u16::from_be_bytes([header[at], header[at + 1]]);
        let (id, flags, question_count, answer_count) = (word(0), word(2), word(4), word(6));
        if question_count == 0 {
            return Err(DnsError::NoQuestion);
        }

        let (name, name_len) = Name::read(bytes, HEADER_BYTES)?;
        if name_len != name.wire_len() {
            // A pointer was followed, so the encoding is shorter than the name
            // it denotes. See `DnsError::CompressedQuestion`.
            return Err(DnsError::CompressedQuestion);
        }
        let fields_at = HEADER_BYTES + name_len;
        let fields = bytes
            .get(fields_at..fields_at + 4)
            .ok_or(DnsError::Truncated)?;

        Ok(Self {
            bytes,
            id,
            flags,
            answer_count,
            question: Question {
                name,
                qtype: RecordType::from_wire(u16::from_be_bytes([fields[0], fields[1]])),
                qclass: u16::from_be_bytes([fields[2], fields[3]]),
            },
            question_bytes: &bytes[HEADER_BYTES..fields_at + 4],
            answers_at: fields_at + 4,
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

    /// The answer section, walked lazily. Each item is fallible because the
    /// bytes are untrusted; a caller that stops at the first error has still
    /// consumed every record before it.
    pub fn answers(&self) -> Answers<'a> {
        Answers {
            message: self.bytes,
            cursor: self.answers_at,
            remaining: self.answer_count,
        }
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
    fn read(&mut self) -> Result<ResourceRecord<'a>, DnsError> {
        let (name, name_len) = Name::read(self.message, self.cursor)?;
        let fields_at = self.cursor + name_len;
        let fields = self
            .message
            .get(fields_at..fields_at + 10)
            .ok_or(DnsError::Truncated)?;
        let rdlength = usize::from(u16::from_be_bytes([fields[8], fields[9]]));
        let rdata_at = fields_at + 10;
        let rdata = self
            .message
            .get(rdata_at..rdata_at + rdlength)
            .ok_or(DnsError::Truncated)?;
        self.cursor = rdata_at + rdlength;

        Ok(ResourceRecord {
            name,
            rtype: RecordType::from_wire(u16::from_be_bytes([fields[0], fields[1]])),
            class: u16::from_be_bytes([fields[2], fields[3]]),
            ttl: u32::from_be_bytes([fields[4], fields[5], fields[6], fields[7]]),
            rdata,
        })
    }
}

/// RFC 9460 section 14.3.2: the `ech` SvcParam key.
pub const SVCPARAM_ECH: u16 = 5;
/// RFC 9460 section 14.3.2: the `alpn` SvcParam key, which P13's steering
/// reads to decide whether a host is offering h3.
pub const SVCPARAM_ALPN: u16 = 1;

/// One SvcParam, with the byte range it occupies inside the RDATA. The range
/// is what makes removal a slice operation rather than a rebuild.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SvcParam<'a> {
    pub key: u16,
    pub value: &'a [u8],
    pub at: Range<usize>,
}

/// Walks the SvcParams of an HTTPS or SVCB RDATA.
///
/// The TargetName inside SVCB RDATA is uncompressible by RFC 9460 section 2.2,
/// so this needs no message context and works on the RDATA alone.
pub fn svc_params(rdata: &[u8]) -> Result<SvcParams<'_>, DnsError> {
    // SvcPriority, then TargetName, then the params.
    let mut cursor = 2;
    if rdata.len() < cursor {
        return Err(DnsError::Truncated);
    }
    loop {
        let length = usize::from(*rdata.get(cursor).ok_or(DnsError::Truncated)?);
        if length & 0xc0 != 0 {
            // A pointer or reserved prefix where RFC 9460 forbids one.
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
        let header = self
            .rdata
            .get(start..start + 4)
            .ok_or(DnsError::Truncated)?;
        let key = u16::from_be_bytes([header[0], header[1]]);
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        let end = start + 4 + length;
        let value = self.rdata.get(start + 4..end).ok_or(DnsError::Truncated)?;
        // RFC 9460 section 2.2 requires strictly increasing keys, which also
        // makes a duplicated key unrepresentable rather than ambiguous.
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

/// The byte range of the `ech` SvcParam inside an HTTPS or SVCB RDATA, when
/// the answer publishes one.
///
/// Deliberately walks the whole parameter list rather than stopping at the
/// match: answering from a record whose remaining parameters do not parse
/// would be validating the part that suits us and trusting the rest.
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

/// What the session may do with a host. This is the entire interface between
/// filtering policy and DNS, and it is deliberately three cases: anything
/// finer is a property of the rule, not of the resolver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostVerdict {
    /// Refuse the name. No upstream is consulted, so a blocked host costs no
    /// query and leaks no name.
    Blocked,
    /// Resolve normally, and leave ECH exactly as the authority published it.
    Allowed,
    /// Resolve, but this session terminates TLS for the host, so an ECH
    /// configuration the client could use would encrypt the ClientHello and
    /// the interception would silently never fire.
    Inspected,
}

/// The verdict for one name, with the rule that produced it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Judgment {
    pub verdict: HostVerdict,
    /// The suffix of the queried name that matched, or `None` when nothing
    /// did. This is what makes a verdict explainable: "blocked by
    /// `doubleclick.net`", not "blocked".
    pub matched: Option<Name>,
}

/// Host rules, indexed for suffix lookup.
///
/// A rule covers a name and everything under it, so the lookup walks the
/// query's suffixes from most to least specific. Two laws decide the winner:
///
/// - **An exception wins outright, at any specificity.** That is Adblock Plus
///   semantics for network rules, and it is the fail-open direction
///   [Filtering](../docs/filtering.md) mandates: a rule that says "never touch
///   this" must not be overridden by a more specific rule that says "block".
/// - **Otherwise the most specific rule wins, and at equal specificity
///   blocking beats inspection**, because a host that is refused is never also
///   intercepted.
///
/// O(labels) hash probes per query, at most three per label, and a name's
/// 253-character limit bounds labels at 127 — typically three to five. The
/// exception law is what costs the full walk rather than an early exit: a
/// block found at the first label must still yield to an exception found at
/// the last. The keys are `HashSet`'s default SipHash with a per-process
/// random seed, which matters because qnames are attacker-chosen: any
/// application on the device can ask for any name it likes.
///
/// Space is O(distinct rule hosts), which a full filter-list build puts in the
/// hundreds of thousands; each key is its own name's bytes and nothing else.
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

    /// Adds a blocking rule. `false` when the name is not one DNS can carry,
    /// which is a rejected rule rather than a silently ignored one.
    pub fn block(&mut self, name: &str) -> bool {
        Self::insert(&mut self.blocked, name)
    }

    /// Adds an exception. It beats every blocking and inspection rule that
    /// matches the same query, however specific they are.
    pub fn allow(&mut self, name: &str) -> bool {
        Self::insert(&mut self.allowed, name)
    }

    /// Adds an inspection rule; see [`HostVerdict::Inspected`].
    pub fn inspect(&mut self, name: &str) -> bool {
        Self::insert(&mut self.inspected, name)
    }

    /// How many rules of each kind this policy holds. The number an operator
    /// reads back after a list reload.
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

    /// Adds an already-parsed name, which is how the filter-list compiler
    /// avoids re-normalizing what it has just parsed.
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
            // The exception law: an allow anywhere in the chain ends the
            // search, which is why the walk cannot stop at the first block.
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

/// Rules held, by kind.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RuleCounts {
    pub allowed: usize,
    pub blocked: usize,
    pub inspected: usize,
}

/// What must happen to the `ech` SvcParam of this host's answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EchPolicy {
    /// Leave it exactly as published. The default, and the reason there is no
    /// global ECH switch anywhere in this crate.
    Preserve,
    /// Remove it from this host's answers, and only this host's.
    Strip,
}

/// The one place ECH policy is decided.
///
/// The law, and the P11 gate: `Strip` if and only if the host is inspected.
/// An allowed host keeps its ECH configuration, and so does a blocked one —
/// its answer carries no addresses to connect to anyway.
pub fn ech_policy(verdict: HostVerdict) -> EchPolicy {
    match verdict {
        HostVerdict::Inspected => EchPolicy::Strip,
        HostVerdict::Allowed | HostVerdict::Blocked => EchPolicy::Preserve,
    }
}

/// What to do with one intercepted query, decided before any upstream is
/// consulted.
///
/// The `Refuse` variant is the larger by the width of a [`Name`], and
/// deliberately not boxed: refusal is the ad-blocking path, the one taken most
/// often, and paying an allocation there to shrink a value that lives for the
/// length of one function call is the wrong trade.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryPlan {
    /// Answer locally with [`write_refusal`]. No query leaves the device.
    Refuse { rule: Name },
    /// Send it upstream, then run [`write_response`] with this policy.
    Forward { ech: EchPolicy },
}

/// Plans one intercepted query. Total: every name has a verdict, and every
/// verdict has a plan.
pub fn plan_query(question: &Question, policy: &HostPolicy) -> QueryPlan {
    let judgment = policy.judge(&question.name);
    match judgment.verdict {
        // `matched` is always `Some` for a non-`Allowed` verdict: only a rule
        // can produce one. The fallback keeps the function total rather than
        // asserting that.
        HostVerdict::Blocked => QueryPlan::Refuse {
            rule: judgment.matched.unwrap_or(Name::ROOT),
        },
        verdict => QueryPlan::Forward {
            ech: ech_policy(verdict),
        },
    }
}

/// The transport an answer crossed. Recorded because the privacy claim differs
/// per transport: Do53 is readable by anything on the path, the rest are not.
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

/// Where an answer came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provenance {
    /// Synthesized from policy; nothing left the device.
    Policy,
    /// Resolved through an upstream.
    Upstream(Upstream),
}

/// What happened to ECH in one response, which is the part of a verdict a
/// privacy-conscious user most needs explained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EchOutcome {
    /// No answer carried an ECH configuration.
    Absent,
    /// Published and preserved, because host policy did not need it gone.
    Preserved,
    /// Removed from `count` answers for this name only.
    Stripped { count: u16 },
}

/// Everything needed to explain one verdict after the fact.
///
/// One of these per query, and a query is a flow-scale event rather than a
/// packet-scale one, so it travels whole rather than being folded into a
/// counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resolution {
    pub name: Name,
    pub qtype: RecordType,
    pub rcode: Rcode,
    pub answers: u16,
    pub provenance: Provenance,
    /// The rule that decided the verdict. Absent when no rule matched.
    pub rule: Option<Name>,
    pub ech: EchOutcome,
}

/// RDATA being written: the bytes as they arrived, or those bytes with one
/// contiguous range removed.
///
/// Removal is the only edit any policy in this module performs, so this is the
/// whole domain — and expressing it as two slices means an ECH strip rewrites
/// nothing and allocates nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rdata<'a> {
    head: &'a [u8],
    tail: &'a [u8],
}

impl<'a> Rdata<'a> {
    pub fn verbatim(bytes: &'a [u8]) -> Self {
        Self {
            head: bytes,
            tail: &[],
        }
    }

    /// `None` when the range does not lie inside `bytes`.
    pub fn without(bytes: &'a [u8], cut: Range<usize>) -> Option<Self> {
        Some(Self {
            head: bytes.get(..cut.start)?,
            tail: bytes.get(cut.end..)?,
        })
    }

    pub fn len(&self) -> usize {
        self.head.len() + self.tail.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// How a response was rewritten.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rewritten {
    pub len: usize,
    pub answers: u16,
    pub ech: EchOutcome,
}

/// Writes the response the client receives, from the client's query and the
/// upstream's answer.
///
/// The transaction id, the question section, and the recursion-desired bit
/// come from the *query*, never from the upstream: a resolver that echoes an
/// upstream's id answers a question the client did not ask. The rcode,
/// truncation bit, and answers come from the upstream.
///
/// Names are written uncompressed. The only edit this function makes is
/// deleting a byte range from one RDATA, and deleting bytes from the middle of
/// a message invalidates every compression pointer targeting anything after
/// the deletion. Uncompressed output costs tens of bytes on a response that
/// crosses a 1420-byte tunnel, and it cannot be wrong.
///
/// The authority and additional sections are dropped: the client is a stub
/// resolver, which needs neither.
///
/// O(answers + bytes), one pass, no allocation.
pub fn write_response(
    out: &mut [u8],
    query: &Message<'_>,
    upstream: &Message<'_>,
    ech: EchPolicy,
) -> Result<Rewritten, DnsError> {
    let mut flags = FLAG_RESPONSE | FLAG_RECURSION_AVAILABLE | upstream.rcode().to_wire();
    if query.recursion_desired() {
        flags |= FLAG_RECURSION_DESIRED;
    }
    if upstream.is_truncated() {
        flags |= FLAG_TRUNCATED;
    }

    let mut cursor = write_header_and_question(out, query, flags)?;
    let (mut answers, mut stripped, mut published) = (0u16, 0u16, false);

    for answer in upstream.answers() {
        let answer = answer?;
        let cut = if answer.rtype.carries_svc_params() {
            ech_param(answer.rdata)?
        } else {
            None
        };
        published |= cut.is_some();
        let rdata = match (cut, ech) {
            (Some(range), EchPolicy::Strip) => {
                stripped += 1;
                Rdata::without(answer.rdata, range).ok_or(DnsError::Truncated)?
            }
            _ => Rdata::verbatim(answer.rdata),
        };
        cursor = write_record(out, cursor, &answer, rdata)?;
        answers += 1;
    }

    out[6..8].copy_from_slice(&answers.to_be_bytes());
    Ok(Rewritten {
        len: cursor,
        answers,
        ech: match (published, stripped) {
            (false, _) => EchOutcome::Absent,
            (true, 0) => EchOutcome::Preserved,
            (true, count) => EchOutcome::Stripped { count },
        },
    })
}

/// The response a refused name receives: `NXDOMAIN` with no answers.
///
/// `NXDOMAIN` rather than a null address, because a client handed `0.0.0.0`
/// opens a connection that fails on a timeout, while a name error fails
/// immediately down a path every browser already has.
pub fn write_refusal(out: &mut [u8], query: &Message<'_>) -> Result<usize, DnsError> {
    let mut flags = FLAG_RESPONSE | FLAG_RECURSION_AVAILABLE | Rcode::NameError.to_wire();
    if query.recursion_desired() {
        flags |= FLAG_RECURSION_DESIRED;
    }
    write_header_and_question(out, query, flags)
}

/// The response an upstream failure receives. Fail visibly rather than
/// silently: a `SERVFAIL` is retried by the stub resolver, whereas a dropped
/// query stalls the application until its own timeout.
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
    let end = HEADER_BYTES + query.question_bytes.len();
    let header = out.get_mut(..end).ok_or(DnsError::OutputTooSmall)?;
    header[0..2].copy_from_slice(&query.id.to_be_bytes());
    header[2..4].copy_from_slice(&flags.to_be_bytes());
    header[4..6].copy_from_slice(&1u16.to_be_bytes());
    header[6..12].fill(0);
    header[HEADER_BYTES..].copy_from_slice(query.question_bytes);
    Ok(end)
}

fn write_record(
    out: &mut [u8],
    at: usize,
    record: &ResourceRecord<'_>,
    rdata: Rdata<'_>,
) -> Result<usize, DnsError> {
    let mut cursor = record.name.write(out, at)?;
    let fields = out
        .get_mut(cursor..cursor + 10)
        .ok_or(DnsError::OutputTooSmall)?;
    fields[0..2].copy_from_slice(&record.rtype.to_wire().to_be_bytes());
    fields[2..4].copy_from_slice(&record.class.to_be_bytes());
    fields[4..8].copy_from_slice(&record.ttl.to_be_bytes());
    let length = u16::try_from(rdata.len()).map_err(|_| DnsError::OutputTooSmall)?;
    fields[8..10].copy_from_slice(&length.to_be_bytes());
    cursor += 10;

    for part in [rdata.head, rdata.tail] {
        let end = cursor + part.len();
        out.get_mut(cursor..end)
            .ok_or(DnsError::OutputTooSmall)?
            .copy_from_slice(part);
        cursor = end;
    }
    Ok(cursor)
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

    /// An HTTPS RDATA in ServiceMode, with params in the ascending key order
    /// RFC 9460 section 2.2 requires.
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

        // The root is the empty name, and it is not the same as any label.
        let root = Name::parse("").expect("the root");
        assert!(root.is_root());
        assert_eq!(root.to_string(), ".");
        assert_eq!(root.wire_len(), 1);
        assert_eq!(name.wire_len(), name.as_bytes().len() + 2);

        // An empty label would encode as the wire's terminator, so `a..b`
        // must not silently become `a`.
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
        // A pointer back to the question's name: the ordinary case, and the
        // one every real response uses.
        let mut message = query("example.com", RecordType::A, 1);
        let name_at = HEADER_BYTES as u16;
        message.extend_from_slice(&(0xc000 | name_at).to_be_bytes());
        let (name, consumed) = Name::read(&message, message.len() - 2).unwrap();
        assert_eq!(name.as_bytes(), b"example.com");
        assert_eq!(consumed, 2, "a pointer costs two bytes where it appears");

        // A pointer to itself is the classic decompression loop. Requiring a
        // strictly backwards target refuses it without a visited set.
        let at = message.len();
        message.extend_from_slice(&(0xc000 | at as u16).to_be_bytes());
        assert_eq!(Name::read(&message, at), Err(DnsError::ForwardPointer));

        // As is a forward pointer, and a two-pointer cycle, which cannot be
        // built at all once every hop must decrease.
        let at = message.len();
        message.extend_from_slice(&(0xc000 | (at as u16 + 8)).to_be_bytes());
        assert_eq!(Name::read(&message, at), Err(DnsError::ForwardPointer));

        // Reserved prefixes and truncation are refusals, not panics.
        assert_eq!(Name::read(&[0x80], 0), Err(DnsError::ReservedLabel));
        assert_eq!(Name::read(&[0x04, b'a'], 0), Err(DnsError::Truncated));
        assert_eq!(Name::read(&[0xc0], 0), Err(DnsError::Truncated));

        // A label carrying the presentation separator would make suffix
        // matching ambiguous.
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
        // The law: `from_wire` and `to_wire` are inverse on every u16, so
        // naming four types cannot lose or alias any of the rest.
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

        // A subdomain inherits its parent's rule, and the parent is named as
        // the reason, which is what makes the verdict explainable.
        assert_eq!(
            judge("static.doubleclick.net"),
            (HostVerdict::Blocked, Some(b"doubleclick.net".to_vec()))
        );
        // The more specific block wins over the less specific inspection.
        assert_eq!(
            judge("img.ads.example.com"),
            (HostVerdict::Blocked, Some(b"ads.example.com".to_vec()))
        );
        assert_eq!(
            judge("www.example.com"),
            (HostVerdict::Inspected, Some(b"example.com".to_vec()))
        );
        assert_eq!(judge("example.org"), (HostVerdict::Allowed, None));

        // A rule matches labels, never substrings: `notexample.com` must not
        // inherit `example.com`.
        assert_eq!(judge("notexample.com"), (HostVerdict::Allowed, None));
    }

    #[test]
    fn ech_is_stripped_for_inspected_hosts_and_for_nothing_else() {
        // The P11 gate as a law over the whole verdict domain.
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
                QueryPlan::Forward { ech } => Err(ech),
            }
        };
        assert_eq!(plan("a.tracker.example"), Ok(b"tracker.example".to_vec()));
        assert_eq!(plan("shop.example"), Err(EchPolicy::Strip));
        assert_eq!(plan("other.example"), Err(EchPolicy::Preserve));
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

        // No ech param at all.
        let plain = https_rdata("target.example", Some(b"\x02h2"), None);
        assert_eq!(ech_param(&plain).unwrap(), None);

        // Descending keys break the ordering RFC 9460 requires, which is what
        // makes a duplicated key unrepresentable rather than ambiguous.
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

        // A compression pointer where RFC 9460 forbids one.
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
        let preserved = write_response(&mut out, &client, &upstream, EchPolicy::Preserve).unwrap();
        assert_eq!(preserved.answers, 2);
        assert_eq!(preserved.ech, EchOutcome::Preserved);
        let parsed = Message::parse(&out[..preserved.len]).unwrap();
        // The id and the question come from the client, never the upstream.
        assert_eq!(parsed.id(), 0x1234);
        assert_eq!(parsed.question(), client.question());
        assert!(parsed.is_response() && parsed.recursion_desired());
        assert_eq!(parsed.rcode(), Rcode::NoError);
        let answers: Vec<ResourceRecord<'_>> = parsed.answers().collect::<Result<_, _>>().unwrap();
        assert_eq!(answers.len(), 2);
        assert!(ech_param(answers[0].rdata).unwrap().is_some());
        assert_eq!(answers[1].rdata, &[93, 184, 215, 14]);

        let mut stripped_out = [0u8; 1500];
        let stripped =
            write_response(&mut stripped_out, &client, &upstream, EchPolicy::Strip).unwrap();
        assert_eq!(stripped.ech, EchOutcome::Stripped { count: 1 });
        let parsed = Message::parse(&stripped_out[..stripped.len]).unwrap();
        let after: Vec<ResourceRecord<'_>> = parsed.answers().collect::<Result<_, _>>().unwrap();
        assert_eq!(after.len(), 2, "stripping removes a param, not a record");

        // Exactly the ech param is gone: the alpn param and the target name
        // survive, and the A record is untouched.
        assert_eq!(ech_param(after[0].rdata).unwrap(), None);
        let remaining: Vec<u16> = svc_params(after[0].rdata)
            .unwrap()
            .map(|param| param.unwrap().key)
            .collect();
        assert_eq!(remaining, vec![SVCPARAM_ALPN]);
        assert_eq!(
            after[0].rdata.len(),
            answers[0].rdata.len() - (4 + ECH_CONFIG.len())
        );
        assert_eq!(after[1].rdata, answers[1].rdata);
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
        for ech in [EchPolicy::Preserve, EchPolicy::Strip] {
            let written = write_response(&mut out, &client, &upstream, ech).unwrap();
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
            write_response(&mut tiny, &client, &upstream, EchPolicy::Preserve).unwrap_err(),
            DnsError::OutputTooSmall
        );
    }
}
