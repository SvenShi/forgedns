// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::core::error::DnsError;
use crate::proto::{Name, RecordType};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DS {
    key_tag: u16,
    algorithm: u8,
    digest_type: u8,
    digest: Box<[u8]>,
}
impl DS {
    pub fn new(key_tag: u16, algorithm: u8, digest_type: u8, digest: Box<[u8]>) -> Self {
        Self {
            key_tag,
            algorithm,
            digest_type,
            digest,
        }
    }

    pub fn key_tag(&self) -> u16 {
        self.key_tag
    }

    pub fn algorithm(&self) -> u8 {
        self.algorithm
    }

    pub fn digest_type(&self) -> u8 {
        self.digest_type
    }

    pub fn digest(&self) -> &[u8] {
        &self.digest
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CDS(pub DS);
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DLV(pub DS);
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TA(pub DS);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SSHFP {
    algorithm: u8,
    fp_type: u8,
    fingerprint: Box<[u8]>,
}
impl SSHFP {
    pub fn new(algorithm: u8, fp_type: u8, fingerprint: Box<[u8]>) -> Self {
        Self {
            algorithm,
            fp_type,
            fingerprint,
        }
    }

    pub fn algorithm(&self) -> u8 {
        self.algorithm
    }

    pub fn fp_type(&self) -> u8 {
        self.fp_type
    }

    pub fn fingerprint(&self) -> &[u8] {
        &self.fingerprint
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DNSKEY {
    flags: u16,
    protocol: u8,
    algorithm: u8,
    public_key: Box<[u8]>,
}
impl DNSKEY {
    pub fn new(flags: u16, protocol: u8, algorithm: u8, public_key: Box<[u8]>) -> Self {
        Self {
            flags,
            protocol,
            algorithm,
            public_key,
        }
    }

    pub fn flags(&self) -> u16 {
        self.flags
    }

    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    pub fn algorithm(&self) -> u8 {
        self.algorithm
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CDNSKEY(pub DNSKEY);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DHCID(pub Box<[u8]>);
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OPENPGPKEY(pub Box<[u8]>);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TLSA {
    usage: u8,
    selector: u8,
    matching_type: u8,
    certificate: Box<[u8]>,
}
impl TLSA {
    pub fn new(usage: u8, selector: u8, matching_type: u8, certificate: Box<[u8]>) -> Self {
        Self {
            usage,
            selector,
            matching_type,
            certificate,
        }
    }

    pub fn usage(&self) -> u8 {
        self.usage
    }

    pub fn selector(&self) -> u8 {
        self.selector
    }

    pub fn matching_type(&self) -> u8 {
        self.matching_type
    }

    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SMIMEA(pub TLSA);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TypeBitMaps {
    wire: Box<[u8]>,
    types: Vec<RecordType>,
}
impl TypeBitMaps {
    /// Decode type bit maps from wire data using RFC 4034 / RFC 5155 validation
    /// rules.
    pub fn try_from_wire(wire: Box<[u8]>) -> Result<Self, DnsError> {
        let types = decode_type_bit_maps(&wire)?;
        Ok(Self { wire, types })
    }

    /// Decode type bit maps from trusted wire data.
    ///
    /// Wire decoders should prefer [`TypeBitMaps::try_from_wire`].
    pub fn from_wire(wire: Box<[u8]>) -> Self {
        let types = decode_type_bit_maps(&wire).unwrap_or_default();
        Self { wire, types }
    }

    pub fn from_types(types: Vec<RecordType>) -> Self {
        let wire = encode_type_bit_maps(&types).into_boxed_slice();
        Self { wire, types }
    }

    pub fn wire_data(&self) -> &[u8] {
        &self.wire
    }

    pub fn types(&self) -> &[RecordType] {
        &self.types
    }
}

fn decode_type_bit_maps(wire: &[u8]) -> Result<Vec<RecordType>, DnsError> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    let mut last_window = None::<u8>;
    while cursor + 2 <= wire.len() {
        let window = wire[cursor];
        let len = wire[cursor + 1] as usize;
        cursor += 2;
        if last_window.is_some_and(|prev| window <= prev) {
            return Err(DnsError::protocol(
                "out of order NSEC(3) block in type bitmap",
            ));
        }
        if len == 0 {
            return Err(DnsError::protocol("empty NSEC(3) block in type bitmap"));
        }
        if len > 32 {
            return Err(DnsError::protocol("NSEC(3) block too long in type bitmap"));
        }
        if cursor + len > wire.len() {
            return Err(DnsError::protocol(
                "overflowing NSEC(3) block in type bitmap",
            ));
        }
        for (octet_index, octet) in wire[cursor..cursor + len].iter().enumerate() {
            if *octet == 0 {
                continue;
            }
            for bit in 0..8 {
                if (octet & (1 << (7 - bit))) != 0 {
                    let low = (octet_index as u16) * 8 + bit as u16;
                    let rr_type = ((window as u16) << 8) | low;
                    out.push(RecordType::from(rr_type));
                }
            }
        }
        cursor += len;
        last_window = Some(window);
    }
    if cursor != wire.len() {
        return Err(DnsError::protocol("overflow unpacking NSEC(3)"));
    }
    Ok(out)
}

fn encode_type_bit_maps(types: &[RecordType]) -> Vec<u8> {
    let mut codes: Vec<u16> = types
        .iter()
        .map(|t| u16::from(*t))
        .filter(|code| *code != 0)
        .collect();
    codes.sort_unstable();
    codes.dedup();

    let mut out = Vec::new();
    let mut i = 0usize;
    while i < codes.len() {
        let window = (codes[i] >> 8) as u8;
        let start = i;
        while i < codes.len() && (codes[i] >> 8) as u8 == window {
            i += 1;
        }
        let group = &codes[start..i];
        let mut bitmap = [0u8; 32];
        let mut max_index = 0usize;
        for code in group {
            let low = (code & 0x00FF) as usize;
            let byte_index = low / 8;
            let bit_index = low % 8;
            bitmap[byte_index] |= 1 << (7 - bit_index);
            max_index = max_index.max(byte_index);
        }
        out.push(window);
        out.push((max_index + 1) as u8);
        out.extend_from_slice(&bitmap[..=max_index]);
    }
    out
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CSYNC {
    serial: u32,
    flags: u16,
    type_bitmap: TypeBitMaps,
}
impl CSYNC {
    pub fn new(serial: u32, flags: u16, type_bitmap: TypeBitMaps) -> Self {
        Self {
            serial,
            flags,
            type_bitmap,
        }
    }

    pub fn serial(&self) -> u32 {
        self.serial
    }

    pub fn flags(&self) -> u16 {
        self.flags
    }

    pub fn type_bitmap(&self) -> &[u8] {
        self.type_bitmap.wire_data()
    }

    pub fn type_bitmap_types(&self) -> &[RecordType] {
        self.type_bitmap.types()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ZONEMD {
    serial: u32,
    scheme: u8,
    hash: u8,
    digest: Box<[u8]>,
}
impl ZONEMD {
    pub fn new(serial: u32, scheme: u8, hash: u8, digest: Box<[u8]>) -> Self {
        Self {
            serial,
            scheme,
            hash,
            digest,
        }
    }

    pub fn serial(&self) -> u32 {
        self.serial
    }

    pub fn scheme(&self) -> u8 {
        self.scheme
    }

    pub fn hash(&self) -> u8 {
        self.hash
    }

    pub fn digest(&self) -> &[u8] {
        &self.digest
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CERT {
    cert_type: u16,
    key_tag: u16,
    algorithm: u8,
    certificate: Box<[u8]>,
}
impl CERT {
    pub fn new(cert_type: u16, key_tag: u16, algorithm: u8, certificate: Box<[u8]>) -> Self {
        Self {
            cert_type,
            key_tag,
            algorithm,
            certificate,
        }
    }

    pub fn cert_type(&self) -> u16 {
        self.cert_type
    }

    pub fn key_tag(&self) -> u16 {
        self.key_tag
    }

    pub fn algorithm(&self) -> u8 {
        self.algorithm
    }

    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RRSIG {
    pub(crate) type_covered: u16,
    pub(crate) algorithm: u8,
    pub(crate) labels: u8,
    pub(crate) orig_ttl: u32,
    pub(crate) expiration: u32,
    pub(crate) inception: u32,
    pub(crate) key_tag: u16,
    pub(crate) signer_name: Name,
    pub(crate) signature: Box<[u8]>,
}
impl RRSIG {
    pub fn type_covered(&self) -> u16 {
        self.type_covered
    }

    pub fn algorithm(&self) -> u8 {
        self.algorithm
    }

    pub fn labels(&self) -> u8 {
        self.labels
    }

    pub fn orig_ttl(&self) -> u32 {
        self.orig_ttl
    }

    pub fn expiration(&self) -> u32 {
        self.expiration
    }

    pub fn inception(&self) -> u32 {
        self.inception
    }

    pub fn key_tag(&self) -> u16 {
        self.key_tag
    }

    pub fn signer_name(&self) -> &Name {
        &self.signer_name
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NSEC {
    next_domain: Name,
    type_bitmap: TypeBitMaps,
}
impl NSEC {
    pub fn new(next_domain: Name, type_bitmap: TypeBitMaps) -> Self {
        Self {
            next_domain,
            type_bitmap,
        }
    }

    pub fn next_domain(&self) -> &Name {
        &self.next_domain
    }

    pub fn type_bitmap(&self) -> &[u8] {
        self.type_bitmap.wire_data()
    }

    pub fn type_bitmap_types(&self) -> &[RecordType] {
        self.type_bitmap.types()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NSEC3 {
    hash: u8,
    flags: u8,
    iterations: u16,
    salt: Box<[u8]>,
    next_domain: Box<[u8]>,
    type_bitmap: TypeBitMaps,
}
impl NSEC3 {
    pub fn new(
        hash: u8,
        flags: u8,
        iterations: u16,
        salt: Box<[u8]>,
        next_domain: Box<[u8]>,
        type_bitmap: TypeBitMaps,
    ) -> Self {
        Self {
            hash,
            flags,
            iterations,
            salt,
            next_domain,
            type_bitmap,
        }
    }

    pub fn hash(&self) -> u8 {
        self.hash
    }

    pub fn flags(&self) -> u8 {
        self.flags
    }

    pub fn iterations(&self) -> u16 {
        self.iterations
    }

    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    pub fn next_domain(&self) -> &[u8] {
        &self.next_domain
    }

    pub fn type_bitmap(&self) -> &[u8] {
        self.type_bitmap.wire_data()
    }

    pub fn type_bitmap_types(&self) -> &[RecordType] {
        self.type_bitmap.types()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NSEC3PARAM {
    hash: u8,
    flags: u8,
    iterations: u16,
    salt: Box<[u8]>,
}
impl NSEC3PARAM {
    pub fn new(hash: u8, flags: u8, iterations: u16, salt: Box<[u8]>) -> Self {
        Self {
            hash,
            flags,
            iterations,
            salt,
        }
    }

    pub fn hash(&self) -> u8 {
        self.hash
    }

    pub fn flags(&self) -> u8 {
        self.flags
    }

    pub fn iterations(&self) -> u16 {
        self.iterations
    }

    pub fn salt(&self) -> &[u8] {
        &self.salt
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HIP {
    hit: Box<[u8]>,
    public_key_algorithm: u8,
    public_key: Box<[u8]>,
    rendezvous_servers: Vec<Name>,
}
impl HIP {
    pub fn new(
        hit: Box<[u8]>,
        public_key_algorithm: u8,
        public_key: Box<[u8]>,
        rendezvous_servers: Vec<Name>,
    ) -> Self {
        Self {
            hit,
            public_key_algorithm,
            public_key,
            rendezvous_servers,
        }
    }

    pub fn hit(&self) -> &[u8] {
        &self.hit
    }

    pub fn public_key_algorithm(&self) -> u8 {
        self.public_key_algorithm
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn rendezvous_servers(&self) -> &[Name] {
        &self.rendezvous_servers
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NINFO(pub Box<[u8]>);
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RKEY(pub Box<[u8]>);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TALINK {
    previous_name: Name,
    next_name: Name,
}
impl TALINK {
    pub fn new(previous_name: Name, next_name: Name) -> Self {
        Self {
            previous_name,
            next_name,
        }
    }

    pub fn previous_name(&self) -> &Name {
        &self.previous_name
    }

    pub fn next_name(&self) -> &Name {
        &self.next_name
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SIG(pub RRSIG);
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KEY(pub DNSKEY);
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NXT(pub NSEC);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TKEY {
    algorithm: Name,
    inception: u32,
    expiration: u32,
    mode: u16,
    error: u16,
    key: Box<[u8]>,
    other_data: Box<[u8]>,
}
impl TKEY {
    pub fn new(
        algorithm: Name,
        inception: u32,
        expiration: u32,
        mode: u16,
        error: u16,
        key: Box<[u8]>,
        other_data: Box<[u8]>,
    ) -> Self {
        Self {
            algorithm,
            inception,
            expiration,
            mode,
            error,
            key,
            other_data,
        }
    }

    pub fn algorithm(&self) -> &Name {
        &self.algorithm
    }

    pub fn inception(&self) -> u32 {
        self.inception
    }

    pub fn expiration(&self) -> u32 {
        self.expiration
    }

    pub fn mode(&self) -> u16 {
        self.mode
    }

    pub fn error(&self) -> u16 {
        self.error
    }

    pub fn key(&self) -> &[u8] {
        &self.key
    }

    pub fn other_data(&self) -> &[u8] {
        &self.other_data
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TSIG {
    algorithm: Name,
    time_signed: u64,
    fudge: u16,
    mac: Box<[u8]>,
    orig_id: u16,
    error: u16,
    other_data: Box<[u8]>,
}
impl TSIG {
    pub fn new(
        algorithm: Name,
        time_signed: u64,
        fudge: u16,
        mac: Box<[u8]>,
        orig_id: u16,
        error: u16,
        other_data: Box<[u8]>,
    ) -> Self {
        Self {
            algorithm,
            time_signed,
            fudge,
            mac,
            orig_id,
            error,
            other_data,
        }
    }

    pub fn algorithm(&self) -> &Name {
        &self.algorithm
    }

    pub fn time_signed(&self) -> u64 {
        self.time_signed
    }

    pub fn fudge(&self) -> u16 {
        self.fudge
    }

    pub fn mac(&self) -> &[u8] {
        &self.mac
    }

    pub fn orig_id(&self) -> u16 {
        self.orig_id
    }

    pub fn error(&self) -> u16 {
        self.error
    }

    pub fn other_data(&self) -> &[u8] {
        &self.other_data
    }
}
