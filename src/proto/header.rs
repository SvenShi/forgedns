/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! DNS message header flags and identity fields.

use crate::proto::{MessageType, Opcode, Rcode};

/// Public message header carried by the owned DNS message model.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Hash)]
pub struct Header {
    pub(super) id: u16,
    pub(super) message_type: MessageType,
    pub(super) opcode: Opcode,
    pub(super) authoritative: bool,
    pub(super) truncated: bool,
    pub(super) recursion_desired: bool,
    pub(super) recursion_available: bool,
    pub(super) authentic_data: bool,
    pub(super) checking_disabled: bool,
    pub(super) rcode: Rcode,
}

impl Default for Header {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
impl Header {
    pub fn new() -> Self {
        Self {
            id: 0,
            message_type: MessageType::Query,
            opcode: Opcode::Query,
            authoritative: false,
            truncated: false,
            recursion_desired: false,
            recursion_available: false,
            authentic_data: false,
            checking_disabled: false,
            rcode: Rcode::NoError,
        }
    }

    pub fn id(&self) -> u16 {
        self.id
    }

    pub fn set_id(&mut self, id: u16) {
        self.id = id;
    }

    pub fn message_type(&self) -> MessageType {
        self.message_type
    }

    pub fn set_message_type(&mut self, kind: MessageType) {
        self.message_type = kind;
    }

    pub fn opcode(&self) -> Opcode {
        self.opcode
    }

    pub fn set_opcode(&mut self, opcode: Opcode) {
        self.opcode = opcode;
    }

    pub fn authoritative(&self) -> bool {
        self.authoritative
    }

    pub fn set_authoritative(&mut self, value: bool) {
        self.authoritative = value;
    }

    pub fn truncated(&self) -> bool {
        self.truncated
    }

    pub fn set_truncated(&mut self, value: bool) {
        self.truncated = value;
    }

    pub fn recursion_desired(&self) -> bool {
        self.recursion_desired
    }

    pub fn set_recursion_desired(&mut self, value: bool) {
        self.recursion_desired = value;
    }

    pub fn recursion_available(&self) -> bool {
        self.recursion_available
    }

    pub fn set_recursion_available(&mut self, value: bool) {
        self.recursion_available = value;
    }

    pub fn authentic_data(&self) -> bool {
        self.authentic_data
    }

    pub fn set_authentic_data(&mut self, value: bool) {
        self.authentic_data = value;
    }

    pub fn checking_disabled(&self) -> bool {
        self.checking_disabled
    }

    pub fn set_checking_disabled(&mut self, value: bool) {
        self.checking_disabled = value;
    }

    pub fn rcode(&self) -> Rcode {
        self.rcode
    }

    pub fn set_rcode(&mut self, rcode: Rcode) {
        self.rcode = rcode;
    }

    pub(crate) fn from_wire(id: u16, flags: u16) -> Self {
        Self {
            id,
            message_type: if (flags & 0x8000) != 0 {
                MessageType::Response
            } else {
                MessageType::Query
            },
            opcode: Opcode::from(((flags >> 11) & 0x0f) as u8),
            authoritative: (flags & 0x0400) != 0,
            truncated: (flags & 0x0200) != 0,
            recursion_desired: (flags & 0x0100) != 0,
            recursion_available: (flags & 0x0080) != 0,
            authentic_data: (flags & 0x0020) != 0,
            checking_disabled: (flags & 0x0010) != 0,
            rcode: Rcode::NoError,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_wire_decodes_dns_header_flags() {
        let header = Header::from_wire(0x1234, 0xA5B3);

        assert_eq!(header.id(), 0x1234);
        assert_eq!(header.message_type(), MessageType::Response);
        assert_eq!(header.opcode(), Opcode::Notify);
        assert!(header.authoritative());
        assert!(header.recursion_desired());
        assert!(header.recursion_available());
        assert!(header.authentic_data());
        assert!(header.checking_disabled());
    }
}
