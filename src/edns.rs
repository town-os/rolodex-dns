// EDNS (Extension Mechanisms for DNS) support (RFC 6891).
//
// Extracts EDNS information from incoming queries and builds OPT records
// for responses, enabling features like larger payload sizes and DNSSEC.

/// Context extracted from an EDNS OPT record in a DNS query.
#[derive(Debug, Clone)]
pub struct EdnsContext {
    /// EDNS version (only version 0 is supported).
    pub version: u8,
    /// Maximum UDP payload size the client can accept.
    pub max_payload: u16,
    /// Whether the client wants DNSSEC records (DO bit).
    pub dnssec_ok: bool,
}

impl Default for EdnsContext {
    fn default() -> Self {
        Self {
            version: 0,
            max_payload: 4096,
            dnssec_ok: false,
        }
    }
}

impl EdnsContext {
    /// Extracts EDNS context from a DNS message.
    /// Returns None if the message has no OPT record.
    pub fn from_message(message: &hickory_proto::op::Message) -> Option<Self> {
        let edns = message.extensions().as_ref()?;
        Some(Self {
            version: edns.version(),
            max_payload: edns.max_payload(),
            dnssec_ok: edns.flags().dnssec_ok,
        })
    }

    /// Returns true if the EDNS version is unsupported (> 0).
    pub fn is_unsupported_version(&self) -> bool {
        self.version > 0
    }
}

/// Adds an OPT record to a DNS response message.
pub fn add_edns_to_response(
    response: &mut hickory_proto::op::Message,
    max_payload: u16,
    dnssec_ok: bool,
) {
    let mut edns = hickory_proto::op::Edns::new();
    edns.set_version(0);
    edns.set_max_payload(max_payload);
    edns.set_dnssec_ok(dnssec_ok);
    response.set_edns(edns);
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, MessageType, OpCode};
    use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};

    #[test]
    fn test_edns_context_default() {
        let ctx = EdnsContext::default();
        assert_eq!(ctx.version, 0);
        assert_eq!(ctx.max_payload, 4096);
        assert!(!ctx.dnssec_ok);
        assert!(!ctx.is_unsupported_version());
    }

    #[test]
    fn test_edns_context_unsupported_version() {
        let ctx = EdnsContext {
            version: 1,
            max_payload: 4096,
            dnssec_ok: false,
        };
        assert!(ctx.is_unsupported_version());
    }

    #[test]
    fn test_edns_from_message_without_opt() {
        let msg = Message::new();
        assert!(EdnsContext::from_message(&msg).is_none());
    }

    #[test]
    fn test_edns_from_message_with_opt() {
        let mut msg = Message::new();
        msg.set_id(1234);
        msg.set_message_type(MessageType::Query);
        msg.set_op_code(OpCode::Query);

        let mut edns = hickory_proto::op::Edns::new();
        edns.set_version(0);
        edns.set_max_payload(1232);
        edns.set_dnssec_ok(true);
        msg.set_edns(edns);

        let bytes = msg.to_bytes().unwrap();
        let parsed = Message::from_bytes(&bytes).unwrap();
        let ctx = EdnsContext::from_message(&parsed).unwrap();
        assert_eq!(ctx.version, 0);
        assert_eq!(ctx.max_payload, 1232);
        assert!(ctx.dnssec_ok);
    }

    #[test]
    fn test_add_edns_to_response() {
        let mut response = Message::new();
        response.set_id(5678);
        response.set_message_type(MessageType::Response);

        add_edns_to_response(&mut response, 4096, true);

        let bytes = response.to_bytes().unwrap();
        let parsed = Message::from_bytes(&bytes).unwrap();
        let edns = parsed.extensions().as_ref().unwrap();
        assert_eq!(edns.version(), 0);
        assert_eq!(edns.max_payload(), 4096);
        assert!(edns.flags().dnssec_ok);
    }
}
