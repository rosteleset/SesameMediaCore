pub const PACKET_MAGIC: &[u8; 8] = b"SESSFRM1";
pub const PACKET_HEADER_BYTES: usize = 24;
pub const DEFAULT_MAX_PAYLOAD_BYTES: usize = 64 * 1024;

const FLAG_MARKER: u16 = 1 << 0;
const FLAG_KEYFRAME: u16 = 1 << 1;
const FLAG_H265: u16 = 1 << 2;
const KNOWN_FLAGS: u16 = FLAG_MARKER | FLAG_KEYFRAME | FLAG_H265;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VideoCodec {
    H264,
    H265,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Packet {
    pub sequence: u16,
    pub timestamp: u32,
    pub marker: bool,
    pub keyframe: bool,
    pub codec: VideoCodec,
    pub payload: Vec<u8>,
}

pub fn encode_packet(packet: &Packet) -> Result<Vec<u8>, String> {
    let payload_len = u32::try_from(packet.payload.len())
        .map_err(|_| "sframe_wire_payload_too_large".to_string())?;
    let mut flags = 0u16;
    if packet.marker {
        flags |= FLAG_MARKER;
    }
    if packet.keyframe {
        flags |= FLAG_KEYFRAME;
    }
    if packet.codec == VideoCodec::H265 {
        flags |= FLAG_H265;
    }

    let mut output = Vec::with_capacity(PACKET_HEADER_BYTES.saturating_add(packet.payload.len()));
    output.extend_from_slice(PACKET_MAGIC);
    output.extend_from_slice(&payload_len.to_be_bytes());
    output.extend_from_slice(&packet.sequence.to_be_bytes());
    output.extend_from_slice(&flags.to_be_bytes());
    output.extend_from_slice(&packet.timestamp.to_be_bytes());
    output.extend_from_slice(&0u32.to_be_bytes());
    debug_assert_eq!(output.len(), PACKET_HEADER_BYTES);
    output.extend_from_slice(&packet.payload);
    Ok(output)
}

pub struct PacketDecoder {
    buffer: Vec<u8>,
    max_payload_bytes: usize,
}

impl Default for PacketDecoder {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_PAYLOAD_BYTES)
    }
}

impl PacketDecoder {
    pub fn new(max_payload_bytes: usize) -> Self {
        Self {
            buffer: Vec::new(),
            max_payload_bytes: max_payload_bytes.max(1),
        }
    }

    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    pub fn next_packet(&mut self) -> Result<Option<Packet>, String> {
        if self.buffer.len() < PACKET_HEADER_BYTES {
            return Ok(None);
        }
        if self.buffer.get(..PACKET_MAGIC.len()) != Some(PACKET_MAGIC.as_slice()) {
            return Err("sframe_wire_invalid_magic".to_string());
        }

        let payload_len = u32::from_be_bytes(self.buffer[8..12].try_into().unwrap()) as usize;
        if payload_len > self.max_payload_bytes {
            return Err("sframe_wire_payload_too_large".to_string());
        }
        let packet_len = PACKET_HEADER_BYTES
            .checked_add(payload_len)
            .ok_or_else(|| "sframe_wire_packet_length_overflow".to_string())?;
        if self.buffer.len() < packet_len {
            return Ok(None);
        }

        let sequence = u16::from_be_bytes(self.buffer[12..14].try_into().unwrap());
        let flags = u16::from_be_bytes(self.buffer[14..16].try_into().unwrap());
        if flags & !KNOWN_FLAGS != 0 {
            return Err("sframe_wire_unknown_flags".to_string());
        }
        let timestamp = u32::from_be_bytes(self.buffer[16..20].try_into().unwrap());
        if self.buffer[20..24] != [0; 4] {
            return Err("sframe_wire_reserved_bytes_nonzero".to_string());
        }
        let payload = self.buffer[PACKET_HEADER_BYTES..packet_len].to_vec();
        self.buffer.drain(..packet_len);

        Ok(Some(Packet {
            sequence,
            timestamp,
            marker: flags & FLAG_MARKER != 0,
            keyframe: flags & FLAG_KEYFRAME != 0,
            codec: if flags & FLAG_H265 != 0 {
                VideoCodec::H265
            } else {
                VideoCodec::H264
            },
            payload,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoder_accepts_arbitrary_transport_chunking() {
        let packet = Packet {
            sequence: 65_530,
            timestamp: 0xfedc_ba98,
            marker: true,
            keyframe: true,
            codec: VideoCodec::H265,
            payload: vec![0x5a; 4_097],
        };
        let encoded = encode_packet(&packet).unwrap();
        let mut decoder = PacketDecoder::default();
        for chunk in encoded.chunks(317) {
            decoder.push(chunk);
        }
        assert_eq!(decoder.next_packet().unwrap(), Some(packet));
        assert!(decoder.next_packet().unwrap().is_none());
    }

    #[test]
    fn decoder_rejects_oversized_payload_before_waiting_for_it() {
        let packet = Packet {
            sequence: 1,
            timestamp: 2,
            marker: false,
            keyframe: false,
            codec: VideoCodec::H264,
            payload: vec![3; 128],
        };
        let encoded = encode_packet(&packet).unwrap();
        let mut decoder = PacketDecoder::new(64);
        decoder.push(&encoded[..PACKET_HEADER_BYTES]);
        assert_eq!(
            decoder.next_packet().unwrap_err(),
            "sframe_wire_payload_too_large"
        );
    }

    #[test]
    fn decoder_rejects_unknown_flags() {
        let packet = Packet {
            sequence: 1,
            timestamp: 2,
            marker: false,
            keyframe: false,
            codec: VideoCodec::H264,
            payload: vec![3],
        };
        let mut encoded = encode_packet(&packet).unwrap();
        encoded[14] = 0x80;
        let mut decoder = PacketDecoder::default();
        decoder.push(&encoded);
        assert_eq!(
            decoder.next_packet().unwrap_err(),
            "sframe_wire_unknown_flags"
        );
    }
}
