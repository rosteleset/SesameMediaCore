use sha2::{Digest, Sha256};

pub const FRAME_MAGIC: &[u8; 8] = b"SESCMAF1";
pub const FRAME_VERSION: u8 = 1;
pub const FRAME_HEADER_BYTES: usize = 80;
pub const DEFAULT_MAX_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameKind {
    Segment = 1,
    Ack = 2,
    Nack = 3,
    Init = 4,
    Part = 5,
    SegmentComplete = 6,
}

impl TryFrom<u8> for FrameKind {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Segment),
            2 => Ok(Self::Ack),
            3 => Ok(Self::Nack),
            4 => Ok(Self::Init),
            5 => Ok(Self::Part),
            6 => Ok(Self::SegmentComplete),
            _ => Err("encrypted_cmaf_unknown_frame_kind".to_string()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub kind: FrameKind,
    pub flags: u16,
    pub sequence: u64,
    pub start_unix_ms: i64,
    pub duration_ms: u32,
    pub part_index: u32,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn segment(sequence: u64, start_unix_ms: i64, duration_ms: u32, payload: Vec<u8>) -> Self {
        Self {
            kind: FrameKind::Segment,
            flags: 0,
            sequence,
            start_unix_ms,
            duration_ms,
            part_index: 0,
            payload,
        }
    }

    pub fn init(sequence: u64, start_unix_ms: i64, payload: Vec<u8>) -> Self {
        Self {
            kind: FrameKind::Init,
            flags: 0,
            sequence,
            start_unix_ms,
            duration_ms: 0,
            part_index: 0,
            payload,
        }
    }

    pub fn part(
        sequence: u64,
        start_unix_ms: i64,
        duration_ms: u32,
        part_index: u32,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            kind: FrameKind::Part,
            flags: 0,
            sequence,
            start_unix_ms,
            duration_ms,
            part_index,
            payload,
        }
    }

    pub fn segment_complete(sequence: u64, start_unix_ms: i64, duration_ms: u32) -> Self {
        Self {
            kind: FrameKind::SegmentComplete,
            flags: 0,
            sequence,
            start_unix_ms,
            duration_ms,
            part_index: u32::MAX,
            payload: Vec::new(),
        }
    }

    pub fn ack(sequence: u64) -> Self {
        Self::ack_part(sequence, 0)
    }

    pub fn ack_part(sequence: u64, part_index: u32) -> Self {
        Self {
            kind: FrameKind::Ack,
            flags: 0,
            sequence,
            start_unix_ms: 0,
            duration_ms: 0,
            part_index,
            payload: Vec::new(),
        }
    }

    pub fn ack_for(frame: &Frame) -> Self {
        let mut ack = Self::ack_part(frame.sequence, frame.part_index);
        ack.flags = frame.kind as u16;
        ack
    }

    pub fn nack(sequence: u64, reason: impl Into<String>) -> Self {
        Self::nack_part(sequence, 0, reason)
    }

    pub fn nack_part(sequence: u64, part_index: u32, reason: impl Into<String>) -> Self {
        Self {
            kind: FrameKind::Nack,
            flags: 0,
            sequence,
            start_unix_ms: 0,
            duration_ms: 0,
            part_index,
            payload: reason.into().into_bytes(),
        }
    }

    pub fn nack_for(frame: &Frame, reason: impl Into<String>) -> Self {
        let mut nack = Self::nack_part(frame.sequence, frame.part_index, reason);
        nack.flags = frame.kind as u16;
        nack
    }
}

pub fn encode_frame(frame: &Frame) -> Result<Vec<u8>, String> {
    let payload_len = u64::try_from(frame.payload.len())
        .map_err(|_| "encrypted_cmaf_payload_too_large".to_string())?;
    let mut output = Vec::with_capacity(FRAME_HEADER_BYTES.saturating_add(frame.payload.len()));
    output.extend_from_slice(FRAME_MAGIC);
    output.push(FRAME_VERSION);
    output.push(frame.kind as u8);
    output.extend_from_slice(&frame.flags.to_be_bytes());
    output.extend_from_slice(&(FRAME_HEADER_BYTES as u32).to_be_bytes());
    output.extend_from_slice(&payload_len.to_be_bytes());
    output.extend_from_slice(&frame.sequence.to_be_bytes());
    output.extend_from_slice(&frame.start_unix_ms.to_be_bytes());
    output.extend_from_slice(&frame.duration_ms.to_be_bytes());
    output.extend_from_slice(&frame.part_index.to_be_bytes());
    output.extend_from_slice(&Sha256::digest(&frame.payload));
    debug_assert_eq!(output.len(), FRAME_HEADER_BYTES);
    output.extend_from_slice(&frame.payload);
    Ok(output)
}

pub struct FrameDecoder {
    buffer: Vec<u8>,
    max_payload_bytes: usize,
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_PAYLOAD_BYTES)
    }
}

impl FrameDecoder {
    pub fn new(max_payload_bytes: usize) -> Self {
        Self {
            buffer: Vec::new(),
            max_payload_bytes: max_payload_bytes.max(1),
        }
    }

    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    pub fn next_frame(&mut self) -> Result<Option<Frame>, String> {
        if self.buffer.len() < FRAME_HEADER_BYTES {
            return Ok(None);
        }
        if self.buffer.get(..8) != Some(FRAME_MAGIC.as_slice()) {
            return Err("encrypted_cmaf_invalid_magic".to_string());
        }
        if self.buffer[8] != FRAME_VERSION {
            return Err("encrypted_cmaf_unsupported_version".to_string());
        }
        let kind = FrameKind::try_from(self.buffer[9])?;
        let flags = u16::from_be_bytes(self.buffer[10..12].try_into().unwrap());
        let header_len = u32::from_be_bytes(self.buffer[12..16].try_into().unwrap()) as usize;
        if header_len != FRAME_HEADER_BYTES {
            return Err("encrypted_cmaf_invalid_header_length".to_string());
        }
        let payload_len_u64 = u64::from_be_bytes(self.buffer[16..24].try_into().unwrap());
        let payload_len = usize::try_from(payload_len_u64)
            .map_err(|_| "encrypted_cmaf_payload_too_large".to_string())?;
        if payload_len > self.max_payload_bytes {
            return Err("encrypted_cmaf_payload_too_large".to_string());
        }
        let frame_len = FRAME_HEADER_BYTES
            .checked_add(payload_len)
            .ok_or_else(|| "encrypted_cmaf_frame_length_overflow".to_string())?;
        if self.buffer.len() < frame_len {
            return Ok(None);
        }

        let sequence = u64::from_be_bytes(self.buffer[24..32].try_into().unwrap());
        let start_unix_ms = i64::from_be_bytes(self.buffer[32..40].try_into().unwrap());
        let duration_ms = u32::from_be_bytes(self.buffer[40..44].try_into().unwrap());
        let part_index = u32::from_be_bytes(self.buffer[44..48].try_into().unwrap());
        let expected_hash: [u8; 32] = self.buffer[48..80].try_into().unwrap();
        let payload = self.buffer[FRAME_HEADER_BYTES..frame_len].to_vec();
        if Sha256::digest(&payload).as_slice() != expected_hash {
            return Err("encrypted_cmaf_payload_hash_mismatch".to_string());
        }
        self.buffer.drain(..frame_len);
        Ok(Some(Frame {
            kind,
            flags,
            sequence,
            start_unix_ms,
            duration_ms,
            part_index,
            payload,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoder_accepts_arbitrary_transport_chunking() {
        let encoded = encode_frame(&Frame::segment(7, 123_456, 4_000, vec![0x5a; 4097])).unwrap();
        let mut decoder = FrameDecoder::default();
        for chunk in encoded.chunks(1316) {
            decoder.push(chunk);
        }
        assert_eq!(
            decoder.next_frame().unwrap(),
            Some(Frame::segment(7, 123_456, 4_000, vec![0x5a; 4097]))
        );
        assert!(decoder.next_frame().unwrap().is_none());
    }

    #[test]
    fn decoder_rejects_corrupted_payload() {
        let mut encoded = encode_frame(&Frame::segment(1, 0, 1, vec![1, 2, 3])).unwrap();
        *encoded.last_mut().unwrap() ^= 0xff;
        let mut decoder = FrameDecoder::default();
        decoder.push(&encoded);
        assert_eq!(
            decoder.next_frame().unwrap_err(),
            "encrypted_cmaf_payload_hash_mismatch"
        );
    }

    #[test]
    fn part_and_completion_round_trip_with_identity_fields() {
        let frames = [
            Frame::init(9, 123_000, vec![1, 2]),
            Frame::part(9, 123_000, 500, 3, vec![3, 4]),
            Frame::segment_complete(9, 123_000, 4_000),
            Frame::ack_part(9, 3),
            Frame::nack_part(9, 3, "retry"),
        ];
        let mut decoder = FrameDecoder::default();
        for expected in frames {
            decoder.push(&encode_frame(&expected).unwrap());
            assert_eq!(decoder.next_frame().unwrap(), Some(expected));
        }
    }
}
