#![no_std]

extern crate alloc;

include!(concat!(env!("OUT_DIR"), "/rustos.registry.rs"));

pub const FRAME_HEADER_LEN: usize = 20;
pub const FRAME_CHECKSUM_LEN: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameError {
    Truncated,
    WrongVersion,
    PayloadTooLarge,
    ChecksumMismatch,
}

pub fn encode_frame(
    version: u32,
    seq: u64,
    message: &impl prost::Message,
) -> Result<alloc::vec::Vec<u8>, prost::EncodeError> {
    let payload_len = message.encoded_len();
    let mut bytes =
        alloc::vec::Vec::with_capacity(FRAME_HEADER_LEN + payload_len + FRAME_CHECKSUM_LEN);

    bytes.extend_from_slice(&version.to_le_bytes());
    bytes.extend_from_slice(&seq.to_le_bytes());
    bytes.extend_from_slice(&(payload_len as u64).to_le_bytes());
    message.encode(&mut bytes)?;
    bytes.extend_from_slice(&embedded_crc32c::crc32c(&bytes).to_le_bytes());

    Ok(bytes)
}

pub fn decode_frame(
    bytes: &[u8],
    expected_version: u32,
) -> Result<(u64, &[u8], usize), FrameError> {
    if bytes.len() < FRAME_HEADER_LEN + FRAME_CHECKSUM_LEN {
        return Err(FrameError::Truncated);
    }

    let version = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    if version != expected_version {
        return Err(FrameError::WrongVersion);
    }

    let seq = u64::from_le_bytes(bytes[4..12].try_into().unwrap());
    let payload_len = u64::from_le_bytes(bytes[12..20].try_into().unwrap());
    let payload_len = usize::try_from(payload_len).map_err(|_| FrameError::PayloadTooLarge)?;

    if payload_len > bytes.len() - FRAME_HEADER_LEN - FRAME_CHECKSUM_LEN {
        return Err(FrameError::Truncated);
    }

    let payload_end = FRAME_HEADER_LEN + payload_len;
    let frame_end = payload_end + FRAME_CHECKSUM_LEN;
    let expected_crc = u32::from_le_bytes(bytes[payload_end..frame_end].try_into().unwrap());

    if embedded_crc32c::crc32c(&bytes[..payload_end]) != expected_crc {
        return Err(FrameError::ChecksumMismatch);
    }

    Ok((seq, &bytes[FRAME_HEADER_LEN..payload_end], frame_end))
}
