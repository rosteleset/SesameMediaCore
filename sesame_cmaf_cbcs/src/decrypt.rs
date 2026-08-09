use std::collections::{BTreeSet, HashMap};

use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes128;
use zeroize::Zeroizing;

const BOX_HEADER_BYTES: usize = 8;
const AES_BLOCK_BYTES: usize = 16;
const COLOR_BOX: [u8; 19] = [
    0x00, 0x00, 0x00, 0x13, b'c', b'o', b'l', b'r', b'n', b'c', b'l', b'x', 0x00, 0x02, 0x00, 0x02,
    0x00, 0x02, 0x00,
];

#[derive(Clone)]
pub struct CbcsContentKey {
    pub kid: [u8; 16],
    pub cek: Zeroizing<[u8; 16]>,
}

impl CbcsContentKey {
    pub fn new(kid: [u8; 16], cek: [u8; 16]) -> Self {
        Self {
            kid,
            cek: Zeroizing::new(cek),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CmafFragmentTimeline {
    pub base_time_microseconds: u64,
    pub fragment_sequence: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct CbcsDecryptionContext {
    tracks: HashMap<u32, TrackProtection>,
}

impl CbcsDecryptionContext {
    pub fn key_ids(&self) -> Vec<[u8; 16]> {
        self.tracks
            .values()
            .map(|track| track.kid)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

#[derive(Clone, Debug)]
pub struct ClearCmafInitialization {
    pub data: Vec<u8>,
    pub context: CbcsDecryptionContext,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TrackKind {
    Video,
    Audio,
}

#[derive(Clone, Debug)]
struct TrackProtection {
    timescale: u32,
    kid: [u8; 16],
    crypt_blocks: u8,
    skip_blocks: u8,
    per_sample_iv_size: usize,
    constant_iv: Option<[u8; 16]>,
}

#[derive(Clone, Copy, Debug)]
struct Mp4Box {
    start: usize,
    size: usize,
    header_size: usize,
    kind: [u8; 4],
}

impl Mp4Box {
    fn payload_start(self) -> usize {
        self.start + self.header_size
    }

    fn end(self) -> usize {
        self.start + self.size
    }
}

#[derive(Clone, Copy)]
struct SizeAdjustment {
    entry: Mp4Box,
    bytes: usize,
}

pub fn clear_cbcs_cmaf_initialization(encrypted: &[u8]) -> Result<ClearCmafInitialization, String> {
    let top = parse_children(encrypted, 0, encrypted.len())?;
    let moov = top
        .iter()
        .copied()
        .find(|entry| entry.kind == *b"moov")
        .ok_or_else(|| "cbcs_missing_moov".to_string())?;

    let mut tracks = HashMap::new();
    let mut removals = Vec::new();
    let mut reductions: HashMap<usize, SizeAdjustment> = HashMap::new();
    let mut type_patches = Vec::new();

    for trak in parse_children(encrypted, moov.payload_start(), moov.end())?
        .into_iter()
        .filter(|entry| entry.kind == *b"trak")
    {
        let Some(tkhd) = direct_child(encrypted, trak, *b"tkhd")? else {
            continue;
        };
        let Some(mdia) = direct_child(encrypted, trak, *b"mdia")? else {
            continue;
        };
        let Some(mdhd) = direct_child(encrypted, mdia, *b"mdhd")? else {
            continue;
        };
        let Some(hdlr) = direct_child(encrypted, mdia, *b"hdlr")? else {
            continue;
        };
        let Some(minf) = direct_child(encrypted, mdia, *b"minf")? else {
            continue;
        };
        let Some(stbl) = direct_child(encrypted, minf, *b"stbl")? else {
            continue;
        };
        let Some(stsd) = direct_child(encrypted, stbl, *b"stsd")? else {
            continue;
        };

        let track_id = parse_track_id(encrypted, tkhd)?;
        let handler = read_fourcc(encrypted, hdlr.payload_start() + 8)?;
        let sample_entry = parse_children(encrypted, stsd.payload_start() + 8, stsd.end())?
            .into_iter()
            .find(|entry| matches!(&entry.kind, b"encv" | b"enca"));
        let Some(sample_entry) = sample_entry else {
            continue;
        };
        let kind = if sample_entry.kind == *b"encv" {
            TrackKind::Video
        } else {
            TrackKind::Audio
        };
        let expected_handler = match kind {
            TrackKind::Video => *b"vide",
            TrackKind::Audio => *b"soun",
        };
        if handler != expected_handler {
            return Err(format!("cbcs_track_handler_mismatch:{track_id}"));
        }

        let children_start = sample_entry_children_start(encrypted, sample_entry)?;
        let sample_children = parse_children(encrypted, children_start, sample_entry.end())?;
        let sinf = sample_children
            .iter()
            .copied()
            .find(|entry| entry.kind == *b"sinf")
            .ok_or_else(|| format!("cbcs_missing_sinf:{track_id}"))?;
        let frma = direct_child(encrypted, sinf, *b"frma")?
            .ok_or_else(|| format!("cbcs_missing_frma:{track_id}"))?;
        let schm = direct_child(encrypted, sinf, *b"schm")?
            .ok_or_else(|| format!("cbcs_missing_schm:{track_id}"))?;
        let schi = direct_child(encrypted, sinf, *b"schi")?
            .ok_or_else(|| format!("cbcs_missing_schi:{track_id}"))?;
        let tenc = direct_child(encrypted, schi, *b"tenc")?
            .ok_or_else(|| format!("cbcs_missing_tenc:{track_id}"))?;
        if read_fourcc(encrypted, schm.payload_start() + 4)? != *b"cbcs" {
            return Err(format!("cbcs_unsupported_scheme:{track_id}"));
        }

        let original_format = read_fourcc(encrypted, frma.payload_start())?;
        let protection = parse_track_protection(
            encrypted,
            track_id,
            kind,
            parse_timescale(encrypted, mdhd)?,
            tenc,
        )?;
        if tracks.insert(track_id, protection).is_some() {
            return Err(format!("cbcs_duplicate_track:{track_id}"));
        }

        removals.push(sinf);
        type_patches.push((sample_entry.start + 4, original_format));
        for entry in [sample_entry, stsd, stbl, minf, mdia, trak, moov] {
            add_adjustment(&mut reductions, entry, sinf.size)?;
        }
    }

    if tracks.is_empty() {
        return Err("cbcs_missing_protected_tracks".to_string());
    }

    let mut clear = encrypted.to_vec();
    for (offset, format) in type_patches {
        write_bytes(&mut clear, offset, &format)?;
    }
    for reduction in reductions.values() {
        if reduction.bytes >= reduction.entry.size {
            return Err("cbcs_negative_box_size".to_string());
        }
        write_box_size(
            &mut clear,
            reduction.entry,
            reduction.entry.size - reduction.bytes,
        )?;
    }
    removals.sort_by_key(|entry| std::cmp::Reverse(entry.start));
    for entry in removals {
        clear.drain(entry.start..entry.end());
    }

    let clear = normalize_clear_cmaf_initialization(&clear)?;
    parse_children(&clear, 0, clear.len())?;
    Ok(ClearCmafInitialization {
        data: clear,
        context: CbcsDecryptionContext { tracks },
    })
}

pub fn normalize_clear_cmaf_initialization(clear: &[u8]) -> Result<Vec<u8>, String> {
    let top = parse_children(clear, 0, clear.len())?;
    let moov = top
        .iter()
        .copied()
        .find(|entry| entry.kind == *b"moov")
        .ok_or_else(|| "cbcs_missing_moov".to_string())?;
    let mut insertions = Vec::new();
    let mut increases: HashMap<usize, SizeAdjustment> = HashMap::new();

    for trak in parse_children(clear, moov.payload_start(), moov.end())?
        .into_iter()
        .filter(|entry| entry.kind == *b"trak")
    {
        let Some(mdia) = direct_child(clear, trak, *b"mdia")? else {
            continue;
        };
        let Some(hdlr) = direct_child(clear, mdia, *b"hdlr")? else {
            continue;
        };
        if read_fourcc(clear, hdlr.payload_start() + 8)? != *b"vide" {
            continue;
        }
        let Some(minf) = direct_child(clear, mdia, *b"minf")? else {
            continue;
        };
        let Some(stbl) = direct_child(clear, minf, *b"stbl")? else {
            continue;
        };
        let Some(stsd) = direct_child(clear, stbl, *b"stsd")? else {
            continue;
        };
        for entry in parse_children(clear, stsd.payload_start() + 8, stsd.end())?
            .into_iter()
            .filter(|entry| matches!(&entry.kind, b"avc1" | b"hvc1" | b"hev1"))
        {
            let children_start = entry
                .start
                .checked_add(86)
                .ok_or_else(|| "cbcs_video_sample_entry_overflow".to_string())?;
            if children_start > entry.end() {
                return Err("cbcs_truncated_video_sample_entry".to_string());
            }
            let children = parse_children(clear, children_start, entry.end())?;
            if children.iter().any(|child| child.kind == *b"colr") {
                continue;
            }
            insertions.push(entry.end());
            for ancestor in [entry, stsd, stbl, minf, mdia, trak, moov] {
                add_adjustment(&mut increases, ancestor, COLOR_BOX.len())?;
            }
        }
    }

    if insertions.is_empty() {
        return Ok(clear.to_vec());
    }
    let mut normalized = clear.to_vec();
    for increase in increases.values() {
        let size = increase
            .entry
            .size
            .checked_add(increase.bytes)
            .ok_or_else(|| "cbcs_box_size_overflow".to_string())?;
        write_box_size(&mut normalized, increase.entry, size)?;
    }
    insertions.sort_by_key(|offset| std::cmp::Reverse(*offset));
    for offset in insertions {
        normalized.splice(offset..offset, COLOR_BOX);
    }
    parse_children(&normalized, 0, normalized.len())?;
    Ok(normalized)
}

fn parse_track_protection(
    bytes: &[u8],
    track_id: u32,
    kind: TrackKind,
    timescale: u32,
    tenc: Mp4Box,
) -> Result<TrackProtection, String> {
    let payload = tenc.payload_start();
    let version = read_u8(bytes, payload)?;
    if version != 1 {
        return Err(format!("cbcs_unsupported_tenc_version:{version}"));
    }
    let pattern = read_u8(bytes, payload + 5)?;
    let is_protected = read_u8(bytes, payload + 6)?;
    let per_sample_iv_size = usize::from(read_u8(bytes, payload + 7)?);
    if is_protected != 1 || !matches!(per_sample_iv_size, 0 | 8 | 16) {
        return Err(format!("cbcs_unsupported_tenc_iv:{track_id}"));
    }
    let kid = read_array_16(bytes, payload + 8)?;
    let constant_iv = if per_sample_iv_size == 0 {
        let size = usize::from(read_u8(bytes, payload + 24)?);
        if !matches!(size, 8 | 16) {
            return Err(format!("cbcs_unsupported_constant_iv:{track_id}"));
        }
        let source = bytes
            .get(payload + 25..payload + 25 + size)
            .ok_or_else(|| "cbcs_truncated_constant_iv".to_string())?;
        let mut value = [0u8; 16];
        value[..size].copy_from_slice(source);
        Some(value)
    } else {
        None
    };
    let crypt_blocks = pattern >> 4;
    let skip_blocks = pattern & 0x0f;
    if kind == TrackKind::Video && (crypt_blocks, skip_blocks) != (1, 9) {
        return Err(format!(
            "cbcs_unsupported_video_pattern:{crypt_blocks}:{skip_blocks}"
        ));
    }
    Ok(TrackProtection {
        timescale,
        kid,
        crypt_blocks: if kind == TrackKind::Audio {
            1
        } else {
            crypt_blocks
        },
        skip_blocks: if kind == TrackKind::Audio {
            0
        } else {
            skip_blocks
        },
        per_sample_iv_size,
        constant_iv,
    })
}

fn parse_track_id(bytes: &[u8], tkhd: Mp4Box) -> Result<u32, String> {
    let version = read_u8(bytes, tkhd.payload_start())?;
    read_u32(
        bytes,
        tkhd.payload_start() + if version == 1 { 20 } else { 12 },
    )
}

fn parse_timescale(bytes: &[u8], mdhd: Mp4Box) -> Result<u32, String> {
    let version = read_u8(bytes, mdhd.payload_start())?;
    let offset = match version {
        0 => mdhd.payload_start() + 12,
        1 => mdhd.payload_start() + 20,
        _ => return Err(format!("cbcs_unsupported_mdhd_version:{version}")),
    };
    let timescale = read_u32(bytes, offset)?;
    if timescale == 0 {
        return Err("cbcs_invalid_timescale".to_string());
    }
    Ok(timescale)
}

fn sample_entry_children_start(bytes: &[u8], entry: Mp4Box) -> Result<usize, String> {
    if entry.kind == *b"encv" {
        let start = entry
            .start
            .checked_add(86)
            .ok_or_else(|| "cbcs_video_sample_entry_overflow".to_string())?;
        if start > entry.end() {
            return Err("cbcs_truncated_video_sample_entry".to_string());
        }
        return Ok(start);
    }
    let version = read_u16(bytes, entry.start + 16)?;
    let header_size = match version {
        0 => 36,
        1 => 52,
        2 => 72,
        _ => return Err(format!("cbcs_unsupported_audio_sample_entry:{version}")),
    };
    let start = entry
        .start
        .checked_add(header_size)
        .ok_or_else(|| "cbcs_audio_sample_entry_overflow".to_string())?;
    if start > entry.end() {
        return Err("cbcs_truncated_audio_sample_entry".to_string());
    }
    Ok(start)
}

fn add_adjustment(
    adjustments: &mut HashMap<usize, SizeAdjustment>,
    entry: Mp4Box,
    bytes: usize,
) -> Result<(), String> {
    let existing = adjustments.get(&entry.start).map_or(0, |value| value.bytes);
    let total = existing
        .checked_add(bytes)
        .ok_or_else(|| "cbcs_box_adjustment_overflow".to_string())?;
    adjustments.insert(
        entry.start,
        SizeAdjustment {
            entry,
            bytes: total,
        },
    );
    Ok(())
}

fn parse_children(bytes: &[u8], start: usize, end: usize) -> Result<Vec<Mp4Box>, String> {
    if start > end || end > bytes.len() {
        return Err("cbcs_invalid_box_range".to_string());
    }
    let mut output = Vec::new();
    let mut cursor = start;
    while cursor < end {
        let entry = parse_box(bytes, cursor, end)?;
        cursor = entry.end();
        output.push(entry);
    }
    Ok(output)
}

fn parse_box(bytes: &[u8], start: usize, parent_end: usize) -> Result<Mp4Box, String> {
    if start
        .checked_add(BOX_HEADER_BYTES)
        .map_or(true, |end| end > parent_end)
        || parent_end > bytes.len()
    {
        return Err("cbcs_truncated_box_header".to_string());
    }
    let size32 =
        usize::try_from(read_u32(bytes, start)?).map_err(|_| "cbcs_box_too_large".to_string())?;
    let kind = read_fourcc(bytes, start + 4)?;
    let (size, header_size) = match size32 {
        0 => (parent_end - start, BOX_HEADER_BYTES),
        1 => {
            let size = usize::try_from(read_u64(bytes, start + 8)?)
                .map_err(|_| "cbcs_box_too_large".to_string())?;
            (size, 16)
        }
        value => (value, BOX_HEADER_BYTES),
    };
    if size < header_size || start.checked_add(size).map_or(true, |end| end > parent_end) {
        return Err("cbcs_invalid_box_size".to_string());
    }
    Ok(Mp4Box {
        start,
        size,
        header_size,
        kind,
    })
}

fn direct_child(bytes: &[u8], parent: Mp4Box, kind: [u8; 4]) -> Result<Option<Mp4Box>, String> {
    Ok(parse_children(bytes, parent.payload_start(), parent.end())?
        .into_iter()
        .find(|entry| entry.kind == kind))
}

fn write_box_size(bytes: &mut [u8], entry: Mp4Box, size: usize) -> Result<(), String> {
    match entry.header_size {
        8 => write_bytes(
            bytes,
            entry.start,
            &u32::try_from(size)
                .map_err(|_| "cbcs_box_too_large".to_string())?
                .to_be_bytes(),
        ),
        16 => {
            write_bytes(bytes, entry.start, &1u32.to_be_bytes())?;
            write_bytes(bytes, entry.start + 8, &(size as u64).to_be_bytes())
        }
        _ => Err("cbcs_invalid_box_header_size".to_string()),
    }
}

fn read_u8(bytes: &[u8], offset: usize) -> Result<u8, String> {
    bytes
        .get(offset)
        .copied()
        .ok_or_else(|| "cbcs_truncated_u8".to_string())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, String> {
    bytes
        .get(offset..offset + 2)
        .map(|value| u16::from_be_bytes(value.try_into().unwrap()))
        .ok_or_else(|| "cbcs_truncated_u16".to_string())
}

fn read_u24(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let value = bytes
        .get(offset..offset + 3)
        .ok_or_else(|| "cbcs_truncated_u24".to_string())?;
    Ok((u32::from(value[0]) << 16) | (u32::from(value[1]) << 8) | u32::from(value[2]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    bytes
        .get(offset..offset + 4)
        .map(|value| u32::from_be_bytes(value.try_into().unwrap()))
        .ok_or_else(|| "cbcs_truncated_u32".to_string())
}

fn read_i32(bytes: &[u8], offset: usize) -> Result<i32, String> {
    Ok(i32::from_be_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or_else(|| "cbcs_truncated_i32".to_string())?
            .try_into()
            .unwrap(),
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, String> {
    bytes
        .get(offset..offset + 8)
        .map(|value| u64::from_be_bytes(value.try_into().unwrap()))
        .ok_or_else(|| "cbcs_truncated_u64".to_string())
}

fn read_fourcc(bytes: &[u8], offset: usize) -> Result<[u8; 4], String> {
    bytes
        .get(offset..offset + 4)
        .map(|value| value.try_into().unwrap())
        .ok_or_else(|| "cbcs_truncated_fourcc".to_string())
}

fn read_array_16(bytes: &[u8], offset: usize) -> Result<[u8; 16], String> {
    bytes
        .get(offset..offset + 16)
        .map(|value| value.try_into().unwrap())
        .ok_or_else(|| "cbcs_truncated_16_bytes".to_string())
}

fn write_bytes(bytes: &mut [u8], offset: usize, value: &[u8]) -> Result<(), String> {
    bytes
        .get_mut(offset..offset + value.len())
        .ok_or_else(|| "cbcs_write_out_of_bounds".to_string())?
        .copy_from_slice(value);
    Ok(())
}

#[derive(Clone, Copy)]
struct TfhdInfo {
    track_id: u32,
    default_sample_duration: Option<u32>,
    default_sample_size: Option<u32>,
    has_base_data_offset: bool,
    default_base_is_moof: bool,
}

#[derive(Clone, Copy)]
struct SampleRange {
    offset: usize,
    size: usize,
}

struct TrunInfo {
    data_offset_field: usize,
    data_offset: i32,
    samples: Vec<SampleRange>,
    duration: u64,
}

#[derive(Clone, Copy)]
struct TfdtField {
    version: u8,
    offset: usize,
}

struct DecodeTimePatch {
    field: TfdtField,
    value: u64,
}

struct DecryptOperation {
    offset: usize,
    length: usize,
    iv: [u8; 16],
    kid: [u8; 16],
    crypt_blocks: u8,
    skip_blocks: u8,
}

pub fn clear_cbcs_cmaf_fragment(
    encrypted: &[u8],
    context: &CbcsDecryptionContext,
    keys: &[CbcsContentKey],
    timeline: Option<CmafFragmentTimeline>,
) -> Result<Vec<u8>, String> {
    let top = parse_children(encrypted, 0, encrypted.len())?;
    let mut operations = Vec::new();
    let mut removals = Vec::new();
    let mut reductions: HashMap<usize, SizeAdjustment> = HashMap::new();
    let mut offset_patches = Vec::new();
    let mut sequence_patches = Vec::new();
    let mut decode_time_patches = Vec::new();
    let mut first_sequence_number = None;
    let mut next_decode_time_by_track = HashMap::new();

    for moof in top.iter().copied().filter(|entry| entry.kind == *b"moof") {
        let moof_children = parse_children(encrypted, moof.payload_start(), moof.end())?;
        if let (Some(timeline), Some(mfhd)) = (
            timeline,
            moof_children
                .iter()
                .copied()
                .find(|entry| entry.kind == *b"mfhd"),
        ) {
            if let Some(fragment_sequence) = timeline.fragment_sequence {
                let field_offset = mfhd.payload_start() + 4;
                let original = read_u32(encrypted, field_offset)?;
                let first = *first_sequence_number.get_or_insert(original);
                let delta = original.saturating_sub(first);
                let target = fragment_sequence
                    .checked_add(delta)
                    .ok_or_else(|| "cbcs_mfhd_sequence_overflow".to_string())?;
                sequence_patches.push((field_offset, target));
            }
        }

        let mut moof_removal_bytes = 0usize;
        let mut moof_trun_offsets = Vec::new();
        for traf in moof_children
            .iter()
            .copied()
            .filter(|entry| entry.kind == *b"traf")
        {
            let children = parse_children(encrypted, traf.payload_start(), traf.end())?;
            let tfhd_box = children
                .iter()
                .copied()
                .find(|entry| entry.kind == *b"tfhd")
                .ok_or_else(|| "cbcs_missing_tfhd".to_string())?;
            let tfhd = parse_tfhd(encrypted, tfhd_box)?;
            let Some(track) = context.tracks.get(&tfhd.track_id) else {
                continue;
            };
            if tfhd.has_base_data_offset || !tfhd.default_base_is_moof {
                return Err(format!("cbcs_unsupported_fragment_base:{}", tfhd.track_id));
            }

            let runs = children
                .iter()
                .copied()
                .filter(|entry| entry.kind == *b"trun")
                .map(|entry| parse_trun(encrypted, moof, entry, tfhd))
                .collect::<Result<Vec<_>, _>>()?;
            if runs.is_empty() {
                return Err(format!("cbcs_missing_trun:{}", tfhd.track_id));
            }
            let senc = children
                .iter()
                .copied()
                .find(|entry| entry.kind == *b"senc")
                .ok_or_else(|| format!("cbcs_missing_senc:{}", tfhd.track_id))?;

            if let Some(timeline) = timeline {
                let tfdt = children
                    .iter()
                    .copied()
                    .find(|entry| entry.kind == *b"tfdt")
                    .ok_or_else(|| format!("cbcs_missing_tfdt:{}", tfhd.track_id))?;
                let field = parse_tfdt_field(encrypted, tfdt)?;
                let base_decode_time = next_decode_time_by_track
                    .get(&tfhd.track_id)
                    .copied()
                    .unwrap_or(decode_time(
                        timeline.base_time_microseconds,
                        track.timescale,
                    )?);
                decode_time_patches.push(DecodeTimePatch {
                    field,
                    value: base_decode_time,
                });
                let duration = runs.iter().try_fold(0u64, |sum, run| {
                    sum.checked_add(run.duration)
                        .ok_or_else(|| "cbcs_sample_duration_overflow".to_string())
                })?;
                next_decode_time_by_track.insert(
                    tfhd.track_id,
                    base_decode_time
                        .checked_add(duration)
                        .ok_or_else(|| "cbcs_tfdt_overflow".to_string())?,
                );
            }

            let samples = runs
                .iter()
                .flat_map(|run| run.samples.iter().copied())
                .collect::<Vec<_>>();
            operations.extend(parse_senc_operations(encrypted, senc, &samples, track)?);
            moof_trun_offsets.extend(
                runs.iter()
                    .map(|run| (run.data_offset_field, run.data_offset)),
            );

            let auxiliary = children
                .iter()
                .copied()
                .filter(|entry| matches!(&entry.kind, b"saiz" | b"saio" | b"senc"))
                .collect::<Vec<_>>();
            let traf_removal_bytes = auxiliary.iter().try_fold(0usize, |sum, entry| {
                sum.checked_add(entry.size)
                    .ok_or_else(|| "cbcs_box_adjustment_overflow".to_string())
            })?;
            removals.extend(auxiliary);
            moof_removal_bytes = moof_removal_bytes
                .checked_add(traf_removal_bytes)
                .ok_or_else(|| "cbcs_box_adjustment_overflow".to_string())?;
            if traf_removal_bytes > 0 {
                add_adjustment(&mut reductions, traf, traf_removal_bytes)?;
            }
        }

        if moof_removal_bytes > 0 {
            add_adjustment(&mut reductions, moof, moof_removal_bytes)?;
            let delta = i32::try_from(moof_removal_bytes)
                .map_err(|_| "cbcs_fragment_auxiliary_too_large".to_string())?;
            for (field, original) in moof_trun_offsets {
                offset_patches.push((
                    field,
                    original
                        .checked_sub(delta)
                        .ok_or_else(|| "cbcs_trun_data_offset_overflow".to_string())?,
                ));
            }
        }
    }

    if operations.is_empty() {
        return Err("cbcs_missing_encrypted_samples".to_string());
    }
    let mut clear = encrypted.to_vec();
    decrypt_operations(&mut clear, &operations, keys)?;
    for (offset, value) in sequence_patches {
        write_u32(&mut clear, offset, value)?;
    }
    for patch in decode_time_patches {
        write_decode_time(&mut clear, patch)?;
    }
    for reduction in reductions.values() {
        if reduction.bytes >= reduction.entry.size {
            return Err("cbcs_negative_box_size".to_string());
        }
        write_box_size(
            &mut clear,
            reduction.entry,
            reduction.entry.size - reduction.bytes,
        )?;
    }
    for (offset, value) in offset_patches {
        write_i32(&mut clear, offset, value)?;
    }
    removals.sort_by_key(|entry| std::cmp::Reverse(entry.start));
    for entry in removals {
        clear.drain(entry.start..entry.end());
    }
    parse_children(&clear, 0, clear.len())?;
    Ok(clear)
}

fn parse_tfhd(bytes: &[u8], entry: Mp4Box) -> Result<TfhdInfo, String> {
    let payload = entry.payload_start();
    let flags = read_u24(bytes, payload + 1)?;
    let track_id = read_u32(bytes, payload + 4)?;
    let mut cursor = payload + 8;
    let has_base_data_offset = flags & 0x000001 != 0;
    if has_base_data_offset {
        cursor = cursor
            .checked_add(8)
            .ok_or_else(|| "cbcs_tfhd_overflow".to_string())?;
    }
    if flags & 0x000002 != 0 {
        cursor += 4;
    }
    let default_sample_duration = if flags & 0x000008 != 0 {
        let value = Some(read_u32(bytes, cursor)?);
        cursor += 4;
        value
    } else {
        None
    };
    let default_sample_size = if flags & 0x000010 != 0 {
        let value = Some(read_u32(bytes, cursor)?);
        cursor += 4;
        value
    } else {
        None
    };
    if flags & 0x000020 != 0 {
        cursor += 4;
    }
    if cursor > entry.end() {
        return Err("cbcs_truncated_tfhd".to_string());
    }
    Ok(TfhdInfo {
        track_id,
        default_sample_duration,
        default_sample_size,
        has_base_data_offset,
        default_base_is_moof: flags & 0x020000 != 0,
    })
}

fn parse_trun(
    bytes: &[u8],
    moof: Mp4Box,
    entry: Mp4Box,
    tfhd: TfhdInfo,
) -> Result<TrunInfo, String> {
    let payload = entry.payload_start();
    let flags = read_u24(bytes, payload + 1)?;
    let sample_count = usize::try_from(read_u32(bytes, payload + 4)?)
        .map_err(|_| "cbcs_sample_count_overflow".to_string())?;
    let mut cursor = payload + 8;
    if flags & 0x000001 == 0 {
        return Err("cbcs_trun_missing_data_offset".to_string());
    }
    let data_offset_field = cursor;
    let data_offset = read_i32(bytes, cursor)?;
    cursor += 4;
    let absolute = i64::try_from(moof.start)
        .ok()
        .and_then(|start| start.checked_add(i64::from(data_offset)))
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| "cbcs_invalid_trun_data_offset".to_string())?;
    if flags & 0x000004 != 0 {
        cursor += 4;
    }
    let mut samples = Vec::with_capacity(sample_count);
    let mut sample_offset = absolute;
    let mut duration = 0u64;
    for _ in 0..sample_count {
        let sample_duration = if flags & 0x000100 != 0 {
            let value = read_u32(bytes, cursor)?;
            cursor += 4;
            value
        } else {
            tfhd.default_sample_duration
                .ok_or_else(|| "cbcs_missing_sample_duration".to_string())?
        };
        duration = duration
            .checked_add(u64::from(sample_duration))
            .ok_or_else(|| "cbcs_sample_duration_overflow".to_string())?;
        let sample_size = if flags & 0x000200 != 0 {
            let value = read_u32(bytes, cursor)?;
            cursor += 4;
            value
        } else {
            tfhd.default_sample_size
                .ok_or_else(|| "cbcs_missing_sample_size".to_string())?
        } as usize;
        if flags & 0x000400 != 0 {
            cursor += 4;
        }
        if flags & 0x000800 != 0 {
            cursor += 4;
        }
        let sample_end = sample_offset
            .checked_add(sample_size)
            .ok_or_else(|| "cbcs_sample_range_overflow".to_string())?;
        if cursor > entry.end() || sample_end > bytes.len() {
            return Err("cbcs_sample_out_of_bounds".to_string());
        }
        samples.push(SampleRange {
            offset: sample_offset,
            size: sample_size,
        });
        sample_offset = sample_end;
    }
    Ok(TrunInfo {
        data_offset_field,
        data_offset,
        samples,
        duration,
    })
}

fn parse_senc_operations(
    bytes: &[u8],
    entry: Mp4Box,
    samples: &[SampleRange],
    track: &TrackProtection,
) -> Result<Vec<DecryptOperation>, String> {
    let flags = read_u24(bytes, entry.payload_start() + 1)?;
    let sample_count = usize::try_from(read_u32(bytes, entry.payload_start() + 4)?)
        .map_err(|_| "cbcs_sample_count_overflow".to_string())?;
    if sample_count != samples.len() {
        return Err("cbcs_senc_sample_count_mismatch".to_string());
    }
    let has_subsamples = flags & 0x000002 != 0;
    let mut cursor = entry.payload_start() + 8;
    let mut output = Vec::new();
    for sample in samples {
        let iv = if track.per_sample_iv_size > 0 {
            let source = bytes
                .get(cursor..cursor + track.per_sample_iv_size)
                .ok_or_else(|| "cbcs_truncated_senc_iv".to_string())?;
            cursor += track.per_sample_iv_size;
            let mut iv = [0u8; 16];
            iv[..source.len()].copy_from_slice(source);
            iv
        } else {
            track
                .constant_iv
                .ok_or_else(|| "cbcs_missing_constant_iv".to_string())?
        };
        let subsamples = if has_subsamples {
            let count = usize::from(read_u16(bytes, cursor)?);
            cursor += 2;
            let mut values = Vec::with_capacity(count);
            for _ in 0..count {
                let clear_bytes = usize::from(read_u16(bytes, cursor)?);
                let cipher_bytes = usize::try_from(read_u32(bytes, cursor + 2)?)
                    .map_err(|_| "cbcs_subsample_size_overflow".to_string())?;
                cursor += 6;
                values.push((clear_bytes, cipher_bytes));
            }
            values
        } else {
            vec![(0, sample.size)]
        };
        let mut sample_cursor = sample.offset;
        let mut described = 0usize;
        for (clear_bytes, cipher_bytes) in subsamples {
            sample_cursor = sample_cursor
                .checked_add(clear_bytes)
                .ok_or_else(|| "cbcs_subsample_range_overflow".to_string())?;
            described = described
                .checked_add(clear_bytes)
                .and_then(|value| value.checked_add(cipher_bytes))
                .ok_or_else(|| "cbcs_subsample_size_overflow".to_string())?;
            if cipher_bytes > 0 {
                output.push(DecryptOperation {
                    offset: sample_cursor,
                    length: cipher_bytes,
                    iv,
                    kid: track.kid,
                    crypt_blocks: track.crypt_blocks,
                    skip_blocks: track.skip_blocks,
                });
            }
            sample_cursor = sample_cursor
                .checked_add(cipher_bytes)
                .ok_or_else(|| "cbcs_subsample_range_overflow".to_string())?;
        }
        if described != sample.size {
            return Err("cbcs_senc_sample_layout_mismatch".to_string());
        }
    }
    if cursor > entry.end() {
        return Err("cbcs_truncated_senc".to_string());
    }
    Ok(output)
}

fn parse_tfdt_field(bytes: &[u8], entry: Mp4Box) -> Result<TfdtField, String> {
    let version = read_u8(bytes, entry.payload_start())?;
    match version {
        0 => {
            read_u32(bytes, entry.payload_start() + 4)?;
        }
        1 => {
            read_u64(bytes, entry.payload_start() + 4)?;
        }
        _ => return Err(format!("cbcs_unsupported_tfdt_version:{version}")),
    }
    Ok(TfdtField {
        version,
        offset: entry.payload_start() + 4,
    })
}

fn decode_time(microseconds: u64, timescale: u32) -> Result<u64, String> {
    microseconds
        .checked_mul(u64::from(timescale))
        .map(|value| value / 1_000_000)
        .ok_or_else(|| "cbcs_decode_time_overflow".to_string())
}

fn write_decode_time(bytes: &mut [u8], patch: DecodeTimePatch) -> Result<(), String> {
    match patch.field.version {
        0 => write_u32(
            bytes,
            patch.field.offset,
            u32::try_from(patch.value).map_err(|_| "cbcs_tfdt_v0_overflow".to_string())?,
        ),
        1 => write_u64(bytes, patch.field.offset, patch.value),
        version => Err(format!("cbcs_unsupported_tfdt_version:{version}")),
    }
}

fn decrypt_operations(
    bytes: &mut [u8],
    operations: &[DecryptOperation],
    keys: &[CbcsContentKey],
) -> Result<(), String> {
    for operation in operations {
        let end = operation
            .offset
            .checked_add(operation.length)
            .ok_or_else(|| "cbcs_decrypt_range_overflow".to_string())?;
        let range = bytes
            .get_mut(operation.offset..end)
            .ok_or_else(|| "cbcs_decrypt_out_of_bounds".to_string())?;
        let key = keys
            .iter()
            .find(|key| key.kid == operation.kid)
            .ok_or_else(|| format!("cbcs_missing_content_key:{}", hex(&operation.kid)))?;
        let aes = Aes128::new_from_slice(key.cek.as_ref())
            .map_err(|_| "cbcs_invalid_content_key".to_string())?;
        decrypt_pattern(
            &aes,
            range,
            operation.crypt_blocks,
            operation.skip_blocks,
            operation.iv,
        );
    }
    Ok(())
}

fn decrypt_pattern(
    aes: &Aes128,
    bytes: &mut [u8],
    crypt_blocks: u8,
    skip_blocks: u8,
    mut previous: [u8; 16],
) {
    let crypt_blocks = usize::from(if crypt_blocks == 0 && skip_blocks == 0 {
        1
    } else {
        crypt_blocks
    });
    let skip_blocks = usize::from(skip_blocks);
    let full_blocks = bytes.len() / AES_BLOCK_BYTES;
    let mut block_index = 0usize;
    while block_index < full_blocks {
        let decrypt_count = crypt_blocks.min(full_blocks - block_index);
        for _ in 0..decrypt_count {
            let start = block_index * AES_BLOCK_BYTES;
            let mut cipher = [0u8; AES_BLOCK_BYTES];
            cipher.copy_from_slice(&bytes[start..start + AES_BLOCK_BYTES]);
            let mut clear = cipher;
            aes.decrypt_block((&mut clear).into());
            for (byte, prior) in clear.iter_mut().zip(previous.iter()) {
                *byte ^= *prior;
            }
            bytes[start..start + AES_BLOCK_BYTES].copy_from_slice(&clear);
            previous = cipher;
            block_index += 1;
        }
        block_index = block_index.saturating_add(skip_blocks).min(full_blocks);
    }
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), String> {
    write_bytes(bytes, offset, &value.to_be_bytes())
}

fn write_i32(bytes: &mut [u8], offset: usize, value: i32) -> Result<(), String> {
    write_bytes(bytes, offset, &value.to_be_bytes())
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) -> Result<(), String> {
    write_bytes(bytes, offset, &value.to_be_bytes())
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}
