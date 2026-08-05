use std::collections::HashMap;
use std::convert::TryFrom;

#[cfg(test)]
use aes::cipher::BlockDecrypt;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use h264_reader::avcc::AvcDecoderConfigurationRecord;
use h264_reader::nal::pps::PicParameterSet;
use h264_reader::nal::slice::SliceHeader;
use h264_reader::nal::sps::SeqParameterSet;
use h264_reader::nal::{Nal, RefNal};
use h264_reader::rbsp::BitRead as H264BitRead;
use h264_reader::Context as H264Context;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct SegmentEncryptionContext {
    pub kid: [u8; 16],
    pub cek: Zeroizing<[u8; 16]>,
    pub crypt_blocks: u8,
    pub skip_blocks: u8,
}

const BOX_HEADER_BYTES: usize = 8;
const CENC_PER_SAMPLE_IV_BYTES: usize = 8;
const CENC_CONSTANT_IV_BYTES: usize = 16;
const AES_BLOCK_BYTES: usize = 16;
pub const PROTECTED_VIDEO_ENVELOPE_MAGIC: &[u8; 8] = b"SESCBCS1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TrackKind {
    Video,
    Audio,
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

#[derive(Clone, Debug)]
struct TrackProtectionPlan {
    track_id: u32,
    kind: TrackKind,
    codec: TrackCodec,
    sample_entry: Mp4Box,
    original_format: [u8; 4],
    size_ancestors: Vec<Mp4Box>,
}

#[derive(Clone, Debug)]
enum TrackCodec {
    H264 {
        avcc: Vec<u8>,
        nal_length_size: usize,
    },
    Hevc {
        nal_length_size: usize,
    },
    Audio,
    Unsupported([u8; 4]),
}

#[derive(Clone, Copy, Debug)]
struct Subsample {
    clear_bytes: usize,
    cipher_bytes: usize,
}

#[derive(Clone, Debug)]
struct EncryptedSample {
    track_id: u32,
    track_kind: TrackKind,
    data_offset: usize,
    data_size: usize,
    iv: [u8; CENC_CONSTANT_IV_BYTES],
    subsamples: Vec<Subsample>,
}

#[derive(Clone, Debug)]
struct FragmentRun {
    data_offset_field: usize,
    samples: Vec<(usize, usize)>,
}

#[derive(Clone, Debug)]
struct TrafEncryptionPlan {
    traf: Mp4Box,
    runs: Vec<FragmentRun>,
    samples: Vec<EncryptedSample>,
}

#[derive(Clone, Debug)]
struct MoofEncryptionPlan {
    moof: Mp4Box,
    trafs: Vec<TrafEncryptionPlan>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CbcsPackagingInfo {
    pub file_len: u64,
    pub moov_end: u64,
    pub init_signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CbcsFragmentPackage {
    pub init: Vec<u8>,
    pub fragment: Vec<u8>,
    pub info: CbcsPackagingInfo,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedCmafInfo {
    pub kid: [u8; 16],
    pub crypt_blocks: u8,
    pub skip_blocks: u8,
    pub file_len: u64,
    pub moov_end: u64,
    pub init_signature: String,
    pub fragment_count: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectedVideoCodec {
    H264,
    H265,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedVideoSubsample {
    pub clear_bytes: u16,
    pub cipher_bytes: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedVideoSample {
    pub pts_90khz: u64,
    pub duration_90khz: u32,
    pub keyframe: bool,
    pub iv: [u8; CENC_CONSTANT_IV_BYTES],
    pub subsamples: Vec<ProtectedVideoSubsample>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedVideoFragment {
    pub codec: ProtectedVideoCodec,
    pub kid: [u8; 16],
    pub crypt_blocks: u8,
    pub skip_blocks: u8,
    pub nal_length_size: u8,
    pub parameter_sets: Vec<Vec<u8>>,
    pub samples: Vec<ProtectedVideoSample>,
}

pub fn encode_protected_video_sample_envelope(
    fragment: &ProtectedVideoFragment,
    sample: &ProtectedVideoSample,
) -> Result<Vec<u8>, String> {
    if !(1..=4).contains(&fragment.nal_length_size)
        || fragment.crypt_blocks == 0
        || fragment.skip_blocks == 0
        || sample.subsamples.is_empty()
    {
        return Err("cbcs_invalid_video_envelope_metadata".to_string());
    }
    let subsample_count = u16::try_from(sample.subsamples.len())
        .map_err(|_| "cbcs_subsample_count_overflow".to_string())?;
    let data_len =
        u32::try_from(sample.data.len()).map_err(|_| "cbcs_video_sample_too_large".to_string())?;
    let metadata_len = sample
        .subsamples
        .len()
        .checked_mul(6)
        .ok_or_else(|| "cbcs_video_envelope_size_overflow".to_string())?;
    let mut output = Vec::with_capacity(
        50usize
            .checked_add(metadata_len)
            .and_then(|value| value.checked_add(sample.data.len()))
            .ok_or_else(|| "cbcs_video_envelope_size_overflow".to_string())?,
    );
    output.extend_from_slice(PROTECTED_VIDEO_ENVELOPE_MAGIC);
    output.push(match fragment.codec {
        ProtectedVideoCodec::H264 => 1,
        ProtectedVideoCodec::H265 => 2,
    });
    output.push(fragment.crypt_blocks);
    output.push(fragment.skip_blocks);
    output.push(fragment.nal_length_size);
    output.extend_from_slice(&fragment.kid);
    output.extend_from_slice(&sample.iv);
    output.extend_from_slice(&subsample_count.to_be_bytes());
    output.extend_from_slice(&data_len.to_be_bytes());
    for entry in &sample.subsamples {
        output.extend_from_slice(&entry.clear_bytes.to_be_bytes());
        output.extend_from_slice(&entry.cipher_bytes.to_be_bytes());
    }
    output.extend_from_slice(&sample.data);
    Ok(output)
}

pub fn package_clear_cmaf_memory_to_cbcs(
    bytes: &mut Vec<u8>,
    context: &SegmentEncryptionContext,
) -> Result<CbcsPackagingInfo, String> {
    let top = parse_children(bytes, 0, bytes.len())?;
    let moov = top
        .iter()
        .copied()
        .find(|entry| entry.kind == *b"moov")
        .ok_or_else(|| "cbcs_missing_moov".to_string())?;
    let mut tracks = parse_clear_track_plans(bytes, moov)?;
    if tracks.is_empty() {
        return Err("cbcs_missing_clear_tracks".to_string());
    }
    // CBCS audio carries one constant IV in tenc. Deriving it from the random
    // KID keeps the init section stable for the lifetime of the content key.
    let audio_constant_iv = derive_audio_constant_iv(&context.kid);
    let plans = parse_clear_fragment_plans(bytes, &top, &tracks, &audio_constant_iv)?;
    if plans.iter().all(|plan| plan.trafs.is_empty()) {
        return Err("cbcs_missing_fragment_samples".to_string());
    }
    canonicalize_hevc_sample_entries(bytes, &mut tracks, &plans)?;

    encrypt_clear_samples(bytes, &plans, context)?;
    let protected_moov = build_protected_moov(bytes, moov, &tracks, context, &audio_constant_iv)?;
    *bytes =
        rebuild_fragments_with_auxiliary_info(bytes, &top, &plans, moov.start, &protected_moov)?;

    let final_top = parse_children(bytes, 0, bytes.len())?;
    let final_moov = final_top
        .iter()
        .copied()
        .find(|entry| entry.kind == *b"moov")
        .ok_or_else(|| "cbcs_missing_final_moov".to_string())?;
    let init_signature = sha256_hex(&bytes[..final_moov.end()]);
    Ok(CbcsPackagingInfo {
        file_len: bytes.len() as u64,
        moov_end: final_moov.end() as u64,
        init_signature,
    })
}

pub fn package_clear_cmaf_fragment_to_cbcs(
    clear_init: &[u8],
    clear_fragment: &[u8],
    context: &SegmentEncryptionContext,
) -> Result<CbcsFragmentPackage, String> {
    if clear_init.is_empty() {
        return Err("cbcs_missing_clear_init".to_string());
    }
    if clear_fragment.is_empty() {
        return Err("cbcs_missing_clear_fragment".to_string());
    }

    let mut protected = Vec::with_capacity(
        clear_init
            .len()
            .checked_add(clear_fragment.len())
            .ok_or_else(|| "cbcs_fragment_input_size_overflow".to_string())?,
    );
    protected.extend_from_slice(clear_init);
    protected.extend_from_slice(clear_fragment);
    let info = package_clear_cmaf_memory_to_cbcs(&mut protected, context)?;
    let split =
        usize::try_from(info.moov_end).map_err(|_| "cbcs_fragment_init_too_large".to_string())?;
    if split == 0 || split >= protected.len() {
        return Err("cbcs_invalid_fragment_output_split".to_string());
    }
    let fragment = protected.split_off(split);

    Ok(CbcsFragmentPackage {
        init: protected,
        fragment,
        info,
    })
}

fn canonicalize_hevc_sample_entries(
    bytes: &mut [u8],
    tracks: &mut [TrackProtectionPlan],
    plans: &[MoofEncryptionPlan],
) -> Result<(), String> {
    for track in tracks.iter_mut() {
        let TrackCodec::Hevc { nal_length_size } = track.codec else {
            continue;
        };
        if track.original_format != *b"hev1" {
            continue;
        }

        let mut has_samples = false;
        let mut has_inband_parameter_sets = false;
        'fragments: for plan in plans {
            for traf in &plan.trafs {
                for sample in &traf.samples {
                    if sample.track_id != track.track_id {
                        continue;
                    }
                    has_samples = true;
                    let end = sample
                        .data_offset
                        .checked_add(sample.data_size)
                        .ok_or_else(|| "cbcs_hevc_sample_range_overflow".to_string())?;
                    let sample_bytes = bytes
                        .get(sample.data_offset..end)
                        .ok_or_else(|| "cbcs_hevc_sample_out_of_bounds".to_string())?;
                    if hevc_sample_has_parameter_sets(sample_bytes, nal_length_size)? {
                        has_inband_parameter_sets = true;
                        break 'fragments;
                    }
                }
            }
        }
        if !has_samples || has_inband_parameter_sets {
            continue;
        }

        let kind_start = track
            .sample_entry
            .start
            .checked_add(4)
            .ok_or_else(|| "cbcs_hevc_sample_entry_range_overflow".to_string())?;
        let kind_end = kind_start
            .checked_add(4)
            .ok_or_else(|| "cbcs_hevc_sample_entry_range_overflow".to_string())?;
        let kind = bytes
            .get_mut(kind_start..kind_end)
            .ok_or_else(|| "cbcs_hevc_sample_entry_out_of_bounds".to_string())?;
        if kind != b"hev1" {
            return Err("cbcs_hevc_sample_entry_changed".to_string());
        }
        kind.copy_from_slice(b"hvc1");
        track.sample_entry.kind = *b"hvc1";
        track.original_format = *b"hvc1";
    }
    Ok(())
}

fn hevc_sample_has_parameter_sets(sample: &[u8], nal_length_size: usize) -> Result<bool, String> {
    if !(1..=4).contains(&nal_length_size) {
        return Err("cbcs_invalid_hevc_nal_length_size".to_string());
    }

    let mut cursor = 0usize;
    while cursor < sample.len() {
        let length_end = cursor
            .checked_add(nal_length_size)
            .ok_or_else(|| "cbcs_hevc_nal_range_overflow".to_string())?;
        let nal_size = read_be_uint(
            sample
                .get(cursor..length_end)
                .ok_or_else(|| "cbcs_truncated_hevc_nal_length".to_string())?,
        )?;
        if nal_size < 2 {
            return Err("cbcs_invalid_hevc_nal".to_string());
        }
        let nal_end = length_end
            .checked_add(nal_size)
            .ok_or_else(|| "cbcs_hevc_nal_range_overflow".to_string())?;
        let nal = sample
            .get(length_end..nal_end)
            .ok_or_else(|| "cbcs_truncated_hevc_nal".to_string())?;
        let nal_type = (nal[0] >> 1) & 0x3f;
        if matches!(nal_type, 32..=34) {
            return Ok(true);
        }
        cursor = nal_end;
    }
    Ok(false)
}

pub fn inspect_protected_cmaf(bytes: &[u8]) -> Result<ProtectedCmafInfo, String> {
    let top = parse_children(bytes, 0, bytes.len())?;
    let moov = top
        .iter()
        .copied()
        .find(|entry| entry.kind == *b"moov")
        .ok_or_else(|| "cbcs_missing_moov".to_string())?;
    let schemes = scan_box_signatures(bytes, moov.start, moov.end(), *b"schm");
    if schemes.is_empty()
        || schemes.iter().any(|entry| {
            bytes.get(entry.payload_start() + 4..entry.payload_start() + 8) != Some(b"cbcs")
        })
    {
        return Err("cbcs_invalid_protection_scheme".to_string());
    }

    let tenc_entries = scan_box_signatures(bytes, moov.start, moov.end(), *b"tenc");
    if tenc_entries.is_empty() {
        return Err("cbcs_missing_tenc".to_string());
    }
    let mut kid = None;
    let mut video_pattern = None;
    for tenc in tenc_entries {
        let payload = bytes
            .get(tenc.payload_start()..tenc.end())
            .ok_or_else(|| "cbcs_invalid_tenc".to_string())?;
        if payload.len() < 24 || payload[0] != 1 || payload[6] != 1 {
            return Err("cbcs_invalid_tenc".to_string());
        }
        let entry_kid: [u8; 16] = payload[8..24].try_into().unwrap();
        if kid.is_some_and(|existing| existing != entry_kid) {
            return Err("cbcs_mixed_content_key_ids".to_string());
        }
        kid = Some(entry_kid);
        let crypt_blocks = payload[5] >> 4;
        let skip_blocks = payload[5] & 0x0f;
        match (crypt_blocks, skip_blocks) {
            (0, 0) => {}
            (1, 9) => video_pattern = Some((crypt_blocks, skip_blocks)),
            _ => return Err("cbcs_invalid_encryption_pattern".to_string()),
        }
    }
    let (crypt_blocks, skip_blocks) =
        video_pattern.ok_or_else(|| "cbcs_missing_video_pattern".to_string())?;
    if !top.iter().any(|entry| entry.kind == *b"moof")
        || scan_box_signatures(bytes, 0, bytes.len(), *b"senc").is_empty()
    {
        return Err("cbcs_missing_fragment_encryption".to_string());
    }
    let fragment_count = u32::try_from(top.iter().filter(|entry| entry.kind == *b"moof").count())
        .map_err(|_| "cbcs_fragment_count_overflow".to_string())?;
    Ok(ProtectedCmafInfo {
        kid: kid.unwrap(),
        crypt_blocks,
        skip_blocks,
        file_len: bytes.len() as u64,
        moov_end: moov.end() as u64,
        init_signature: sha256_hex(&bytes[..moov.end()]),
        fragment_count,
    })
}

pub fn extract_protected_video_fragment(bytes: &[u8]) -> Result<ProtectedVideoFragment, String> {
    let protected = inspect_protected_cmaf(bytes)?;
    let top = parse_children(bytes, 0, bytes.len())?;
    let moov = top
        .iter()
        .copied()
        .find(|entry| entry.kind == *b"moov")
        .ok_or_else(|| "cbcs_missing_moov".to_string())?;
    let track = parse_protected_video_track(bytes, moov)?;
    let mut samples = Vec::new();

    for moof in top.iter().copied().filter(|entry| entry.kind == *b"moof") {
        for traf in parse_children(bytes, moof.payload_start(), moof.end())?
            .into_iter()
            .filter(|entry| entry.kind == *b"traf")
        {
            let children = parse_children(bytes, traf.payload_start(), traf.end())?;
            let tfhd = children
                .iter()
                .copied()
                .find(|entry| entry.kind == *b"tfhd")
                .ok_or_else(|| "cbcs_missing_tfhd".to_string())?;
            let tfhd = parse_tfhd(bytes, tfhd)?;
            if tfhd.track_id != track.track_id {
                continue;
            }
            if !tfhd.default_base_is_moof || tfhd.has_base_data_offset {
                return Err(format!("cbcs_unsupported_fragment_base:{}", tfhd.track_id));
            }
            let tfdt = children
                .iter()
                .copied()
                .find(|entry| entry.kind == *b"tfdt")
                .ok_or_else(|| format!("cbcs_missing_tfdt:{}", tfhd.track_id))?;
            let mut decode_time = parse_tfdt(bytes, tfdt)?;
            let runs = children
                .iter()
                .copied()
                .filter(|entry| entry.kind == *b"trun")
                .map(|entry| parse_protected_trun(bytes, moof.start, entry, &tfhd))
                .collect::<Result<Vec<_>, _>>()?;
            let flat_runs = runs.iter().flat_map(|run| run.iter()).collect::<Vec<_>>();
            if flat_runs.is_empty() {
                return Err(format!("cbcs_missing_trun:{}", tfhd.track_id));
            }
            let senc = children
                .iter()
                .copied()
                .find(|entry| entry.kind == *b"senc")
                .ok_or_else(|| format!("cbcs_missing_senc:{}", tfhd.track_id))?;
            let senc_runs = flat_runs
                .iter()
                .map(|sample| (sample.data_offset, sample.data_size))
                .collect::<Vec<_>>();
            let encryption = parse_senc(bytes, senc, &senc_runs, None)?;

            for (run, (iv, subsamples)) in flat_runs.into_iter().zip(encryption) {
                let end = run
                    .data_offset
                    .checked_add(run.data_size)
                    .ok_or_else(|| "cbcs_sample_range_overflow".to_string())?;
                let data = bytes
                    .get(run.data_offset..end)
                    .ok_or_else(|| "cbcs_sample_out_of_bounds".to_string())?
                    .to_vec();
                let pts = i128::from(decode_time) + i128::from(run.composition_time_offset);
                if pts < 0 {
                    return Err("cbcs_negative_video_pts".to_string());
                }
                samples.push(ProtectedVideoSample {
                    pts_90khz: scale_to_90khz(pts as u64, track.timescale)?,
                    duration_90khz: u32::try_from(scale_to_90khz(
                        u64::from(run.duration),
                        track.timescale,
                    )?)
                    .map_err(|_| "cbcs_video_duration_overflow".to_string())?,
                    keyframe: protected_sample_is_keyframe(
                        &data,
                        track.codec,
                        track.nal_length_size,
                    )?,
                    iv,
                    subsamples: subsamples
                        .into_iter()
                        .map(|entry| {
                            Ok(ProtectedVideoSubsample {
                                clear_bytes: u16::try_from(entry.clear_bytes)
                                    .map_err(|_| "cbcs_subsample_clear_overflow".to_string())?,
                                cipher_bytes: u32::try_from(entry.cipher_bytes)
                                    .map_err(|_| "cbcs_subsample_cipher_overflow".to_string())?,
                            })
                        })
                        .collect::<Result<Vec<_>, String>>()?,
                    data,
                });
                decode_time = decode_time
                    .checked_add(u64::from(run.duration))
                    .ok_or_else(|| "cbcs_video_decode_time_overflow".to_string())?;
            }
        }
    }

    if samples.is_empty() {
        return Err("cbcs_missing_video_samples".to_string());
    }
    Ok(ProtectedVideoFragment {
        codec: track.codec,
        kid: protected.kid,
        crypt_blocks: protected.crypt_blocks,
        skip_blocks: protected.skip_blocks,
        nal_length_size: u8::try_from(track.nal_length_size)
            .map_err(|_| "cbcs_invalid_video_nal_length_size".to_string())?,
        parameter_sets: track.parameter_sets,
        samples,
    })
}

#[derive(Clone, Debug)]
struct ProtectedVideoTrack {
    track_id: u32,
    codec: ProtectedVideoCodec,
    timescale: u32,
    nal_length_size: usize,
    parameter_sets: Vec<Vec<u8>>,
}

#[derive(Clone, Debug)]
struct ProtectedRunSample {
    data_offset: usize,
    data_size: usize,
    duration: u32,
    composition_time_offset: i32,
}

fn parse_protected_video_track(bytes: &[u8], moov: Mp4Box) -> Result<ProtectedVideoTrack, String> {
    let mut video_tracks = Vec::new();
    for trak in parse_children(bytes, moov.payload_start(), moov.end())?
        .into_iter()
        .filter(|entry| entry.kind == *b"trak")
    {
        let handler = find_box_recursive(bytes, trak, *b"hdlr")
            .and_then(|entry| parse_handler_type(bytes, entry))
            .ok_or_else(|| "cbcs_invalid_handler".to_string())?;
        if handler != *b"vide" {
            continue;
        }
        let track_id = find_box_recursive(bytes, trak, *b"tkhd")
            .and_then(|entry| parse_tkhd_track_id(bytes, entry))
            .ok_or_else(|| "cbcs_invalid_tkhd".to_string())?;
        let mdhd = find_box_recursive(bytes, trak, *b"mdhd")
            .ok_or_else(|| format!("cbcs_missing_mdhd:{track_id}"))?;
        let timescale = parse_mdhd_timescale(bytes, mdhd)?;
        let stsd = find_box_recursive(bytes, trak, *b"stsd")
            .ok_or_else(|| format!("cbcs_missing_stsd:{track_id}"))?;
        let entries_start = stsd
            .payload_start()
            .checked_add(8)
            .ok_or_else(|| format!("cbcs_invalid_stsd:{track_id}"))?;
        let sample_entry = parse_children(bytes, entries_start, stsd.end())?
            .into_iter()
            .find(|entry| entry.kind == *b"encv")
            .ok_or_else(|| format!("cbcs_missing_protected_video_sample_entry:{track_id}"))?;
        let frma = scan_box_signatures(bytes, sample_entry.start, sample_entry.end(), *b"frma")
            .into_iter()
            .next()
            .ok_or_else(|| format!("cbcs_missing_frma:{track_id}"))?;
        let original_format: [u8; 4] = bytes
            .get(frma.payload_start()..frma.payload_start() + 4)
            .ok_or_else(|| format!("cbcs_invalid_frma:{track_id}"))?
            .try_into()
            .unwrap();
        let (codec, nal_length_size, parameter_sets) = match &original_format {
            b"avc1" | b"avc3" => {
                let avcc =
                    scan_box_signatures(bytes, sample_entry.start, sample_entry.end(), *b"avcC")
                        .into_iter()
                        .next()
                        .ok_or_else(|| format!("cbcs_missing_avcc:{track_id}"))?;
                let payload = bytes
                    .get(avcc.payload_start()..avcc.end())
                    .ok_or_else(|| format!("cbcs_invalid_avcc:{track_id}"))?;
                let record = AvcDecoderConfigurationRecord::try_from(payload)
                    .map_err(|error| format!("cbcs_invalid_avcc:{track_id}:{error:?}"))?;
                (
                    ProtectedVideoCodec::H264,
                    usize::from(record.length_size_minus_one()) + 1,
                    avcc_parameter_sets(payload)?,
                )
            }
            b"hvc1" | b"hev1" => {
                let hvcc =
                    scan_box_signatures(bytes, sample_entry.start, sample_entry.end(), *b"hvcC")
                        .into_iter()
                        .next()
                        .ok_or_else(|| format!("cbcs_missing_hvcc:{track_id}"))?;
                let payload = bytes
                    .get(hvcc.payload_start()..hvcc.end())
                    .ok_or_else(|| format!("cbcs_invalid_hvcc:{track_id}"))?;
                if payload.len() < 23 || payload[0] != 1 {
                    return Err(format!("cbcs_invalid_hvcc:{track_id}"));
                }
                (
                    ProtectedVideoCodec::H265,
                    usize::from(payload[21] & 0x03) + 1,
                    hvcc_parameter_sets(payload)?,
                )
            }
            _other => {
                return Err(format!(
                    "cbcs_unsupported_protected_video_codec:{}:{}",
                    track_id,
                    String::from_utf8_lossy(&original_format)
                ))
            }
        };
        video_tracks.push(ProtectedVideoTrack {
            track_id,
            codec,
            timescale,
            nal_length_size,
            parameter_sets,
        });
    }
    match video_tracks.len() {
        1 => Ok(video_tracks.remove(0)),
        0 => Err("cbcs_missing_protected_video_track".to_string()),
        _ => Err("cbcs_multiple_protected_video_tracks".to_string()),
    }
}

fn avcc_parameter_sets(payload: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if payload.len() < 7 || payload[0] != 1 {
        return Err("cbcs_invalid_avcc".to_string());
    }
    let mut cursor = 6usize;
    let sps_count = usize::from(payload[5] & 0x1f);
    let mut output = Vec::new();
    for _ in 0..sps_count {
        output.push(read_decoder_config_nal(payload, &mut cursor)?);
    }
    let pps_count = usize::from(
        *payload
            .get(cursor)
            .ok_or_else(|| "cbcs_truncated_avcc_pps_count".to_string())?,
    );
    cursor += 1;
    for _ in 0..pps_count {
        output.push(read_decoder_config_nal(payload, &mut cursor)?);
    }
    Ok(output)
}

fn hvcc_parameter_sets(payload: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if payload.len() < 23 || payload[0] != 1 {
        return Err("cbcs_invalid_hvcc".to_string());
    }
    let mut cursor = 23usize;
    let array_count = usize::from(payload[22]);
    let mut output = Vec::new();
    for _ in 0..array_count {
        let _header = *payload
            .get(cursor)
            .ok_or_else(|| "cbcs_truncated_hvcc_array".to_string())?;
        cursor += 1;
        let nal_count = usize::from(read_u16(payload, cursor)?);
        cursor += 2;
        for _ in 0..nal_count {
            output.push(read_decoder_config_nal(payload, &mut cursor)?);
        }
    }
    Ok(output)
}

fn read_decoder_config_nal(payload: &[u8], cursor: &mut usize) -> Result<Vec<u8>, String> {
    let length = usize::from(read_u16(payload, *cursor)?);
    *cursor = cursor.saturating_add(2);
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| "cbcs_decoder_config_nal_overflow".to_string())?;
    let nal = payload
        .get(*cursor..end)
        .ok_or_else(|| "cbcs_truncated_decoder_config_nal".to_string())?
        .to_vec();
    *cursor = end;
    Ok(nal)
}

fn parse_mdhd_timescale(bytes: &[u8], entry: Mp4Box) -> Result<u32, String> {
    let payload = entry.payload_start();
    let version = *bytes
        .get(payload)
        .ok_or_else(|| "cbcs_truncated_mdhd".to_string())?;
    let offset = if version == 1 {
        payload + 20
    } else {
        payload + 12
    };
    let timescale = read_u32(bytes, offset)?;
    if timescale == 0 {
        return Err("cbcs_invalid_video_timescale".to_string());
    }
    Ok(timescale)
}

fn parse_tfdt(bytes: &[u8], entry: Mp4Box) -> Result<u64, String> {
    let payload = entry.payload_start();
    match bytes
        .get(payload)
        .copied()
        .ok_or_else(|| "cbcs_truncated_tfdt".to_string())?
    {
        0 => Ok(u64::from(read_u32(bytes, payload + 4)?)),
        1 => read_u64(bytes, payload + 4),
        _other => Err("cbcs_unsupported_tfdt_version".to_string()),
    }
}

fn parse_protected_trun(
    bytes: &[u8],
    moof_start: usize,
    entry: Mp4Box,
    tfhd: &TfhdInfo,
) -> Result<Vec<ProtectedRunSample>, String> {
    let payload = entry.payload_start();
    let version = *bytes
        .get(payload)
        .ok_or_else(|| "cbcs_truncated_trun".to_string())?;
    let flags = read_u24(bytes, payload + 1)?;
    let sample_count = read_u32(bytes, payload + 4)? as usize;
    let mut cursor = payload + 8;
    let relative = if flags & 0x000001 != 0 {
        let value = read_i32(bytes, cursor)? as i64;
        cursor += 4;
        value
    } else {
        return Err("cbcs_trun_missing_data_offset".to_string());
    };
    let mut sample_offset = usize::try_from(
        (moof_start as i64)
            .checked_add(relative)
            .ok_or_else(|| "cbcs_invalid_trun_data_offset".to_string())?,
    )
    .map_err(|_| "cbcs_invalid_trun_data_offset".to_string())?;
    let first_sample_flags = if flags & 0x000004 != 0 {
        let value = Some(read_u32(bytes, cursor)?);
        cursor += 4;
        value
    } else {
        None
    };
    let mut output = Vec::with_capacity(sample_count);
    for index in 0..sample_count {
        let duration = if flags & 0x000100 != 0 {
            let value = read_u32(bytes, cursor)?;
            cursor += 4;
            value
        } else {
            tfhd.default_sample_duration
                .ok_or_else(|| "cbcs_missing_sample_duration".to_string())?
        };
        let data_size = if flags & 0x000200 != 0 {
            let value = read_u32(bytes, cursor)?;
            cursor += 4;
            value
        } else {
            tfhd.default_sample_size
                .ok_or_else(|| "cbcs_missing_sample_size".to_string())?
        } as usize;
        let _sample_flags = if flags & 0x000400 != 0 {
            let value = read_u32(bytes, cursor)?;
            cursor += 4;
            Some(value)
        } else if index == 0 {
            first_sample_flags.or(tfhd.default_sample_flags)
        } else {
            tfhd.default_sample_flags
        };
        let composition_time_offset = if flags & 0x000800 != 0 {
            let value = if version == 1 {
                read_i32(bytes, cursor)?
            } else {
                i32::try_from(read_u32(bytes, cursor)?)
                    .map_err(|_| "cbcs_composition_offset_overflow".to_string())?
            };
            cursor += 4;
            value
        } else {
            0
        };
        if cursor > entry.end() || duration == 0 {
            return Err("cbcs_invalid_trun_sample".to_string());
        }
        output.push(ProtectedRunSample {
            data_offset: sample_offset,
            data_size,
            duration,
            composition_time_offset,
        });
        sample_offset = sample_offset
            .checked_add(data_size)
            .ok_or_else(|| "cbcs_sample_range_overflow".to_string())?;
    }
    Ok(output)
}

fn scale_to_90khz(value: u64, timescale: u32) -> Result<u64, String> {
    let scaled = u128::from(value)
        .checked_mul(90_000)
        .and_then(|value| value.checked_add(u128::from(timescale / 2)))
        .ok_or_else(|| "cbcs_video_timestamp_overflow".to_string())?
        / u128::from(timescale);
    u64::try_from(scaled).map_err(|_| "cbcs_video_timestamp_overflow".to_string())
}

fn protected_sample_is_keyframe(
    sample: &[u8],
    codec: ProtectedVideoCodec,
    nal_length_size: usize,
) -> Result<bool, String> {
    if !(1..=4).contains(&nal_length_size) {
        return Err("cbcs_invalid_video_nal_length_size".to_string());
    }
    let mut cursor = 0usize;
    while cursor < sample.len() {
        let length_end = cursor
            .checked_add(nal_length_size)
            .ok_or_else(|| "cbcs_video_nal_range_overflow".to_string())?;
        let nal_size = read_be_uint(
            sample
                .get(cursor..length_end)
                .ok_or_else(|| "cbcs_truncated_video_nal_length".to_string())?,
        )?;
        let nal_end = length_end
            .checked_add(nal_size)
            .ok_or_else(|| "cbcs_video_nal_range_overflow".to_string())?;
        let nal = sample
            .get(length_end..nal_end)
            .ok_or_else(|| "cbcs_truncated_video_nal".to_string())?;
        let keyframe = match codec {
            ProtectedVideoCodec::H264 => nal.first().is_some_and(|value| value & 0x1f == 5),
            ProtectedVideoCodec::H265 => nal
                .first()
                .is_some_and(|value| matches!((value >> 1) & 0x3f, 16..=21)),
        };
        if keyframe {
            return Ok(true);
        }
        cursor = nal_end;
    }
    Ok(false)
}

fn derive_audio_constant_iv(kid: &[u8; 16]) -> [u8; CENC_CONSTANT_IV_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(b"sesame-dvr:cbcs:audio-constant-iv:v1");
    hasher.update(kid);
    let digest = hasher.finalize();
    digest[..CENC_CONSTANT_IV_BYTES].try_into().unwrap()
}

fn parse_clear_track_plans(bytes: &[u8], moov: Mp4Box) -> Result<Vec<TrackProtectionPlan>, String> {
    let mut output = Vec::new();
    for trak in parse_children(bytes, moov.payload_start(), moov.end())?
        .into_iter()
        .filter(|entry| entry.kind == *b"trak")
    {
        let track_id = find_box_recursive(bytes, trak, *b"tkhd")
            .and_then(|entry| parse_tkhd_track_id(bytes, entry))
            .ok_or_else(|| "cbcs_invalid_tkhd".to_string())?;
        let handler = find_box_recursive(bytes, trak, *b"hdlr")
            .and_then(|entry| parse_handler_type(bytes, entry))
            .ok_or_else(|| "cbcs_invalid_handler".to_string())?;
        let kind = match &handler {
            b"vide" => TrackKind::Video,
            b"soun" => TrackKind::Audio,
            _ => continue,
        };
        let mdia = direct_child(bytes, trak, *b"mdia")
            .ok_or_else(|| format!("cbcs_missing_mdia:{track_id}"))?;
        let minf = direct_child(bytes, mdia, *b"minf")
            .ok_or_else(|| format!("cbcs_missing_minf:{track_id}"))?;
        let stbl = direct_child(bytes, minf, *b"stbl")
            .ok_or_else(|| format!("cbcs_missing_stbl:{track_id}"))?;
        let stsd = direct_child(bytes, stbl, *b"stsd")
            .ok_or_else(|| format!("cbcs_missing_stsd:{track_id}"))?;
        let entries_start = stsd
            .payload_start()
            .checked_add(8)
            .ok_or_else(|| format!("cbcs_invalid_stsd:{track_id}"))?;
        let sample_entries = parse_children(bytes, entries_start, stsd.end())?;
        let sample_entry = sample_entries
            .into_iter()
            .find(|entry| match kind {
                TrackKind::Video => {
                    matches!(&entry.kind, b"avc1" | b"avc3" | b"hvc1" | b"hev1" | b"encv")
                }
                TrackKind::Audio => matches!(&entry.kind, b"mp4a" | b"ac-3" | b"ec-3" | b"enca"),
            })
            .ok_or_else(|| format!("cbcs_missing_sample_entry:{track_id}"))?;
        if matches!(&sample_entry.kind, b"encv" | b"enca") {
            return Err(format!("cbcs_input_already_encrypted:{track_id}"));
        }
        let original_format = sample_entry.kind;
        let codec = match kind {
            TrackKind::Audio if original_format == *b"mp4a" => TrackCodec::Audio,
            TrackKind::Audio => TrackCodec::Unsupported(original_format),
            TrackKind::Video if matches!(&original_format, b"avc1" | b"avc3") => {
                let avcc =
                    scan_box_signatures(bytes, sample_entry.start, sample_entry.end(), *b"avcC")
                        .into_iter()
                        .next()
                        .ok_or_else(|| format!("cbcs_missing_avcc:{track_id}"))?;
                let payload = bytes
                    .get(avcc.payload_start()..avcc.end())
                    .ok_or_else(|| format!("cbcs_invalid_avcc:{track_id}"))?;
                let record = AvcDecoderConfigurationRecord::try_from(payload)
                    .map_err(|error| format!("cbcs_invalid_avcc:{track_id}:{error:?}"))?;
                TrackCodec::H264 {
                    avcc: payload.to_vec(),
                    nal_length_size: usize::from(record.length_size_minus_one()) + 1,
                }
            }
            TrackKind::Video if matches!(&original_format, b"hvc1" | b"hev1") => {
                let hvcc =
                    scan_box_signatures(bytes, sample_entry.start, sample_entry.end(), *b"hvcC")
                        .into_iter()
                        .next()
                        .ok_or_else(|| format!("cbcs_missing_hvcc:{track_id}"))?;
                let payload = bytes
                    .get(hvcc.payload_start()..hvcc.end())
                    .ok_or_else(|| format!("cbcs_invalid_hvcc:{track_id}"))?;
                if payload.len() < 22 || payload[0] != 1 {
                    return Err(format!("cbcs_invalid_hvcc:{track_id}"));
                }
                TrackCodec::Hevc {
                    nal_length_size: usize::from(payload[21] & 0x03) + 1,
                }
            }
            TrackKind::Video => TrackCodec::Unsupported(original_format),
        };
        output.push(TrackProtectionPlan {
            track_id,
            kind,
            codec,
            sample_entry,
            original_format,
            size_ancestors: vec![sample_entry, stsd, stbl, minf, mdia, trak, moov],
        });
    }
    Ok(output)
}

fn parse_clear_fragment_plans(
    bytes: &[u8],
    top: &[Mp4Box],
    tracks: &[TrackProtectionPlan],
    audio_constant_iv: &[u8; CENC_CONSTANT_IV_BYTES],
) -> Result<Vec<MoofEncryptionPlan>, String> {
    let mut h264_states = HashMap::new();
    for track in tracks {
        if let TrackCodec::H264 {
            avcc,
            nal_length_size,
        } = &track.codec
        {
            let record = AvcDecoderConfigurationRecord::try_from(avcc.as_slice())
                .map_err(|error| format!("cbcs_invalid_avcc:{}:{error:?}", track.track_id))?;
            let context = record
                .create_context()
                .map_err(|error| format!("cbcs_invalid_avcc:{}:{error:?}", track.track_id))?;
            h264_states.insert(
                track.track_id,
                H264TrackState {
                    context,
                    nal_length_size: *nal_length_size,
                },
            );
        }
    }

    let mut output = Vec::new();
    for moof in top.iter().copied().filter(|entry| entry.kind == *b"moof") {
        let mut trafs = Vec::new();
        for traf in parse_children(bytes, moof.payload_start(), moof.end())?
            .into_iter()
            .filter(|entry| entry.kind == *b"traf")
        {
            let children = parse_children(bytes, traf.payload_start(), traf.end())?;
            let tfhd = children
                .iter()
                .copied()
                .find(|entry| entry.kind == *b"tfhd")
                .ok_or_else(|| "cbcs_missing_tfhd".to_string())?;
            let tfhd = parse_tfhd(bytes, tfhd)?;
            if !tfhd.default_base_is_moof || tfhd.has_base_data_offset {
                return Err(format!("cbcs_unsupported_fragment_base:{}", tfhd.track_id));
            }
            let track = tracks
                .iter()
                .find(|track| track.track_id == tfhd.track_id)
                .ok_or_else(|| format!("cbcs_unknown_fragment_track:{}", tfhd.track_id))?;
            if children.iter().any(|entry| entry.kind == *b"senc") {
                return Err(format!(
                    "cbcs_unexpected_fragment_encryption:{}",
                    tfhd.track_id
                ));
            }
            let mut runs = Vec::new();
            for trun in children
                .iter()
                .copied()
                .filter(|entry| entry.kind == *b"trun")
            {
                runs.push(parse_trun(
                    bytes,
                    moof.start,
                    trun,
                    tfhd.default_sample_size,
                )?);
            }
            if runs.is_empty() {
                return Err(format!("cbcs_missing_trun:{}", tfhd.track_id));
            }

            let mut samples = Vec::new();
            for (data_offset, data_size) in runs.iter().flat_map(|run| run.samples.iter().copied())
            {
                let end = data_offset
                    .checked_add(data_size)
                    .ok_or_else(|| "cbcs_sample_range_overflow".to_string())?;
                let sample = bytes
                    .get(data_offset..end)
                    .ok_or_else(|| "cbcs_sample_out_of_bounds".to_string())?;
                let subsamples = match &track.codec {
                    TrackCodec::Audio => Vec::new(),
                    TrackCodec::H264 { .. } => generate_h264_subsamples(
                        sample,
                        h264_states
                            .get_mut(&tfhd.track_id)
                            .ok_or_else(|| "cbcs_missing_h264_state".to_string())?,
                    )
                    .map_err(|error| {
                        format!(
                            "{error}:track={}:sample_offset={data_offset}:sample_size={data_size}",
                            tfhd.track_id
                        )
                    })?,
                    TrackCodec::Hevc { nal_length_size } => {
                        generate_hevc_subsamples(sample, *nal_length_size).map_err(|error| {
                            format!(
                            "{error}:track={}:sample_offset={data_offset}:sample_size={data_size}",
                            tfhd.track_id
                        )
                        })?
                    }
                    TrackCodec::Unsupported(format) => {
                        return Err(format!(
                            "cbcs_unsupported_codec:{}:{}",
                            tfhd.track_id,
                            String::from_utf8_lossy(format)
                        ));
                    }
                };
                let mut iv = [0u8; CENC_CONSTANT_IV_BYTES];
                match track.kind {
                    TrackKind::Video => OsRng.fill_bytes(&mut iv[..CENC_PER_SAMPLE_IV_BYTES]),
                    TrackKind::Audio => iv.copy_from_slice(audio_constant_iv),
                }
                samples.push(EncryptedSample {
                    track_id: tfhd.track_id,
                    track_kind: track.kind,
                    data_offset,
                    data_size,
                    iv,
                    subsamples,
                });
            }
            trafs.push(TrafEncryptionPlan {
                traf,
                runs,
                samples,
            });
        }
        output.push(MoofEncryptionPlan { moof, trafs });
    }
    Ok(output)
}

fn encrypt_clear_samples(
    bytes: &mut [u8],
    plans: &[MoofEncryptionPlan],
    context: &SegmentEncryptionContext,
) -> Result<(), String> {
    let aes = Aes128::new_from_slice(context.cek.as_ref())
        .map_err(|_| "cbcs_invalid_content_key".to_string())?;
    for sample in plans
        .iter()
        .flat_map(|plan| plan.trafs.iter())
        .flat_map(|traf| traf.samples.iter())
    {
        let end = sample.data_offset.saturating_add(sample.data_size);
        if end > bytes.len() {
            return Err("cbcs_sample_out_of_bounds".to_string());
        }
        let (crypt_blocks, skip_blocks) = match sample.track_kind {
            TrackKind::Video => (context.crypt_blocks, context.skip_blocks),
            TrackKind::Audio => (1, 0),
        };
        if sample.subsamples.is_empty() {
            let mut cbc_previous = sample.iv;
            cbcs_encrypt_pattern_in_place(
                &aes,
                &mut bytes[sample.data_offset..end],
                crypt_blocks,
                skip_blocks,
                &mut cbc_previous,
            );
            continue;
        }
        let mut cursor = sample.data_offset;
        for subsample in &sample.subsamples {
            cursor = cursor.saturating_add(subsample.clear_bytes);
            let cipher_end = cursor.saturating_add(subsample.cipher_bytes);
            if cipher_end > end {
                return Err("cbcs_subsample_out_of_bounds".to_string());
            }
            let mut cbc_previous = sample.iv;
            cbcs_encrypt_pattern_in_place(
                &aes,
                &mut bytes[cursor..cipher_end],
                crypt_blocks,
                skip_blocks,
                &mut cbc_previous,
            );
            cursor = cipher_end;
        }
        if cursor != end {
            return Err("cbcs_sample_layout_mismatch".to_string());
        }
    }
    Ok(())
}

struct H264TrackState {
    context: H264Context,
    nal_length_size: usize,
}

fn generate_h264_subsamples(
    sample: &[u8],
    state: &mut H264TrackState,
) -> Result<Vec<Subsample>, String> {
    let mut output = Vec::new();
    let mut accumulated_clear = 0usize;
    let mut cursor = 0usize;
    while cursor < sample.len() {
        let length_end = cursor
            .checked_add(state.nal_length_size)
            .ok_or_else(|| "cbcs_h264_nal_range_overflow".to_string())?;
        let length_bytes = sample
            .get(cursor..length_end)
            .ok_or_else(|| "cbcs_truncated_h264_nal_length".to_string())?;
        let nal_size = read_be_uint(length_bytes)?;
        if nal_size == 0 {
            return Err("cbcs_empty_h264_nal".to_string());
        }
        let nal_end = length_end
            .checked_add(nal_size)
            .ok_or_else(|| "cbcs_h264_nal_range_overflow".to_string())?;
        let nal = sample
            .get(length_end..nal_end)
            .ok_or_else(|| "cbcs_truncated_h264_nal".to_string())?;
        let nal_type = nal[0] & 0x1f;
        let (clear_bytes, cipher_bytes) = match nal_type {
            1 | 5 => {
                let header_bytes = h264_slice_header_bytes(nal, &state.context)?;
                (
                    state.nal_length_size.saturating_add(header_bytes),
                    nal_size.saturating_sub(header_bytes),
                )
            }
            2..=4 => return Err("cbcs_h264_partitioned_slice_unsupported".to_string()),
            7 => {
                let parsed = RefNal::new(nal, &[], true);
                let sps = SeqParameterSet::from_bits(parsed.rbsp_bits())
                    .map_err(|error| format!("cbcs_invalid_h264_sps:{error:?}"))?;
                state.context.put_seq_param_set(sps);
                (state.nal_length_size.saturating_add(nal_size), 0)
            }
            8 => {
                let parsed = RefNal::new(nal, &[], true);
                let pps = PicParameterSet::from_bits(&state.context, parsed.rbsp_bits())
                    .map_err(|error| format!("cbcs_invalid_h264_pps:{error:?}"))?;
                state.context.put_pic_param_set(pps);
                (state.nal_length_size.saturating_add(nal_size), 0)
            }
            _ => (state.nal_length_size.saturating_add(nal_size), 0),
        };
        append_subsample(
            &mut output,
            &mut accumulated_clear,
            clear_bytes,
            cipher_bytes,
        )?;
        cursor = nal_end;
    }
    finish_subsamples(&mut output, accumulated_clear);
    let described = output.iter().fold(0usize, |total, subsample| {
        total
            .saturating_add(subsample.clear_bytes)
            .saturating_add(subsample.cipher_bytes)
    });
    if described != sample.len() {
        return Err("cbcs_h264_subsample_layout_mismatch".to_string());
    }
    Ok(output)
}

fn generate_hevc_subsamples(
    sample: &[u8],
    nal_length_size: usize,
) -> Result<Vec<Subsample>, String> {
    if !(1..=4).contains(&nal_length_size) {
        return Err("cbcs_invalid_hevc_nal_length_size".to_string());
    }

    let mut output = Vec::new();
    let mut accumulated_clear = 0usize;
    let mut cursor = 0usize;
    while cursor < sample.len() {
        let length_end = cursor
            .checked_add(nal_length_size)
            .ok_or_else(|| "cbcs_hevc_nal_range_overflow".to_string())?;
        let length_bytes = sample
            .get(cursor..length_end)
            .ok_or_else(|| "cbcs_truncated_hevc_nal_length".to_string())?;
        let nal_size = read_be_uint(length_bytes)?;
        if nal_size < 2 {
            return Err("cbcs_invalid_hevc_nal".to_string());
        }
        let nal_end = length_end
            .checked_add(nal_size)
            .ok_or_else(|| "cbcs_hevc_nal_range_overflow".to_string())?;
        sample
            .get(length_end..nal_end)
            .ok_or_else(|| "cbcs_truncated_hevc_nal".to_string())?;

        // CENC v1 leaves the length prefix and the two-byte HEVC NAL header
        // clear. The remainder follows the track's CBCS 1:9 pattern.
        append_subsample(
            &mut output,
            &mut accumulated_clear,
            nal_length_size.saturating_add(2),
            nal_size.saturating_sub(2),
        )?;
        cursor = nal_end;
    }
    finish_subsamples(&mut output, accumulated_clear);
    let described = output.iter().fold(0usize, |total, subsample| {
        total
            .saturating_add(subsample.clear_bytes)
            .saturating_add(subsample.cipher_bytes)
    });
    if described != sample.len() {
        return Err("cbcs_hevc_subsample_layout_mismatch".to_string());
    }
    Ok(output)
}

fn h264_slice_header_bytes(nal: &[u8], context: &H264Context) -> Result<usize, String> {
    let parsed = RefNal::new(nal, &[], true);
    let header = parsed
        .header()
        .map_err(|error| format!("cbcs_invalid_h264_nal_header:{error:?}"))?;
    let mut reader = CountingBitReader::new(parsed.rbsp_bits());
    SliceHeader::from_bits(context, &mut reader, header)
        .map_err(|error| format!("cbcs_invalid_h264_slice_header:{error:?}"))?;
    let rbsp_header_bytes = reader.bits_read().saturating_add(7) / 8;
    let encoded_header_bytes = encoded_rbsp_prefix_len(&nal[1..], rbsp_header_bytes)?;
    Ok(1usize.saturating_add(encoded_header_bytes))
}

fn encoded_rbsp_prefix_len(encoded: &[u8], wanted_rbsp_bytes: usize) -> Result<usize, String> {
    if wanted_rbsp_bytes == 0 {
        return Ok(0);
    }
    let mut decoded = 0usize;
    let mut zero_run = 0usize;
    for (index, byte) in encoded.iter().copied().enumerate() {
        if zero_run >= 2 && byte == 0x03 {
            continue;
        }
        decoded = decoded.saturating_add(1);
        zero_run = if byte == 0 {
            zero_run.saturating_add(1)
        } else {
            0
        };
        if decoded == wanted_rbsp_bytes {
            return Ok(index + 1);
        }
    }
    Err("cbcs_truncated_h264_slice_header".to_string())
}

fn append_subsample(
    output: &mut Vec<Subsample>,
    accumulated_clear: &mut usize,
    clear_bytes: usize,
    cipher_bytes: usize,
) -> Result<(), String> {
    *accumulated_clear = accumulated_clear
        .checked_add(clear_bytes)
        .ok_or_else(|| "cbcs_subsample_clear_overflow".to_string())?;
    if cipher_bytes == 0 {
        return Ok(());
    }
    if cipher_bytes > u32::MAX as usize {
        return Err("cbcs_subsample_cipher_overflow".to_string());
    }
    while *accumulated_clear > u16::MAX as usize {
        output.push(Subsample {
            clear_bytes: u16::MAX as usize,
            cipher_bytes: 0,
        });
        *accumulated_clear -= u16::MAX as usize;
    }
    output.push(Subsample {
        clear_bytes: *accumulated_clear,
        cipher_bytes,
    });
    *accumulated_clear = 0;
    Ok(())
}

fn finish_subsamples(output: &mut Vec<Subsample>, mut clear_bytes: usize) {
    while clear_bytes > u16::MAX as usize {
        output.push(Subsample {
            clear_bytes: u16::MAX as usize,
            cipher_bytes: 0,
        });
        clear_bytes -= u16::MAX as usize;
    }
    if clear_bytes > 0 {
        output.push(Subsample {
            clear_bytes,
            cipher_bytes: 0,
        });
    }
}

fn read_be_uint(bytes: &[u8]) -> Result<usize, String> {
    if bytes.is_empty() || bytes.len() > 4 {
        return Err("cbcs_invalid_h264_nal_length_size".to_string());
    }
    Ok(bytes.iter().fold(0usize, |value, byte| {
        value.saturating_mul(256).saturating_add(usize::from(*byte))
    }))
}

struct CountingBitReader<R> {
    inner: R,
    bits_read: usize,
}

impl<R> CountingBitReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            bits_read: 0,
        }
    }

    fn bits_read(&self) -> usize {
        self.bits_read
    }
}

impl<R: H264BitRead> H264BitRead for CountingBitReader<R> {
    fn read_ue(&mut self, name: &'static str) -> Result<u32, h264_reader::rbsp::BitReaderError> {
        let value = self.inner.read_ue(name)?;
        self.bits_read = self
            .bits_read
            .saturating_add(exp_golomb_bits(u64::from(value)));
        Ok(value)
    }

    fn read_se(&mut self, name: &'static str) -> Result<i32, h264_reader::rbsp::BitReaderError> {
        let value = self.inner.read_se(name)?;
        let code_num = if value > 0 {
            (i64::from(value) * 2 - 1) as u64
        } else {
            (-i64::from(value) * 2) as u64
        };
        self.bits_read = self.bits_read.saturating_add(exp_golomb_bits(code_num));
        Ok(value)
    }

    fn read_bool(&mut self, name: &'static str) -> Result<bool, h264_reader::rbsp::BitReaderError> {
        let value = self.inner.read_bool(name)?;
        self.bits_read = self.bits_read.saturating_add(1);
        Ok(value)
    }

    fn read<U: h264_reader::rbsp::Numeric>(
        &mut self,
        bit_count: u32,
        name: &'static str,
    ) -> Result<U, h264_reader::rbsp::BitReaderError> {
        let value = self.inner.read(bit_count, name)?;
        self.bits_read = self.bits_read.saturating_add(bit_count as usize);
        Ok(value)
    }

    fn read_to<V: h264_reader::rbsp::Primitive>(
        &mut self,
        name: &'static str,
    ) -> Result<V, h264_reader::rbsp::BitReaderError> {
        let value = self.inner.read_to(name)?;
        self.bits_read = self
            .bits_read
            .saturating_add(std::mem::size_of::<V>().saturating_mul(8));
        Ok(value)
    }

    fn skip(
        &mut self,
        bit_count: u32,
        name: &'static str,
    ) -> Result<(), h264_reader::rbsp::BitReaderError> {
        self.inner.skip(bit_count, name)?;
        self.bits_read = self.bits_read.saturating_add(bit_count as usize);
        Ok(())
    }

    fn has_more_rbsp_data(
        &mut self,
        name: &'static str,
    ) -> Result<bool, h264_reader::rbsp::BitReaderError> {
        self.inner.has_more_rbsp_data(name)
    }

    fn finish_rbsp(self) -> Result<(), h264_reader::rbsp::BitReaderError> {
        self.inner.finish_rbsp()
    }

    fn finish_sei_payload(self) -> Result<(), h264_reader::rbsp::BitReaderError> {
        self.inner.finish_sei_payload()
    }
}

fn exp_golomb_bits(code_num: u64) -> usize {
    let value = code_num.saturating_add(1);
    let leading = 63usize.saturating_sub(value.leading_zeros() as usize);
    leading.saturating_mul(2).saturating_add(1)
}

fn build_protected_moov(
    bytes: &[u8],
    moov: Mp4Box,
    tracks: &[TrackProtectionPlan],
    context: &SegmentEncryptionContext,
    audio_constant_iv: &[u8; CENC_CONSTANT_IV_BYTES],
) -> Result<Vec<u8>, String> {
    let mut output = bytes
        .get(moov.start..moov.end())
        .ok_or_else(|| "cbcs_invalid_moov_range".to_string())?
        .to_vec();
    let mut size_patches: HashMap<usize, (Mp4Box, usize)> = HashMap::new();
    let mut insertions = Vec::with_capacity(tracks.len());

    for track in tracks {
        let sinf = build_track_sinf(track, context, audio_constant_iv)?;
        for entry in &track.size_ancestors {
            let patch = size_patches.entry(entry.start).or_insert((*entry, 0));
            patch.1 = patch
                .1
                .checked_add(sinf.len())
                .ok_or_else(|| "cbcs_moov_growth_overflow".to_string())?;
        }
        let local_start = track
            .sample_entry
            .start
            .checked_sub(moov.start)
            .ok_or_else(|| "cbcs_invalid_sample_entry_range".to_string())?;
        let protected_format = match track.kind {
            TrackKind::Video => b"encv",
            TrackKind::Audio => b"enca",
        };
        output
            .get_mut(local_start + 4..local_start + 8)
            .ok_or_else(|| "cbcs_truncated_sample_entry".to_string())?
            .copy_from_slice(protected_format);
        let insertion_offset = track
            .sample_entry
            .end()
            .checked_sub(moov.start)
            .ok_or_else(|| "cbcs_invalid_sample_entry_range".to_string())?;
        insertions.push((insertion_offset, sinf));
    }

    for (entry, growth) in size_patches.values() {
        let local_start = entry
            .start
            .checked_sub(moov.start)
            .ok_or_else(|| "cbcs_invalid_moov_child_range".to_string())?;
        let local_end = entry
            .end()
            .checked_sub(moov.start)
            .ok_or_else(|| "cbcs_invalid_moov_child_range".to_string())?;
        let updated_size = entry
            .size
            .checked_add(*growth)
            .ok_or_else(|| "cbcs_moov_growth_overflow".to_string())?;
        write_box_size(
            output
                .get_mut(local_start..local_end)
                .ok_or_else(|| "cbcs_invalid_moov_child_range".to_string())?,
            entry.header_size,
            updated_size,
        )?;
    }

    insertions.sort_by(|left, right| right.0.cmp(&left.0));
    for (offset, bytes) in insertions {
        if offset > output.len() {
            return Err("cbcs_invalid_sinf_insertion".to_string());
        }
        output.splice(offset..offset, bytes);
    }

    let rebuilt = parse_box(&output, 0, output.len())?;
    if rebuilt.kind != *b"moov" || rebuilt.end() != output.len() {
        return Err("cbcs_invalid_protected_moov".to_string());
    }
    Ok(output)
}

fn build_track_sinf(
    track: &TrackProtectionPlan,
    context: &SegmentEncryptionContext,
    audio_constant_iv: &[u8; CENC_CONSTANT_IV_BYTES],
) -> Result<Vec<u8>, String> {
    let frma = make_box(*b"frma", &track.original_format)?;
    let mut schm_payload = vec![0, 0, 0, 0];
    schm_payload.extend_from_slice(b"cbcs");
    schm_payload.extend_from_slice(&0x0001_0000u32.to_be_bytes());
    let schm = make_box(*b"schm", &schm_payload)?;

    let mut tenc_payload = Vec::with_capacity(41);
    tenc_payload.extend_from_slice(&[1, 0, 0, 0]);
    tenc_payload.push(0);
    tenc_payload.push(match track.kind {
        TrackKind::Video => (context.crypt_blocks << 4) | (context.skip_blocks & 0x0f),
        TrackKind::Audio => 0,
    });
    tenc_payload.push(1);
    tenc_payload.push(match track.kind {
        TrackKind::Video => CENC_PER_SAMPLE_IV_BYTES as u8,
        TrackKind::Audio => 0,
    });
    tenc_payload.extend_from_slice(&context.kid);
    if track.kind == TrackKind::Audio {
        tenc_payload.push(CENC_CONSTANT_IV_BYTES as u8);
        tenc_payload.extend_from_slice(audio_constant_iv);
    }
    let tenc = make_box(*b"tenc", &tenc_payload)?;
    let schi = make_box(*b"schi", &tenc)?;

    let mut sinf_payload = Vec::with_capacity(frma.len() + schm.len() + schi.len());
    sinf_payload.extend_from_slice(&frma);
    sinf_payload.extend_from_slice(&schm);
    sinf_payload.extend_from_slice(&schi);
    make_box(*b"sinf", &sinf_payload)
}

fn rebuild_fragments_with_auxiliary_info(
    bytes: &[u8],
    top: &[Mp4Box],
    plans: &[MoofEncryptionPlan],
    moov_start: usize,
    protected_moov: &[u8],
) -> Result<Vec<u8>, String> {
    let growth = plans.iter().try_fold(0usize, |total, plan| {
        let next = plan.trafs.iter().try_fold(0usize, |subtotal, traf| {
            let parts = build_auxiliary_parts(&traf.samples)?;
            subtotal
                .checked_add(parts.total_size())
                .ok_or_else(|| "cbcs_fragment_growth_overflow".to_string())
        })?;
        total
            .checked_add(next)
            .ok_or_else(|| "cbcs_fragment_growth_overflow".to_string())
    })?;
    let mut output = Vec::with_capacity(
        bytes
            .len()
            .checked_add(growth)
            .and_then(|value| value.checked_add(protected_moov.len()))
            .ok_or_else(|| "cbcs_output_size_overflow".to_string())?,
    );
    for entry in top {
        if entry.kind == *b"moov" && entry.start == moov_start {
            output.extend_from_slice(protected_moov);
            continue;
        }
        if entry.kind != *b"moof" {
            output.extend_from_slice(&bytes[entry.start..entry.end()]);
            continue;
        }
        let plan = plans
            .iter()
            .find(|plan| plan.moof.start == entry.start)
            .ok_or_else(|| "cbcs_missing_moof_plan".to_string())?;
        output.extend_from_slice(&rebuild_moof(bytes, plan)?);
    }
    Ok(output)
}

struct AuxiliaryParts {
    saiz: Vec<u8>,
    senc: Vec<u8>,
}

impl AuxiliaryParts {
    fn total_size(&self) -> usize {
        self.saiz
            .len()
            .saturating_add(if self.saiz.is_empty() { 0 } else { 20 })
            .saturating_add(self.senc.len())
    }
}

fn rebuild_moof(bytes: &[u8], plan: &MoofEncryptionPlan) -> Result<Vec<u8>, String> {
    let mut auxiliary = Vec::with_capacity(plan.trafs.len());
    let mut growth = 0usize;
    for traf in &plan.trafs {
        let parts = build_auxiliary_parts(&traf.samples)?;
        growth = growth
            .checked_add(parts.total_size())
            .ok_or_else(|| "cbcs_fragment_growth_overflow".to_string())?;
        auxiliary.push(parts);
    }
    let growth_i32 = i32::try_from(growth).map_err(|_| "cbcs_fragment_too_large".to_string())?;
    let mut source = bytes[plan.moof.start..plan.moof.end()].to_vec();
    for traf in &plan.trafs {
        for run in &traf.runs {
            let local_offset = run
                .data_offset_field
                .checked_sub(plan.moof.start)
                .ok_or_else(|| "cbcs_invalid_trun_patch_offset".to_string())?;
            let current = read_i32(&source, local_offset)?;
            let updated = current
                .checked_add(growth_i32)
                .ok_or_else(|| "cbcs_trun_data_offset_overflow".to_string())?;
            write_i32(&mut source, local_offset, updated)?;
        }
    }

    let mut output = Vec::with_capacity(
        plan.moof
            .size
            .checked_add(growth)
            .ok_or_else(|| "cbcs_fragment_growth_overflow".to_string())?,
    );
    let mut cursor = 0usize;
    for (traf, parts) in plan.trafs.iter().zip(auxiliary) {
        let traf_start = traf
            .traf
            .start
            .checked_sub(plan.moof.start)
            .ok_or_else(|| "cbcs_invalid_traf_offset".to_string())?;
        let traf_end = traf
            .traf
            .end()
            .checked_sub(plan.moof.start)
            .ok_or_else(|| "cbcs_invalid_traf_offset".to_string())?;
        if traf_start < cursor || traf_end > source.len() {
            return Err("cbcs_invalid_traf_range".to_string());
        }
        output.extend_from_slice(&source[cursor..traf_start]);
        let new_traf_start = output.len();
        let mut traf_bytes = source[traf_start..traf_end].to_vec();
        let new_traf_size = traf
            .traf
            .size
            .checked_add(parts.total_size())
            .ok_or_else(|| "cbcs_traf_growth_overflow".to_string())?;
        write_box_size(&mut traf_bytes, traf.traf.header_size, new_traf_size)?;
        output.extend_from_slice(&traf_bytes);

        if !parts.saiz.is_empty() {
            let senc_start = new_traf_start
                .checked_add(traf.traf.size)
                .and_then(|value| value.checked_add(parts.saiz.len()))
                .and_then(|value| value.checked_add(20))
                .ok_or_else(|| "cbcs_saio_offset_overflow".to_string())?;
            let first_iv_offset = senc_start
                .checked_add(16)
                .ok_or_else(|| "cbcs_saio_offset_overflow".to_string())?;
            output.extend_from_slice(&parts.saiz);
            output.extend_from_slice(&build_saio(first_iv_offset)?);
        }
        output.extend_from_slice(&parts.senc);
        cursor = traf_end;
    }
    output.extend_from_slice(&source[cursor..]);
    let output_len = output.len();
    write_box_size(&mut output, plan.moof.header_size, output_len)?;
    Ok(output)
}

fn build_auxiliary_parts(samples: &[EncryptedSample]) -> Result<AuxiliaryParts, String> {
    if samples.is_empty() {
        return Err("cbcs_empty_traf".to_string());
    }
    let track_id = samples[0].track_id;
    if samples.iter().any(|sample| sample.track_id != track_id) {
        return Err("cbcs_mixed_track_traf".to_string());
    }
    let track_kind = samples[0].track_kind;
    if samples.iter().any(|sample| sample.track_kind != track_kind) {
        return Err(format!("cbcs_mixed_track_kind:{track_id}"));
    }
    if track_kind == TrackKind::Audio {
        if samples.iter().any(|sample| !sample.subsamples.is_empty()) {
            return Err(format!("cbcs_audio_has_subsamples:{track_id}"));
        }
        let mut senc_payload = vec![0, 0, 0, 0];
        senc_payload.extend_from_slice(
            &u32::try_from(samples.len())
                .map_err(|_| "cbcs_sample_count_overflow".to_string())?
                .to_be_bytes(),
        );
        return Ok(AuxiliaryParts {
            saiz: Vec::new(),
            senc: make_box(*b"senc", &senc_payload)?,
        });
    }
    let has_subsamples = !samples[0].subsamples.is_empty();
    if samples
        .iter()
        .any(|sample| sample.subsamples.is_empty() == has_subsamples)
    {
        return Err(format!("cbcs_mixed_subsample_mode:{track_id}"));
    }

    let mut info_sizes = Vec::with_capacity(samples.len());
    let mut senc_payload = Vec::new();
    senc_payload.push(0);
    senc_payload.extend_from_slice(if has_subsamples {
        &[0, 0, 2]
    } else {
        &[0, 0, 0]
    });
    senc_payload.extend_from_slice(
        &u32::try_from(samples.len())
            .map_err(|_| "cbcs_sample_count_overflow".to_string())?
            .to_be_bytes(),
    );
    for sample in samples {
        senc_payload.extend_from_slice(&sample.iv[..CENC_PER_SAMPLE_IV_BYTES]);
        let mut info_size = CENC_PER_SAMPLE_IV_BYTES;
        if has_subsamples {
            let count = u16::try_from(sample.subsamples.len())
                .map_err(|_| "cbcs_subsample_count_overflow".to_string())?;
            senc_payload.extend_from_slice(&count.to_be_bytes());
            info_size = info_size.saturating_add(2);
            for subsample in &sample.subsamples {
                senc_payload.extend_from_slice(
                    &u16::try_from(subsample.clear_bytes)
                        .map_err(|_| "cbcs_subsample_clear_overflow".to_string())?
                        .to_be_bytes(),
                );
                senc_payload.extend_from_slice(
                    &u32::try_from(subsample.cipher_bytes)
                        .map_err(|_| "cbcs_subsample_cipher_overflow".to_string())?
                        .to_be_bytes(),
                );
                info_size = info_size.saturating_add(6);
            }
        }
        info_sizes.push(
            u8::try_from(info_size).map_err(|_| format!("cbcs_saiz_entry_too_large:{track_id}"))?,
        );
    }
    Ok(AuxiliaryParts {
        saiz: build_saiz(&info_sizes)?,
        senc: make_box(*b"senc", &senc_payload)?,
    })
}

fn build_saiz(info_sizes: &[u8]) -> Result<Vec<u8>, String> {
    let default_size = info_sizes
        .first()
        .copied()
        .filter(|first| info_sizes.iter().all(|size| size == first))
        .unwrap_or(0);
    let mut payload = vec![0, 0, 0, 0, default_size];
    payload.extend_from_slice(
        &u32::try_from(info_sizes.len())
            .map_err(|_| "cbcs_sample_count_overflow".to_string())?
            .to_be_bytes(),
    );
    if default_size == 0 {
        payload.extend_from_slice(info_sizes);
    }
    make_box(*b"saiz", &payload)
}

fn build_saio(first_iv_offset: usize) -> Result<Vec<u8>, String> {
    let mut payload = vec![0, 0, 0, 0];
    payload.extend_from_slice(&1u32.to_be_bytes());
    payload.extend_from_slice(
        &u32::try_from(first_iv_offset)
            .map_err(|_| "cbcs_saio_offset_overflow".to_string())?
            .to_be_bytes(),
    );
    make_box(*b"saio", &payload)
}

fn make_box(kind: [u8; 4], payload: &[u8]) -> Result<Vec<u8>, String> {
    let size = BOX_HEADER_BYTES
        .checked_add(payload.len())
        .ok_or_else(|| "cbcs_box_size_overflow".to_string())?;
    let size = u32::try_from(size).map_err(|_| "cbcs_box_too_large".to_string())?;
    let mut output = Vec::with_capacity(size as usize);
    output.extend_from_slice(&size.to_be_bytes());
    output.extend_from_slice(&kind);
    output.extend_from_slice(payload);
    Ok(output)
}

fn write_box_size(bytes: &mut [u8], header_size: usize, size: usize) -> Result<(), String> {
    match header_size {
        8 => {
            let value = u32::try_from(size).map_err(|_| "cbcs_box_too_large".to_string())?;
            bytes
                .get_mut(0..4)
                .ok_or_else(|| "cbcs_truncated_box_header".to_string())?
                .copy_from_slice(&value.to_be_bytes());
        }
        16 => {
            bytes
                .get_mut(0..4)
                .ok_or_else(|| "cbcs_truncated_box_header".to_string())?
                .copy_from_slice(&1u32.to_be_bytes());
            bytes
                .get_mut(8..16)
                .ok_or_else(|| "cbcs_truncated_large_box".to_string())?
                .copy_from_slice(&(size as u64).to_be_bytes());
        }
        _ => return Err("cbcs_invalid_box_header_size".to_string()),
    }
    Ok(())
}

fn write_i32(bytes: &mut [u8], offset: usize, value: i32) -> Result<(), String> {
    bytes
        .get_mut(offset..offset.saturating_add(4))
        .ok_or_else(|| "cbcs_truncated_i32".to_string())?
        .copy_from_slice(&value.to_be_bytes());
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn cbcs_encrypt_pattern_in_place(
    aes: &Aes128,
    bytes: &mut [u8],
    crypt_blocks: u8,
    skip_blocks: u8,
    previous: &mut [u8; AES_BLOCK_BYTES],
) {
    let crypt_blocks = usize::from(if crypt_blocks == 0 && skip_blocks == 0 {
        1
    } else {
        crypt_blocks
    });
    let skip_blocks = usize::from(skip_blocks);
    let full_blocks = bytes.len() / AES_BLOCK_BYTES;
    let mut block_index = 0;
    while block_index < full_blocks {
        let encrypt_count = crypt_blocks.min(full_blocks - block_index);
        for _ in 0..encrypt_count {
            let start = block_index * AES_BLOCK_BYTES;
            let mut block = [0u8; AES_BLOCK_BYTES];
            block.copy_from_slice(&bytes[start..start + AES_BLOCK_BYTES]);
            for (byte, prior) in block.iter_mut().zip(previous.iter()) {
                *byte ^= *prior;
            }
            aes.encrypt_block((&mut block).into());
            bytes[start..start + AES_BLOCK_BYTES].copy_from_slice(&block);
            *previous = block;
            block_index += 1;
        }
        block_index = block_index.saturating_add(skip_blocks).min(full_blocks);
    }
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
    if start + BOX_HEADER_BYTES > parent_end || parent_end > bytes.len() {
        return Err("cbcs_truncated_box_header".to_string());
    }
    let size32 = read_u32(bytes, start)? as usize;
    let kind = bytes[start + 4..start + 8].try_into().unwrap();
    let (size, header_size) = match size32 {
        0 => (parent_end - start, BOX_HEADER_BYTES),
        1 => {
            if start + 16 > parent_end {
                return Err("cbcs_truncated_large_box".to_string());
            }
            let size = read_u64(bytes, start + 8)?;
            let size = usize::try_from(size).map_err(|_| "cbcs_box_too_large".to_string())?;
            (size, 16)
        }
        value => (value, BOX_HEADER_BYTES),
    };
    if size < header_size || start.saturating_add(size) > parent_end {
        return Err("cbcs_invalid_box_size".to_string());
    }
    Ok(Mp4Box {
        start,
        size,
        header_size,
        kind,
    })
}

fn find_box_recursive(bytes: &[u8], parent: Mp4Box, target: [u8; 4]) -> Option<Mp4Box> {
    let children = parse_children(bytes, parent.payload_start(), parent.end()).ok()?;
    for child in children {
        if child.kind == target {
            return Some(child);
        }
        if is_container(child.kind) {
            if let Some(found) = find_box_recursive(bytes, child, target) {
                return Some(found);
            }
        }
    }
    None
}

fn direct_child(bytes: &[u8], parent: Mp4Box, target: [u8; 4]) -> Option<Mp4Box> {
    parse_children(bytes, parent.payload_start(), parent.end())
        .ok()?
        .into_iter()
        .find(|entry| entry.kind == target)
}

fn is_container(kind: [u8; 4]) -> bool {
    matches!(
        &kind,
        b"moov" | b"trak" | b"mdia" | b"minf" | b"stbl" | b"edts" | b"dinf" | b"mvex"
    )
}

fn scan_box_signatures(bytes: &[u8], start: usize, end: usize, target: [u8; 4]) -> Vec<Mp4Box> {
    let mut output = Vec::new();
    if end > bytes.len() || start + 8 > end {
        return output;
    }
    for type_offset in start + 4..=end.saturating_sub(4) {
        if bytes[type_offset..type_offset + 4] != target || type_offset < 4 {
            continue;
        }
        let box_start = type_offset - 4;
        let Ok(entry) = parse_box(bytes, box_start, end) else {
            continue;
        };
        if entry.kind == target && entry.end() <= end {
            output.push(entry);
        }
    }
    output
}

fn parse_tkhd_track_id(bytes: &[u8], entry: Mp4Box) -> Option<u32> {
    let payload = entry.payload_start();
    let version = *bytes.get(payload)?;
    let offset = if version == 1 {
        payload + 20
    } else {
        payload + 12
    };
    read_u32(bytes, offset).ok()
}

fn parse_handler_type(bytes: &[u8], entry: Mp4Box) -> Option<[u8; 4]> {
    let offset = entry.payload_start().saturating_add(8);
    bytes.get(offset..offset + 4)?.try_into().ok()
}

struct TfhdInfo {
    track_id: u32,
    default_sample_duration: Option<u32>,
    default_sample_size: Option<u32>,
    default_sample_flags: Option<u32>,
    has_base_data_offset: bool,
    default_base_is_moof: bool,
}

fn parse_tfhd(bytes: &[u8], entry: Mp4Box) -> Result<TfhdInfo, String> {
    let payload = entry.payload_start();
    let flags = read_u24(bytes, payload + 1)?;
    let track_id = read_u32(bytes, payload + 4)?;
    let mut cursor = payload + 8;
    let has_base_data_offset = flags & 0x000001 != 0;
    if has_base_data_offset {
        cursor += 8;
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
    let default_sample_flags = if flags & 0x000020 != 0 {
        Some(read_u32(bytes, cursor)?)
    } else {
        None
    };
    Ok(TfhdInfo {
        track_id,
        default_sample_duration,
        default_sample_size,
        default_sample_flags,
        has_base_data_offset,
        default_base_is_moof: flags & 0x020000 != 0,
    })
}

fn parse_trun(
    bytes: &[u8],
    moof_start: usize,
    entry: Mp4Box,
    default_sample_size: Option<u32>,
) -> Result<FragmentRun, String> {
    let payload = entry.payload_start();
    let flags = read_u24(bytes, payload + 1)?;
    let sample_count = read_u32(bytes, payload + 4)? as usize;
    let mut cursor = payload + 8;
    let data_offset_field = cursor;
    let data_offset = if flags & 0x000001 != 0 {
        let relative = read_i32(bytes, cursor)? as i64;
        cursor += 4;
        let absolute = (moof_start as i64)
            .checked_add(relative)
            .ok_or_else(|| "cbcs_invalid_trun_data_offset".to_string())?;
        usize::try_from(absolute).map_err(|_| "cbcs_invalid_trun_data_offset".to_string())?
    } else {
        return Err("cbcs_trun_missing_data_offset".to_string());
    };
    if flags & 0x000004 != 0 {
        cursor += 4;
    }
    let mut output = Vec::with_capacity(sample_count);
    let mut sample_offset = data_offset;
    for _ in 0..sample_count {
        if flags & 0x000100 != 0 {
            cursor += 4;
        }
        let sample_size = if flags & 0x000200 != 0 {
            let value = read_u32(bytes, cursor)?;
            cursor += 4;
            value
        } else {
            default_sample_size.ok_or_else(|| "cbcs_missing_sample_size".to_string())?
        } as usize;
        if flags & 0x000400 != 0 {
            cursor += 4;
        }
        if flags & 0x000800 != 0 {
            cursor += 4;
        }
        if cursor > entry.end() {
            return Err("cbcs_truncated_trun".to_string());
        }
        output.push((sample_offset, sample_size));
        sample_offset = sample_offset
            .checked_add(sample_size)
            .ok_or_else(|| "cbcs_sample_range_overflow".to_string())?;
    }
    Ok(FragmentRun {
        data_offset_field,
        samples: output,
    })
}

type ParsedSencEntry = ([u8; CENC_CONSTANT_IV_BYTES], Vec<Subsample>);

fn parse_senc(
    bytes: &[u8],
    entry: Mp4Box,
    runs: &[(usize, usize)],
    constant_iv: Option<[u8; CENC_CONSTANT_IV_BYTES]>,
) -> Result<Vec<ParsedSencEntry>, String> {
    let payload = entry.payload_start();
    let flags = read_u24(bytes, payload + 1)?;
    let sample_count = read_u32(bytes, payload + 4)? as usize;
    if sample_count != runs.len() {
        return Err("cbcs_senc_sample_count_mismatch".to_string());
    }
    let has_subsamples = flags & 0x000002 != 0;
    let mut cursor = payload + 8;
    let mut output = Vec::with_capacity(sample_count);
    for (_, sample_size) in runs {
        let iv = if let Some(iv) = constant_iv {
            iv
        } else {
            let mut iv = [0u8; CENC_CONSTANT_IV_BYTES];
            iv[..CENC_PER_SAMPLE_IV_BYTES].copy_from_slice(
                bytes
                    .get(cursor..cursor + CENC_PER_SAMPLE_IV_BYTES)
                    .ok_or_else(|| "cbcs_truncated_senc_iv".to_string())?,
            );
            cursor += CENC_PER_SAMPLE_IV_BYTES;
            iv
        };
        let subsamples = if has_subsamples {
            let count = read_u16(bytes, cursor)? as usize;
            cursor += 2;
            let mut entries = Vec::with_capacity(count);
            for _ in 0..count {
                let clear_bytes = read_u16(bytes, cursor)? as usize;
                let cipher_bytes = read_u32(bytes, cursor + 2)? as usize;
                cursor += 6;
                entries.push(Subsample {
                    clear_bytes,
                    cipher_bytes,
                });
            }
            entries
        } else {
            vec![Subsample {
                clear_bytes: 0,
                cipher_bytes: *sample_size,
            }]
        };
        let described = subsamples.iter().fold(0usize, |sum, value| {
            sum.saturating_add(value.clear_bytes)
                .saturating_add(value.cipher_bytes)
        });
        if described != *sample_size {
            return Err("cbcs_senc_sample_layout_mismatch".to_string());
        }
        output.push((iv, subsamples));
    }
    if cursor > entry.end() {
        return Err("cbcs_truncated_senc".to_string());
    }
    Ok(output)
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
    bytes
        .get(offset..offset + 4)
        .map(|value| i32::from_be_bytes(value.try_into().unwrap()))
        .ok_or_else(|| "cbcs_truncated_i32".to_string())
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, String> {
    bytes
        .get(offset..offset + 8)
        .map(|value| u64::from_be_bytes(value.try_into().unwrap()))
        .ok_or_else(|| "cbcs_truncated_u64".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbcs_pattern_encrypts_one_block_skips_nine_and_round_trips() {
        let aes = Aes128::new_from_slice(&[0x33; 16]).unwrap();
        let mut bytes = vec![0x44; 16 * 21 + 7];
        let original = bytes.clone();
        let mut previous = [0u8; 16];
        cbcs_encrypt_pattern_in_place(&aes, &mut bytes, 1, 9, &mut previous);
        assert_ne!(&bytes[0..16], &original[0..16]);
        assert_eq!(&bytes[16..160], &original[16..160]);
        assert_ne!(&bytes[160..176], &original[160..176]);
        assert_eq!(&bytes[176..320], &original[176..320]);
        assert_ne!(&bytes[320..336], &original[320..336]);
        assert_eq!(&bytes[336..], &original[336..]);
        let mut decrypt_previous = [0u8; 16];
        cbcs_decrypt_pattern_in_place(&aes, &mut bytes, 1, 9, &mut decrypt_previous);
        assert_eq!(bytes, original);
    }

    #[test]
    fn h264_cbcs_subsample_starts_after_slice_header() {
        let avcc = [
            0x01, 0x64, 0x00, 0x1e, 0xff, 0xe1, 0x00, 0x19, 0x67, 0x64, 0x00, 0x1e, 0xac, 0xd9,
            0x40, 0xa0, 0x2f, 0xf9, 0x70, 0x11, 0x00, 0x00, 0x03, 0x03, 0xe9, 0x00, 0x00, 0xea,
            0x60, 0x0f, 0x16, 0x2d, 0x96, 0x01, 0x00, 0x06, 0x68, 0xeb, 0xe3, 0xcb, 0x22, 0xc0,
        ];
        let nal = [
            0x65, 0x88, 0x84, 0x00, 0x21, 0xff, 0xcf, 0x73, 0xc7, 0x24, 0xc8, 0xc3, 0xa5, 0xcb,
            0x77, 0x60, 0x50, 0x85, 0xd9, 0xfc,
        ];
        let record = AvcDecoderConfigurationRecord::try_from(avcc.as_slice()).unwrap();
        let mut state = H264TrackState {
            context: record.create_context().unwrap(),
            nal_length_size: 4,
        };
        assert_eq!(h264_slice_header_bytes(&nal, &state.context).unwrap(), 6);
        let mut sample = Vec::new();
        sample.extend_from_slice(&(nal.len() as u32).to_be_bytes());
        sample.extend_from_slice(&nal);
        let subsamples = generate_h264_subsamples(&sample, &mut state).unwrap();
        assert_eq!(subsamples.len(), 1);
        assert_eq!(subsamples[0].clear_bytes, 10);
        assert_eq!(subsamples[0].cipher_bytes, 14);
    }

    #[test]
    fn hevc_cbcs_subsamples_leave_length_and_nal_header_clear() {
        let mut sample = Vec::new();
        let first = [0x26, 0x01, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85];
        sample.extend_from_slice(&(first.len() as u32).to_be_bytes());
        sample.extend_from_slice(&first);
        let second = [0x02, 0x01, 0x90, 0x91, 0x92];
        sample.extend_from_slice(&(second.len() as u32).to_be_bytes());
        sample.extend_from_slice(&second);

        let subsamples = generate_hevc_subsamples(&sample, 4).unwrap();
        assert_eq!(subsamples.len(), 2);
        assert_eq!(subsamples[0].clear_bytes, 6);
        assert_eq!(subsamples[0].cipher_bytes, 6);
        assert_eq!(subsamples[1].clear_bytes, 6);
        assert_eq!(subsamples[1].cipher_bytes, 3);
    }

    #[test]
    fn cbcs_subsamples_restart_cbc_chain_from_sample_iv() {
        let first_clear = [0xa1, 0xa2, 0xa3];
        let second_clear = [0xb1, 0xb2, 0xb3, 0xb4, 0xb5];
        let protected = [0x55; AES_BLOCK_BYTES];
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&first_clear);
        let first_cipher_offset = bytes.len();
        bytes.extend_from_slice(&protected);
        bytes.extend_from_slice(&second_clear);
        let second_cipher_offset = bytes.len();
        bytes.extend_from_slice(&protected);
        let original = bytes.clone();
        let placeholder = Mp4Box {
            start: 0,
            size: BOX_HEADER_BYTES,
            header_size: BOX_HEADER_BYTES,
            kind: *b"moof",
        };
        let samples = vec![EncryptedSample {
            track_id: 1,
            track_kind: TrackKind::Video,
            data_offset: 0,
            data_size: bytes.len(),
            iv: [0x22; CENC_CONSTANT_IV_BYTES],
            subsamples: vec![
                Subsample {
                    clear_bytes: first_clear.len(),
                    cipher_bytes: protected.len(),
                },
                Subsample {
                    clear_bytes: second_clear.len(),
                    cipher_bytes: protected.len(),
                },
            ],
        }];
        let plans = vec![MoofEncryptionPlan {
            moof: placeholder,
            trafs: vec![TrafEncryptionPlan {
                traf: placeholder,
                runs: Vec::new(),
                samples: samples.clone(),
            }],
        }];
        let context = SegmentEncryptionContext {
            kid: [0x42; 16],
            cek: Zeroizing::new([0x33; 16]),
            crypt_blocks: 1,
            skip_blocks: 9,
        };

        encrypt_clear_samples(&mut bytes, &plans, &context).unwrap();
        assert_eq!(
            &bytes[first_cipher_offset..first_cipher_offset + AES_BLOCK_BYTES],
            &bytes[second_cipher_offset..second_cipher_offset + AES_BLOCK_BYTES]
        );
        decrypt_samples(&mut bytes, &samples, &context).unwrap();
        assert_eq!(bytes, original);
    }

    #[test]
    fn detects_only_inband_hevc_parameter_sets() {
        let sample = hevc_sample(&[(19, &[0x80, 0x81]), (1, &[0x90, 0x91])]);
        assert!(!hevc_sample_has_parameter_sets(&sample, 4).unwrap());

        for nal_type in 32..=34 {
            let sample = hevc_sample(&[(nal_type, &[0x80, 0x81])]);
            assert!(hevc_sample_has_parameter_sets(&sample, 4).unwrap());
        }
    }

    #[test]
    fn canonicalizes_hev1_only_when_parameter_sets_are_out_of_band() {
        let sample = hevc_sample(&[(19, &[0x80, 0x81]), (1, &[0x90, 0x91])]);
        let (mut bytes, mut tracks, plans) = hevc_canonicalization_fixture(sample);
        canonicalize_hevc_sample_entries(&mut bytes, &mut tracks, &plans).unwrap();
        assert_eq!(&bytes[4..8], b"hvc1");
        assert_eq!(tracks[0].sample_entry.kind, *b"hvc1");
        assert_eq!(tracks[0].original_format, *b"hvc1");

        let sample = hevc_sample(&[(32, &[0x80, 0x81]), (19, &[0x90, 0x91])]);
        let (mut bytes, mut tracks, plans) = hevc_canonicalization_fixture(sample);
        canonicalize_hevc_sample_entries(&mut bytes, &mut tracks, &plans).unwrap();
        assert_eq!(&bytes[4..8], b"hev1");
        assert_eq!(tracks[0].sample_entry.kind, *b"hev1");
        assert_eq!(tracks[0].original_format, *b"hev1");
    }

    fn hevc_canonicalization_fixture(
        sample: Vec<u8>,
    ) -> (Vec<u8>, Vec<TrackProtectionPlan>, Vec<MoofEncryptionPlan>) {
        let sample_entry = Mp4Box {
            start: 0,
            size: 8,
            header_size: 8,
            kind: *b"hev1",
        };
        let mut bytes = vec![0, 0, 0, 8, b'h', b'e', b'v', b'1'];
        let data_offset = bytes.len();
        let data_size = sample.len();
        bytes.extend_from_slice(&sample);
        let tracks = vec![TrackProtectionPlan {
            track_id: 1,
            kind: TrackKind::Video,
            codec: TrackCodec::Hevc { nal_length_size: 4 },
            sample_entry,
            original_format: *b"hev1",
            size_ancestors: Vec::new(),
        }];
        let plans = vec![MoofEncryptionPlan {
            moof: sample_entry,
            trafs: vec![TrafEncryptionPlan {
                traf: sample_entry,
                runs: Vec::new(),
                samples: vec![EncryptedSample {
                    track_id: 1,
                    track_kind: TrackKind::Video,
                    data_offset,
                    data_size,
                    iv: [0; CENC_CONSTANT_IV_BYTES],
                    subsamples: Vec::new(),
                }],
            }],
        }];
        (bytes, tracks, plans)
    }

    fn hevc_sample(nals: &[(u8, &[u8])]) -> Vec<u8> {
        let mut sample = Vec::new();
        for (nal_type, payload) in nals {
            let mut nal = vec![nal_type << 1, 0x01];
            nal.extend_from_slice(payload);
            sample.extend_from_slice(&(nal.len() as u32).to_be_bytes());
            sample.extend_from_slice(&nal);
        }
        sample
    }

    #[test]
    fn audio_constant_iv_is_stable_per_content_key() {
        let first = derive_audio_constant_iv(&[0x11; 16]);
        assert_eq!(first, derive_audio_constant_iv(&[0x11; 16]));
        assert_ne!(first, derive_audio_constant_iv(&[0x12; 16]));
    }

    #[test]
    fn audio_uses_tenc_constant_iv_without_per_sample_auxiliary_offsets() {
        let context = SegmentEncryptionContext {
            kid: [0x42; 16],
            cek: zeroize::Zeroizing::new([0x24; 16]),
            crypt_blocks: 1,
            skip_blocks: 9,
        };
        let constant_iv = derive_audio_constant_iv(&context.kid);
        let placeholder = Mp4Box {
            start: 0,
            size: 8,
            header_size: 8,
            kind: *b"mp4a",
        };
        let track = TrackProtectionPlan {
            track_id: 2,
            kind: TrackKind::Audio,
            codec: TrackCodec::Audio,
            sample_entry: placeholder,
            original_format: *b"mp4a",
            size_ancestors: Vec::new(),
        };
        let sinf = build_track_sinf(&track, &context, &constant_iv).unwrap();
        let tenc = scan_box_signatures(&sinf, 0, sinf.len(), *b"tenc")
            .into_iter()
            .next()
            .unwrap();
        let payload = tenc.payload_start();
        assert_eq!(&sinf[payload..payload + 4], &[1, 0, 0, 0]);
        assert_eq!(&sinf[payload + 4..payload + 8], &[0, 0, 1, 0]);
        assert_eq!(&sinf[payload + 8..payload + 24], &context.kid);
        assert_eq!(sinf[payload + 24], CENC_CONSTANT_IV_BYTES as u8);
        assert_eq!(
            &sinf[payload + 25..payload + 25 + CENC_CONSTANT_IV_BYTES],
            &constant_iv
        );

        let samples = vec![
            EncryptedSample {
                track_id: 2,
                track_kind: TrackKind::Audio,
                data_offset: 0,
                data_size: 32,
                iv: constant_iv,
                subsamples: Vec::new(),
            },
            EncryptedSample {
                track_id: 2,
                track_kind: TrackKind::Audio,
                data_offset: 32,
                data_size: 31,
                iv: constant_iv,
                subsamples: Vec::new(),
            },
        ];
        let auxiliary = build_auxiliary_parts(&samples).unwrap();
        assert!(auxiliary.saiz.is_empty());
        assert_eq!(auxiliary.senc.len(), 16);
        assert_eq!(read_u32(&auxiliary.senc, 12).unwrap(), 2);
        assert_eq!(auxiliary.total_size(), auxiliary.senc.len());
    }

    #[test]
    fn packages_clear_fragment_and_round_trips_without_external_fixture() {
        assert_packaging_round_trip(synthetic_clear_avc_fragment(), false);
    }

    #[test]
    fn packages_one_fragment_without_reencrypting_an_archive_prefix() {
        let clear = synthetic_clear_avc_fragment();
        let top = parse_children(&clear, 0, clear.len()).unwrap();
        let fragment_start = top
            .iter()
            .find(|entry| entry.kind == *b"moof")
            .map(|entry| entry.start)
            .unwrap();
        let context = SegmentEncryptionContext {
            kid: [0x42; 16],
            cek: zeroize::Zeroizing::new([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ]),
            crypt_blocks: 1,
            skip_blocks: 9,
        };

        let packaged = package_clear_cmaf_fragment_to_cbcs(
            &clear[..fragment_start],
            &clear[fragment_start..],
            &context,
        )
        .unwrap();
        let mut combined = packaged.init.clone();
        combined.extend_from_slice(&packaged.fragment);

        assert_eq!(combined.len() as u64, packaged.info.file_len);
        assert_eq!(inspect_protected_cmaf(&combined).unwrap().fragment_count, 1);
        let video = extract_protected_video_fragment(&combined).unwrap();
        assert_eq!(video.codec, ProtectedVideoCodec::H264);
        assert_eq!(video.kid, context.kid);
        assert_eq!((video.crypt_blocks, video.skip_blocks), (1, 9));
        assert_eq!(video.nal_length_size, 4);
        assert_eq!(video.parameter_sets.len(), 2);
        assert_eq!(video.samples.len(), 1);
        assert_eq!(video.samples[0].pts_90khz, 0);
        assert_eq!(video.samples[0].duration_90khz, 3_000);
        assert!(video.samples[0].keyframe);
        assert_eq!(
            video.samples[0]
                .subsamples
                .iter()
                .map(|entry| usize::from(entry.clear_bytes) + entry.cipher_bytes as usize)
                .sum::<usize>(),
            video.samples[0].data.len()
        );
        let envelope = encode_protected_video_sample_envelope(&video, &video.samples[0]).unwrap();
        assert_eq!(&envelope[..8], PROTECTED_VIDEO_ENVELOPE_MAGIC);
        assert_eq!(envelope[8], 1);
        assert_eq!(&envelope[12..28], &context.kid);
        assert_eq!(
            read_u32(&envelope, 46).unwrap() as usize,
            video.samples[0].data.len()
        );
    }

    #[test]
    fn packages_clear_ffmpeg_fixture_when_path_is_provided() {
        let Ok(path) = std::env::var("SESAME_DVR_CLEAR_CMAF_TEST_FIXTURE") else {
            return;
        };
        let bytes = std::fs::read(path).unwrap();
        let expect_audio = clear_track_plans(&bytes)
            .unwrap()
            .iter()
            .any(|track| track.kind == TrackKind::Audio);
        assert_packaging_round_trip(bytes, expect_audio);
    }

    fn assert_packaging_round_trip(mut bytes: Vec<u8>, expect_audio: bool) {
        let original = bytes.clone();
        let original_len = bytes.len();
        let context = SegmentEncryptionContext {
            kid: [0x42; 16],
            cek: zeroize::Zeroizing::new([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ]),
            crypt_blocks: 1,
            skip_blocks: 9,
        };
        let tracks = clear_track_plans(&original).unwrap();
        let original_samples = clear_samples(&original, &tracks).unwrap();
        let expected_fragment_count = parse_children(&original, 0, original.len())
            .unwrap()
            .iter()
            .filter(|entry| entry.kind == *b"moof")
            .count() as u32;
        let info = package_clear_cmaf_memory_to_cbcs(&mut bytes, &context).unwrap();
        assert!(bytes.len() > original_len);
        assert_eq!(info.file_len, bytes.len() as u64);
        let protected = inspect_protected_cmaf(&bytes).unwrap();
        assert_eq!(protected.kid, context.kid);
        assert_eq!((protected.crypt_blocks, protected.skip_blocks), (1, 9));
        assert_eq!(protected.moov_end, info.moov_end);
        assert_eq!(protected.init_signature, info.init_signature);
        assert_eq!(protected.fragment_count, expected_fragment_count);
        assert!(bytes.windows(4).any(|window| window == b"cbcs"));
        assert_eq!(
            bytes.windows(4).any(|window| window == b"encv"),
            tracks.iter().any(|track| track.kind == TrackKind::Video)
        );
        assert_eq!(
            bytes.windows(4).any(|window| window == b"enca"),
            expect_audio
        );
        let tenc_entries = scan_box_signatures(&bytes, 0, bytes.len(), *b"tenc");
        assert_eq!(tenc_entries.len(), tracks.len());
        for tenc in tenc_entries {
            assert_eq!(
                &bytes[tenc.payload_start() + 8..tenc.payload_start() + 24],
                context.kid.as_slice()
            );
        }
        let samples = packaged_samples(&bytes, &tracks).unwrap();
        assert_eq!(samples.len(), original_samples.len());
        let mut decrypted = bytes.clone();
        decrypt_samples(&mut decrypted, &samples, &context).unwrap();
        for (expected, sample) in original_samples.iter().zip(&samples) {
            assert_eq!(
                &decrypted[sample.data_offset..sample.data_offset + sample.data_size],
                expected
            );
        }
        if let Ok(output) = std::env::var("SESAME_DVR_CBCS_TEST_OUTPUT") {
            std::fs::write(output, &bytes).unwrap();
        }
    }

    fn synthetic_clear_avc_fragment() -> Vec<u8> {
        let avcc = [
            0x01, 0x64, 0x00, 0x1e, 0xff, 0xe1, 0x00, 0x19, 0x67, 0x64, 0x00, 0x1e, 0xac, 0xd9,
            0x40, 0xa0, 0x2f, 0xf9, 0x70, 0x11, 0x00, 0x00, 0x03, 0x03, 0xe9, 0x00, 0x00, 0xea,
            0x60, 0x0f, 0x16, 0x2d, 0x96, 0x01, 0x00, 0x06, 0x68, 0xeb, 0xe3, 0xcb, 0x22, 0xc0,
        ];
        let nal = [
            0x65, 0x88, 0x84, 0x00, 0x21, 0xff, 0xcf, 0x73, 0xc7, 0x24, 0xc8, 0xc3, 0xa5, 0xcb,
            0x77, 0x60, 0x50, 0x85, 0xd9, 0xfc,
        ];
        let mut sample = Vec::new();
        sample.extend_from_slice(&(nal.len() as u32).to_be_bytes());
        sample.extend_from_slice(&nal);

        let mut avc1_payload = vec![0; 78];
        avc1_payload.extend_from_slice(&make_box(*b"avcC", &avcc).unwrap());
        let avc1 = make_box(*b"avc1", &avc1_payload).unwrap();
        let mut stsd_payload = vec![0, 0, 0, 0];
        stsd_payload.extend_from_slice(&1u32.to_be_bytes());
        stsd_payload.extend_from_slice(&avc1);
        let stsd = make_box(*b"stsd", &stsd_payload).unwrap();
        let stbl = make_box(*b"stbl", &stsd).unwrap();
        let minf = make_box(*b"minf", &stbl).unwrap();
        let mut hdlr_payload = vec![0; 12];
        hdlr_payload[8..12].copy_from_slice(b"vide");
        let hdlr = make_box(*b"hdlr", &hdlr_payload).unwrap();
        let mut mdhd_payload = vec![0; 24];
        mdhd_payload[12..16].copy_from_slice(&90_000u32.to_be_bytes());
        let mdhd = make_box(*b"mdhd", &mdhd_payload).unwrap();
        let mut mdia_payload = mdhd;
        mdia_payload.extend_from_slice(&hdlr);
        mdia_payload.extend_from_slice(&minf);
        let mdia = make_box(*b"mdia", &mdia_payload).unwrap();
        let mut tkhd_payload = vec![0; 20];
        tkhd_payload[12..16].copy_from_slice(&1u32.to_be_bytes());
        let tkhd = make_box(*b"tkhd", &tkhd_payload).unwrap();
        let mut trak_payload = tkhd;
        trak_payload.extend_from_slice(&mdia);
        let trak = make_box(*b"trak", &trak_payload).unwrap();
        let moov = make_box(*b"moov", &trak).unwrap();

        let mut tfhd_payload = vec![0, 0x02, 0, 0x18];
        tfhd_payload.extend_from_slice(&1u32.to_be_bytes());
        tfhd_payload.extend_from_slice(&3_000u32.to_be_bytes());
        tfhd_payload.extend_from_slice(&(sample.len() as u32).to_be_bytes());
        let tfhd = make_box(*b"tfhd", &tfhd_payload).unwrap();
        let build_moof = |data_offset: i32| {
            let mut trun_payload = vec![0, 0, 0, 1];
            trun_payload.extend_from_slice(&1u32.to_be_bytes());
            trun_payload.extend_from_slice(&data_offset.to_be_bytes());
            let trun = make_box(*b"trun", &trun_payload).unwrap();
            let mut traf_payload = tfhd.clone();
            traf_payload.extend_from_slice(&make_box(*b"tfdt", &[0; 8]).unwrap());
            traf_payload.extend_from_slice(&trun);
            make_box(*b"moof", &make_box(*b"traf", &traf_payload).unwrap()).unwrap()
        };
        let placeholder_moof = build_moof(0);
        let moof = build_moof((placeholder_moof.len() + BOX_HEADER_BYTES) as i32);
        let mdat = make_box(*b"mdat", &sample).unwrap();
        let mut output = make_box(*b"ftyp", b"iso6\0\0\0\x01iso6cmfc").unwrap();
        output.extend_from_slice(&moov);
        output.extend_from_slice(&moof);
        output.extend_from_slice(&mdat);
        output
    }

    fn clear_track_plans(bytes: &[u8]) -> Result<Vec<TrackProtectionPlan>, String> {
        let top = parse_children(bytes, 0, bytes.len())?;
        let moov = top
            .iter()
            .copied()
            .find(|entry| entry.kind == *b"moov")
            .ok_or_else(|| "test_missing_moov".to_string())?;
        parse_clear_track_plans(bytes, moov)
    }

    fn clear_samples(bytes: &[u8], tracks: &[TrackProtectionPlan]) -> Result<Vec<Vec<u8>>, String> {
        let top = parse_children(bytes, 0, bytes.len())?;
        let plans =
            parse_clear_fragment_plans(bytes, &top, tracks, &[0u8; CENC_CONSTANT_IV_BYTES])?;
        plans
            .iter()
            .flat_map(|plan| plan.trafs.iter())
            .flat_map(|traf| traf.samples.iter())
            .map(|sample| {
                bytes
                    .get(sample.data_offset..sample.data_offset + sample.data_size)
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| "test_sample_out_of_bounds".to_string())
            })
            .collect()
    }

    fn packaged_samples(
        bytes: &[u8],
        tracks: &[TrackProtectionPlan],
    ) -> Result<Vec<EncryptedSample>, String> {
        let top = parse_children(bytes, 0, bytes.len())?;
        let audio_constant_ivs = protected_audio_constant_ivs(bytes, &top)?;
        let mut output = Vec::new();
        for moof in top.iter().copied().filter(|entry| entry.kind == *b"moof") {
            for traf in parse_children(bytes, moof.payload_start(), moof.end())?
                .into_iter()
                .filter(|entry| entry.kind == *b"traf")
            {
                let children = parse_children(bytes, traf.payload_start(), traf.end())?;
                let tfhd = children
                    .iter()
                    .copied()
                    .find(|entry| entry.kind == *b"tfhd")
                    .ok_or_else(|| "test_missing_tfhd".to_string())?;
                let tfhd = parse_tfhd(bytes, tfhd)?;
                let track = tracks
                    .iter()
                    .find(|track| track.track_id == tfhd.track_id)
                    .ok_or_else(|| "test_missing_track".to_string())?;
                let runs: Vec<FragmentRun> = children
                    .iter()
                    .copied()
                    .filter(|entry| entry.kind == *b"trun")
                    .map(|entry| parse_trun(bytes, moof.start, entry, tfhd.default_sample_size))
                    .collect::<Result<_, _>>()?;
                let flat_runs: Vec<(usize, usize)> = runs
                    .iter()
                    .flat_map(|run| run.samples.iter().copied())
                    .collect();
                let senc = children
                    .iter()
                    .copied()
                    .find(|entry| entry.kind == *b"senc")
                    .ok_or_else(|| "test_missing_senc".to_string())?;
                let constant_iv = match track.kind {
                    TrackKind::Audio => {
                        assert!(!children.iter().any(|entry| entry.kind == *b"saiz"));
                        assert!(!children.iter().any(|entry| entry.kind == *b"saio"));
                        Some(
                            *audio_constant_ivs
                                .get(&tfhd.track_id)
                                .ok_or_else(|| "test_missing_audio_constant_iv".to_string())?,
                        )
                    }
                    TrackKind::Video => {
                        let saiz = children
                            .iter()
                            .copied()
                            .find(|entry| entry.kind == *b"saiz")
                            .ok_or_else(|| "test_missing_saiz".to_string())?;
                        let saio = children
                            .iter()
                            .copied()
                            .find(|entry| entry.kind == *b"saio")
                            .ok_or_else(|| "test_missing_saio".to_string())?;
                        assert!(saiz.start < saio.start && saio.start < senc.start);
                        assert_eq!(
                            read_u32(bytes, saio.payload_start() + 8)? as usize,
                            senc.start + 16 - moof.start
                        );
                        None
                    }
                };
                let entries = parse_senc(bytes, senc, &flat_runs, constant_iv)?;
                for ((data_offset, data_size), (iv, subsamples)) in
                    flat_runs.into_iter().zip(entries)
                {
                    output.push(EncryptedSample {
                        track_id: tfhd.track_id,
                        track_kind: track.kind,
                        data_offset,
                        data_size,
                        iv,
                        subsamples,
                    });
                }
            }
        }
        Ok(output)
    }

    fn protected_audio_constant_ivs(
        bytes: &[u8],
        top: &[Mp4Box],
    ) -> Result<HashMap<u32, [u8; CENC_CONSTANT_IV_BYTES]>, String> {
        let moov = top
            .iter()
            .copied()
            .find(|entry| entry.kind == *b"moov")
            .ok_or_else(|| "test_missing_moov".to_string())?;
        let mut output = HashMap::new();
        for trak in parse_children(bytes, moov.payload_start(), moov.end())?
            .into_iter()
            .filter(|entry| entry.kind == *b"trak")
        {
            let track_id = find_box_recursive(bytes, trak, *b"tkhd")
                .and_then(|entry| parse_tkhd_track_id(bytes, entry))
                .ok_or_else(|| "test_missing_track_id".to_string())?;
            let handler = find_box_recursive(bytes, trak, *b"hdlr")
                .and_then(|entry| parse_handler_type(bytes, entry))
                .ok_or_else(|| "test_missing_handler".to_string())?;
            if handler != *b"soun" {
                continue;
            }
            let tenc = scan_box_signatures(bytes, trak.start, trak.end(), *b"tenc")
                .into_iter()
                .next()
                .ok_or_else(|| "test_missing_tenc".to_string())?;
            let payload = tenc.payload_start();
            if bytes.get(payload + 7).copied() != Some(0)
                || bytes.get(payload + 24).copied() != Some(CENC_CONSTANT_IV_BYTES as u8)
            {
                return Err("test_invalid_audio_tenc".to_string());
            }
            let iv = bytes
                .get(payload + 25..payload + 25 + CENC_CONSTANT_IV_BYTES)
                .ok_or_else(|| "test_truncated_audio_constant_iv".to_string())?
                .try_into()
                .unwrap();
            output.insert(track_id, iv);
        }
        Ok(output)
    }

    fn decrypt_samples(
        bytes: &mut [u8],
        samples: &[EncryptedSample],
        context: &SegmentEncryptionContext,
    ) -> Result<(), String> {
        let aes = Aes128::new_from_slice(context.cek.as_ref())
            .map_err(|_| "test_invalid_content_key".to_string())?;
        for sample in samples {
            let (crypt_blocks, skip_blocks) = match sample.track_kind {
                TrackKind::Video => (context.crypt_blocks, context.skip_blocks),
                TrackKind::Audio => (1, 0),
            };
            if sample.subsamples.is_empty() {
                let mut previous = sample.iv;
                cbcs_decrypt_pattern_in_place(
                    &aes,
                    &mut bytes[sample.data_offset..sample.data_offset + sample.data_size],
                    crypt_blocks,
                    skip_blocks,
                    &mut previous,
                );
                continue;
            }
            let mut cursor = sample.data_offset;
            for subsample in &sample.subsamples {
                cursor = cursor.saturating_add(subsample.clear_bytes);
                let end = cursor.saturating_add(subsample.cipher_bytes);
                let mut previous = sample.iv;
                cbcs_decrypt_pattern_in_place(
                    &aes,
                    &mut bytes[cursor..end],
                    crypt_blocks,
                    skip_blocks,
                    &mut previous,
                );
                cursor = end;
            }
            if cursor != sample.data_offset + sample.data_size {
                return Err("test_sample_layout_mismatch".to_string());
            }
        }
        Ok(())
    }

    fn cbcs_decrypt_pattern_in_place(
        aes: &Aes128,
        bytes: &mut [u8],
        crypt_blocks: u8,
        skip_blocks: u8,
        previous: &mut [u8; AES_BLOCK_BYTES],
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
                *previous = cipher;
                block_index += 1;
            }
            block_index = block_index.saturating_add(skip_blocks).min(full_blocks);
        }
    }
}
