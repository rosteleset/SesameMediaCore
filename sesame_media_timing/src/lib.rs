use std::time::{Duration, Instant};

pub const RTP_TIMESTAMP_WRAP: i64 = 1_i64 << 32;
pub const RTP_TIMESTAMP_WRAP_THRESHOLD: i64 = 1_i64 << 31;
pub const TIMESTAMP_GAP_CLAMP_MULTIPLIER: i64 = 5;
pub const MAX_RELIABLE_VIDEO_FRAME_RATE: i64 = 240;
pub const VIDEO_CLOCK_RATE: i64 = 90_000;

const LIVE_MIN_RESYNC_GAP: i64 = VIDEO_CLOCK_RATE / 4;
const LIVE_RESYNC_FRAME_GAP: i64 = 4;
const LIVE_MAX_FRAME_DURATION: i64 = VIDEO_CLOCK_RATE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rational {
    pub numerator: i64,
    pub denominator: i64,
}

impl Rational {
    pub const fn new(numerator: i64, denominator: i64) -> Self {
        Self {
            numerator,
            denominator,
        }
    }

    fn valid(self) -> bool {
        self.numerator > 0 && self.denominator > 0
    }
}

#[derive(Clone, Debug, Default)]
pub struct DurationEstimator {
    pub previous_dts: Option<i64>,
    pub samples: [i64; 5],
    pub sample_count: usize,
    pub learned_duration: Option<i64>,
}

impl DurationEstimator {
    pub fn observe(
        &mut self,
        timestamp: i64,
        minimum_duration: i64,
        maximum_duration: i64,
    ) -> Option<i64> {
        if let Some(duration) = self.learned_duration {
            return Some(duration);
        }

        let previous = self.previous_dts.replace(timestamp)?;
        let delta = timestamp.saturating_sub(previous);
        if delta < minimum_duration
            || delta > maximum_duration.max(minimum_duration)
            || self.sample_count >= self.samples.len()
        {
            return None;
        }

        self.samples[self.sample_count] = delta;
        self.sample_count += 1;
        if self.sample_count < self.samples.len() {
            return None;
        }

        let mut samples = self.samples;
        samples.sort_unstable();
        let duration = samples[samples.len() / 2];
        self.learned_duration = Some(duration);
        self.learned_duration
    }
}

#[derive(Clone, Debug, Default)]
pub struct TimestampState {
    pub base_dts: Option<i64>,
    pub last_dts: Option<i64>,
    pub last_duration: Option<i64>,
    pub last_raw_dts: Option<i64>,
    pub wrap_offset: i64,
    pub direct_archive_duration: DurationEstimator,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveTimelineSample {
    pub dts: i64,
    pub pts: i64,
    pub duration: i64,
    pub cadence_learned: bool,
    pub resynced: bool,
    pub source_timing_preserved: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LivePacingDecision {
    pub delay: Duration,
    pub resynced: bool,
}

#[derive(Clone, Debug)]
pub struct LiveMediaPacer {
    clock_rate: i64,
    max_step_ticks: i64,
    max_lag: Duration,
    startup_delay: Duration,
    startup_delay_pending: bool,
    last_media_ticks: Option<i64>,
    deadline: Option<Instant>,
}

impl LiveMediaPacer {
    pub fn new(clock_rate: i64, max_step_ticks: i64, max_lag: Duration) -> Self {
        Self {
            clock_rate: clock_rate.max(1),
            max_step_ticks: max_step_ticks.max(1),
            max_lag,
            startup_delay: Duration::ZERO,
            startup_delay_pending: false,
            last_media_ticks: None,
            deadline: None,
        }
    }

    pub fn with_startup_delay(mut self, startup_delay: Duration) -> Self {
        self.startup_delay = startup_delay;
        self.startup_delay_pending = !startup_delay.is_zero();
        self
    }

    pub fn delay_for(&mut self, media_ticks: i64, now: Instant) -> LivePacingDecision {
        let Some(previous_media_ticks) = self.last_media_ticks else {
            let startup_delay = if self.startup_delay_pending {
                self.startup_delay_pending = false;
                self.startup_delay
            } else {
                Duration::ZERO
            };
            self.reset(media_ticks, now.checked_add(startup_delay).unwrap_or(now));
            return LivePacingDecision {
                delay: startup_delay,
                resynced: false,
            };
        };
        let Some(previous_deadline) = self.deadline else {
            self.reset(media_ticks, now);
            return LivePacingDecision {
                delay: Duration::ZERO,
                resynced: true,
            };
        };

        let step_ticks = media_ticks.saturating_sub(previous_media_ticks);
        if step_ticks == 0 {
            return LivePacingDecision {
                delay: Duration::ZERO,
                resynced: false,
            };
        }
        if step_ticks < 0 || step_ticks > self.max_step_ticks {
            self.reset(media_ticks, now);
            return LivePacingDecision {
                delay: Duration::ZERO,
                resynced: true,
            };
        }

        let Some(step) = ticks_to_duration(step_ticks, self.clock_rate) else {
            self.reset(media_ticks, now);
            return LivePacingDecision {
                delay: Duration::ZERO,
                resynced: true,
            };
        };
        let Some(deadline) = previous_deadline.checked_add(step) else {
            self.reset(media_ticks, now);
            return LivePacingDecision {
                delay: Duration::ZERO,
                resynced: true,
            };
        };

        self.last_media_ticks = Some(media_ticks);
        self.deadline = Some(deadline);
        if now >= deadline {
            if now.duration_since(deadline) > self.max_lag {
                self.reset(media_ticks, now);
                LivePacingDecision {
                    delay: Duration::ZERO,
                    resynced: true,
                }
            } else {
                LivePacingDecision {
                    delay: Duration::ZERO,
                    resynced: false,
                }
            }
        } else {
            LivePacingDecision {
                delay: deadline.duration_since(now),
                resynced: false,
            }
        }
    }

    fn reset(&mut self, media_ticks: i64, now: Instant) {
        self.last_media_ticks = Some(media_ticks);
        self.deadline = Some(now);
    }
}

#[derive(Clone, Debug)]
pub struct LiveTimelineRepair {
    declared_duration: Option<i64>,
    force_declared_cadence: bool,
    frame_duration: i64,
    source_base: Option<i64>,
    source_last: Option<i64>,
    source_wrap_state: TimestampState,
    source_duration: DurationEstimator,
    wall_duration: DurationEstimator,
    wall_last: Option<i64>,
    last_output_dts: Option<i64>,
}

impl LiveTimelineRepair {
    pub fn new(declared_duration: Option<i64>, fallback_duration: i64) -> Self {
        let declared_duration = declared_duration.filter(|duration| *duration > 0);
        Self {
            declared_duration,
            force_declared_cadence: false,
            frame_duration: declared_duration.unwrap_or(fallback_duration.max(1)),
            source_base: None,
            source_last: None,
            source_wrap_state: TimestampState::default(),
            source_duration: DurationEstimator::default(),
            wall_duration: DurationEstimator::default(),
            wall_last: None,
            last_output_dts: None,
        }
    }

    pub fn with_forced_declared_cadence(mut self, force: bool) -> Self {
        self.force_declared_cadence = force && self.declared_duration.is_some();
        self
    }

    pub fn repair(
        &mut self,
        raw_dts: Option<i64>,
        raw_pts: Option<i64>,
        wall_relative: i64,
    ) -> LiveTimelineSample {
        let wall_relative = wall_relative.max(0);
        let minimum_duration =
            minimum_plausible_video_duration_ticks(Rational::new(1, VIDEO_CLOCK_RATE));
        let unwrapped_dts = raw_dts.map(|dts| unwrap_dts(dts, &mut self.source_wrap_state));
        let source_delta = unwrapped_dts.and_then(|dts| {
            let previous = self.source_last.replace(dts)?;
            Some(dts.saturating_sub(previous))
        });
        let source_relative = unwrapped_dts.map(|dts| {
            let base = *self.source_base.get_or_insert(dts);
            dts.saturating_sub(base).max(0)
        });
        let wall_delta = self
            .wall_last
            .replace(wall_relative)
            .map(|previous| wall_relative.saturating_sub(previous));

        if let Some(dts) = unwrapped_dts {
            self.source_duration
                .observe(dts, minimum_duration, LIVE_MAX_FRAME_DURATION);
        }
        self.wall_duration
            .observe(wall_relative, minimum_duration, LIVE_MAX_FRAME_DURATION);

        if self.declared_duration.is_none() {
            if let Some(duration) = self
                .source_duration
                .learned_duration
                .or(self.wall_duration.learned_duration)
            {
                self.frame_duration = duration.max(1);
            }
        }

        let cadence_learned = self.declared_duration.is_some()
            || self.source_duration.learned_duration.is_some()
            || self.wall_duration.learned_duration.is_some();
        let previous_output = self.last_output_dts;
        let expected = previous_output
            .map(|dts| dts.saturating_add(self.frame_duration))
            .unwrap_or(0);
        let resync_gap = self
            .frame_duration
            .saturating_mul(LIVE_RESYNC_FRAME_GAP)
            .max(LIVE_MIN_RESYNC_GAP);
        let source_late = source_relative.is_some_and(|source| {
            previous_output.is_some() && source.saturating_sub(expected) > resync_gap
        });
        let wall_late =
            previous_output.is_some() && wall_relative.saturating_sub(expected) > resync_gap;
        let resynced = !self.force_declared_cadence
            && wall_late
            && (source_late || source_relative.is_none());
        let valid_source_delta = source_delta
            .filter(|delta| *delta >= minimum_duration && *delta <= LIVE_MAX_FRAME_DURATION);
        let valid_wall_delta = wall_delta
            .filter(|delta| *delta >= minimum_duration && *delta <= LIVE_MAX_FRAME_DURATION);
        let source_timing_preserved = previous_output.is_some()
            && self.declared_duration.is_none()
            && valid_source_delta.is_some()
            && !source_late
            && !resynced;

        let dts = if previous_output.is_none() {
            0
        } else if resynced {
            wall_relative.max(expected)
        } else if source_timing_preserved {
            previous_output
                .unwrap_or_default()
                .saturating_add(valid_source_delta.unwrap_or(self.frame_duration))
        } else if self.declared_duration.is_none()
            && (source_relative.is_none() || valid_source_delta.is_none())
        {
            previous_output
                .unwrap_or_default()
                .saturating_add(valid_wall_delta.unwrap_or(self.frame_duration))
        } else {
            expected
        };

        let source_composition_offset = match (raw_pts, unwrapped_dts) {
            (Some(pts), Some(dts)) => unwrap_pts(pts, self.source_wrap_state.wrap_offset, dts)
                .saturating_sub(dts)
                .clamp(0, LIVE_MAX_FRAME_DURATION),
            _ => 0,
        };
        let duration = if source_timing_preserved {
            valid_source_delta.unwrap_or(self.frame_duration)
        } else if cadence_learned {
            self.frame_duration
        } else {
            valid_source_delta
                .or(valid_wall_delta)
                .unwrap_or(self.frame_duration)
        }
        .max(1);

        self.last_output_dts = Some(dts);
        LiveTimelineSample {
            dts,
            pts: dts.saturating_add(source_composition_offset),
            duration,
            cadence_learned,
            resynced,
            source_timing_preserved,
        }
    }
}

pub fn plausible_declared_frame_rate(frame_rate: Rational) -> bool {
    let numerator = i128::from(frame_rate.numerator);
    let denominator = i128::from(frame_rate.denominator);

    numerator > 0
        && denominator > 0
        && numerator <= denominator.saturating_mul(i128::from(MAX_RELIABLE_VIDEO_FRAME_RATE))
}

pub fn declared_frame_rate(average_rate: Rational, rate: Rational) -> Option<Rational> {
    if plausible_declared_frame_rate(average_rate) {
        Some(average_rate)
    } else if plausible_declared_frame_rate(rate) {
        Some(rate)
    } else {
        None
    }
}

pub fn estimated_frame_duration_ticks(
    time_base: Rational,
    average_rate: Rational,
    rate: Rational,
) -> Option<i64> {
    frame_duration_ticks(time_base, declared_frame_rate(average_rate, rate)?)
}

pub fn frame_duration_ticks(time_base: Rational, frame_rate: Rational) -> Option<i64> {
    if !time_base.valid() || !plausible_declared_frame_rate(frame_rate) {
        return None;
    }

    let numerator =
        i128::from(frame_rate.denominator).saturating_mul(i128::from(time_base.denominator));
    let denominator =
        i128::from(frame_rate.numerator).saturating_mul(i128::from(time_base.numerator));
    rounded_ratio(numerator, denominator)
}

pub fn frame_duration_ticks_for_fps(time_base: Rational, fps: f64) -> Option<i64> {
    if !time_base.valid()
        || !fps.is_finite()
        || fps <= 0.0
        || fps > MAX_RELIABLE_VIDEO_FRAME_RATE as f64
    {
        return None;
    }

    let ticks = time_base.denominator as f64 / (fps * time_base.numerator as f64);
    ticks.is_finite().then(|| ticks.max(1.0).round() as i64)
}

pub fn minimum_plausible_video_duration_ticks(time_base: Rational) -> i64 {
    if !time_base.valid() {
        return 1;
    }

    let numerator = i128::from(time_base.denominator);
    let denominator =
        i128::from(time_base.numerator).saturating_mul(i128::from(MAX_RELIABLE_VIDEO_FRAME_RATE));
    ceil_ratio(numerator, denominator).unwrap_or(1)
}

pub fn rescale_ticks(value: i64, source: Rational, destination: Rational) -> i64 {
    if !source.valid() || !destination.valid() {
        return value;
    }

    let numerator = i128::from(value)
        .saturating_mul(i128::from(source.numerator))
        .saturating_mul(i128::from(destination.denominator));
    let denominator =
        i128::from(source.denominator).saturating_mul(i128::from(destination.numerator));
    rounded_ratio_signed(numerator, denominator).unwrap_or(value)
}

pub fn unwrap_dts(raw_dts: i64, state: &mut TimestampState) -> i64 {
    if let Some(last_raw_dts) = state.last_raw_dts {
        if raw_dts < last_raw_dts
            && last_raw_dts.saturating_sub(raw_dts) > RTP_TIMESTAMP_WRAP_THRESHOLD
        {
            state.wrap_offset = state.wrap_offset.saturating_add(RTP_TIMESTAMP_WRAP);
        } else if raw_dts > last_raw_dts
            && raw_dts.saturating_sub(last_raw_dts) > RTP_TIMESTAMP_WRAP_THRESHOLD
        {
            state.wrap_offset = state.wrap_offset.saturating_sub(RTP_TIMESTAMP_WRAP);
        }
    }

    state.last_raw_dts = Some(raw_dts);
    raw_dts.saturating_add(state.wrap_offset)
}

pub fn unwrap_pts(raw_pts: i64, wrap_offset: i64, unwrapped_dts: i64) -> i64 {
    let mut pts = raw_pts.saturating_add(wrap_offset);
    if pts.saturating_add(RTP_TIMESTAMP_WRAP_THRESHOLD) < unwrapped_dts {
        pts = pts.saturating_add(RTP_TIMESTAMP_WRAP);
    }
    pts
}

fn ticks_to_duration(ticks: i64, clock_rate: i64) -> Option<Duration> {
    if ticks < 0 || clock_rate <= 0 {
        return None;
    }
    let nanos = i128::from(ticks).saturating_mul(1_000_000_000) / i128::from(clock_rate);
    Some(Duration::from_nanos(
        u64::try_from(nanos).unwrap_or(u64::MAX),
    ))
}

fn rounded_ratio(numerator: i128, denominator: i128) -> Option<i64> {
    if numerator < 0 || denominator <= 0 {
        return None;
    }
    let rounded = numerator.saturating_add(denominator / 2) / denominator;
    Some(rounded.clamp(1, i128::from(i64::MAX)) as i64)
}

fn rounded_ratio_signed(numerator: i128, denominator: i128) -> Option<i64> {
    if denominator <= 0 {
        return None;
    }
    let rounded = if numerator >= 0 {
        numerator.saturating_add(denominator / 2) / denominator
    } else {
        numerator.saturating_sub(denominator / 2) / denominator
    };
    Some(rounded.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64)
}

fn ceil_ratio(numerator: i128, denominator: i128) -> Option<i64> {
    if numerator < 0 || denominator <= 0 {
        return None;
    }
    let value = numerator.saturating_add(denominator.saturating_sub(1)) / denominator;
    Some(value.clamp(1, i128::from(i64::MAX)) as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_placeholder_90khz_frame_rate() {
        assert_eq!(
            estimated_frame_duration_ticks(
                Rational::new(1, 90_000),
                Rational::new(90_000, 1),
                Rational::new(0, 1),
            ),
            None
        );
    }

    #[test]
    fn learns_15fps_from_source_timestamps() {
        let mut repair = LiveTimelineRepair::new(None, 3_600);
        let arrivals = [0, 5_800, 12_300, 17_700, 24_500, 29_800, 36_100];
        let timestamps = arrivals
            .into_iter()
            .enumerate()
            .map(|(index, wall)| {
                repair
                    .repair(Some(index as i64 * 6_000), Some(index as i64 * 6_000), wall)
                    .dts
            })
            .collect::<Vec<_>>();

        assert_eq!(
            timestamps,
            vec![0, 6_000, 12_000, 18_000, 24_000, 30_000, 36_000]
        );
        assert_eq!(repair.frame_duration, 6_000);
    }

    #[test]
    fn preserves_plausible_variable_source_cadence_after_learning() {
        let mut repair = LiveTimelineRepair::new(None, 3_600);
        let source = [0, 3_600, 10_800, 18_000, 21_600, 28_800, 36_000, 39_600];
        let samples = source
            .into_iter()
            .enumerate()
            .map(|(index, timestamp)| {
                repair.repair(
                    Some(timestamp),
                    Some(timestamp),
                    i64::try_from(index).unwrap_or_default() * 6_000,
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(
            samples.iter().map(|sample| sample.dts).collect::<Vec<_>>(),
            source
        );
        assert!(samples[6].cadence_learned);
        assert!(samples[6].source_timing_preserved);
        assert_eq!(samples[6].duration, 7_200);
        assert_eq!(samples[7].duration, 3_600);
    }

    #[test]
    fn paces_accelerated_variable_frame_cadence() {
        let started = Instant::now();
        let mut pacer = LiveMediaPacer::new(
            VIDEO_CLOCK_RATE,
            VIDEO_CLOCK_RATE * 2,
            Duration::from_millis(120),
        );

        assert_eq!(
            pacer.delay_for(0, started),
            LivePacingDecision {
                delay: Duration::ZERO,
                resynced: false,
            }
        );
        assert_eq!(
            pacer.delay_for(3_600, started).delay,
            Duration::from_millis(40)
        );
        assert_eq!(
            pacer
                .delay_for(10_800, started + Duration::from_millis(40))
                .delay,
            Duration::from_millis(80)
        );
        assert_eq!(
            pacer
                .delay_for(18_000, started + Duration::from_millis(120))
                .delay,
            Duration::from_millis(80)
        );
    }

    #[test]
    fn startup_delay_buffers_transport_jitter_without_changing_media_cadence() {
        let started = Instant::now();
        let mut pacer = LiveMediaPacer::new(
            VIDEO_CLOCK_RATE,
            VIDEO_CLOCK_RATE * 2,
            Duration::from_millis(120),
        )
        .with_startup_delay(Duration::from_millis(300));

        assert_eq!(
            pacer.delay_for(0, started),
            LivePacingDecision {
                delay: Duration::from_millis(300),
                resynced: false,
            }
        );
        assert_eq!(
            pacer
                .delay_for(6_000, started + Duration::from_millis(300))
                .delay,
            Duration::from_nanos(66_666_666)
        );
        assert_eq!(
            pacer
                .delay_for(12_000, started + Duration::from_millis(367))
                .delay,
            Duration::from_nanos(66_333_332)
        );
    }

    #[test]
    fn pacer_resyncs_instead_of_replaying_a_late_burst() {
        let started = Instant::now();
        let mut pacer = LiveMediaPacer::new(
            VIDEO_CLOCK_RATE,
            VIDEO_CLOCK_RATE * 2,
            Duration::from_millis(120),
        );

        pacer.delay_for(0, started);
        let late = pacer.delay_for(3_600, started + Duration::from_millis(500));
        assert_eq!(
            late,
            LivePacingDecision {
                delay: Duration::ZERO,
                resynced: true,
            }
        );
        assert_eq!(
            pacer
                .delay_for(7_200, started + Duration::from_millis(500))
                .delay,
            Duration::from_millis(40)
        );
    }

    #[test]
    fn ignores_arrival_jitter_with_declared_cadence() {
        let mut repair = LiveTimelineRepair::new(Some(6_000), 3_600);
        let arrivals = [0, 4_900, 10_900, 18_100, 23_000, 29_100, 36_900];
        let timestamps = arrivals
            .into_iter()
            .map(|wall| repair.repair(None, None, wall).dts)
            .collect::<Vec<_>>();

        assert_eq!(
            timestamps,
            vec![0, 6_000, 12_000, 18_000, 24_000, 30_000, 36_000]
        );
    }

    #[test]
    fn resyncs_after_real_source_and_wall_gap() {
        let mut repair = LiveTimelineRepair::new(Some(6_000), 3_600);
        assert_eq!(repair.repair(Some(0), Some(0), 0).dts, 0);
        assert_eq!(repair.repair(Some(6_000), Some(6_000), 6_000).dts, 6_000);
        assert_eq!(
            repair.repair(Some(54_000), Some(54_000), 54_000).dts,
            54_000
        );
        assert_eq!(
            repair.repair(Some(60_000), Some(60_000), 56_000).dts,
            60_000
        );
    }

    #[test]
    fn forced_declared_cadence_does_not_turn_input_stalls_into_media_gaps() {
        let mut repair =
            LiveTimelineRepair::new(Some(6_000), 3_600).with_forced_declared_cadence(true);
        assert_eq!(repair.repair(Some(0), Some(0), 0).dts, 0);
        assert_eq!(repair.repair(Some(6_000), Some(6_000), 6_000).dts, 6_000);

        let delayed = repair.repair(Some(36_000), Some(36_000), 36_000);
        assert_eq!(delayed.dts, 12_000);
        assert!(!delayed.resynced);
        assert_eq!(
            repair.repair(Some(42_000), Some(42_000), 42_000).dts,
            18_000
        );
    }

    #[test]
    fn clamps_false_source_jump_to_elapsed_wall_gap() {
        let mut repair = LiveTimelineRepair::new(Some(6_000), 3_600);
        assert_eq!(repair.repair(Some(0), Some(0), 0).dts, 0);
        assert_eq!(repair.repair(Some(6_000), Some(6_000), 6_000).dts, 6_000);

        let jumped = repair.repair(Some(7_200_000), Some(7_200_000), 45_000);
        assert_eq!(jumped.dts, 45_000);
        assert!(jumped.resynced);
        assert_eq!(
            repair.repair(Some(7_206_000), Some(7_206_000), 51_000).dts,
            51_000
        );
    }
}
