// src-tauri/src/session/state.rs
use super::source::{DetectedSession, DetectionDiagnostics, SessionDetectorError, SessionSource};
use super::{create_session_source, mode_from_env, BackendMode};
use crate::session::detector::LegacySessionSource;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

const DOWNGRADE_THRESHOLD: u32 = 5;

pub struct DetectorState {
    source: Box<dyn SessionSource>,
    consecutive_failures: u32,
    telemetry_counter: Arc<AtomicU32>,
    mode: BackendMode,
}

impl DetectorState {
    pub fn new() -> Self {
        Self {
            source: create_session_source(),
            consecutive_failures: 0,
            telemetry_counter: Arc::new(AtomicU32::new(0)),
            mode: mode_from_env(),
        }
    }

    pub fn detect(
        &mut self,
    ) -> Result<(Vec<DetectedSession>, DetectionDiagnostics), SessionDetectorError> {
        match self.source.detect() {
            Ok((mut detected, mut diagnostics)) => {
                self.consecutive_failures = 0;
                if self.should_supplement_cli_with_legacy() {
                    match LegacySessionSource::new().and_then(|mut legacy| legacy.detect()) {
                        Ok((legacy_detected, legacy_diagnostics)) => {
                            supplement_detected_sessions(&mut detected, legacy_detected);
                            diagnostics = merge_diagnostics(diagnostics, legacy_diagnostics);
                        }
                        Err(e) => {
                            crate::debug_log::log_warn(&format!(
                                "CLI detector legacy supplement failed: {e}"
                            ));
                        }
                    }
                }
                Ok((detected, diagnostics))
            }
            Err(e) => {
                self.consecutive_failures += 1;
                if self.should_supplement_cli_with_legacy() {
                    match LegacySessionSource::new().and_then(|mut legacy| legacy.detect()) {
                        Ok(out) => {
                            if self.should_downgrade() {
                                self.downgrade_to_legacy();
                            }
                            return Ok(out);
                        }
                        Err(legacy_err) => {
                            crate::debug_log::log_warn(&format!(
                                "CLI detector failed ({e}); legacy fallback also failed: {legacy_err}"
                            ));
                        }
                    }
                }
                if self.should_downgrade() {
                    self.downgrade_to_legacy();
                }
                Err(e)
            }
        }
    }

    fn should_downgrade(&self) -> bool {
        self.mode == BackendMode::Auto
            && self.source.backend_name() == "cli"
            && self.consecutive_failures >= DOWNGRADE_THRESHOLD
    }

    fn should_supplement_cli_with_legacy(&self) -> bool {
        self.mode == BackendMode::Auto && self.source.backend_name() == "cli"
    }

    fn downgrade_to_legacy(&mut self) {
        self.source = Box::new(LegacySessionSource::new().expect("legacy ctor"));
        self.consecutive_failures = 0;
        self.telemetry_counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn recheck_and_maybe_swap(&mut self) {
        if self.mode != BackendMode::Auto {
            return;
        }
        let supports_cli = super::probe_claude_supports_agents_json();
        let want = if supports_cli { "cli" } else { "legacy" };
        if self.source.backend_name() != want {
            self.source = create_session_source();
            self.consecutive_failures = 0;
            self.telemetry_counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn backend_name(&self) -> &'static str {
        self.source.backend_name()
    }

    pub fn telemetry_counter(&self) -> Arc<AtomicU32> {
        self.telemetry_counter.clone()
    }
}

fn supplement_detected_sessions(base: &mut Vec<DetectedSession>, extras: Vec<DetectedSession>) {
    let mut seen_session_ids: HashSet<String> =
        base.iter().filter_map(|s| s.session_id.clone()).collect();
    let mut seen_pids: HashSet<u32> = base.iter().map(|s| s.pid).collect();

    for extra in extras {
        let duplicate_session = extra
            .session_id
            .as_ref()
            .is_some_and(|id| seen_session_ids.contains(id));
        if duplicate_session || seen_pids.contains(&extra.pid) {
            continue;
        }

        if let Some(id) = &extra.session_id {
            seen_session_ids.insert(id.clone());
        }
        seen_pids.insert(extra.pid);
        base.push(extra);
    }
}

fn merge_diagnostics(
    primary: DetectionDiagnostics,
    supplement: DetectionDiagnostics,
) -> DetectionDiagnostics {
    DetectionDiagnostics {
        claude_processes_found: primary
            .claude_processes_found
            .max(supplement.claude_processes_found),
        processes_with_cwd: primary
            .processes_with_cwd
            .max(supplement.processes_with_cwd),
        fda_likely_needed: primary.fda_likely_needed || supplement.fda_likely_needed,
    }
}

#[cfg(test)]
impl DetectorState {
    /// Test-only constructor that injects an explicit source + mode.
    pub fn for_test(source: Box<dyn SessionSource>, mode: BackendMode) -> Self {
        Self {
            source,
            consecutive_failures: 0,
            telemetry_counter: Arc::new(AtomicU32::new(0)),
            mode,
        }
    }

    /// Test-only helper to replace the underlying source mid-test (e.g. to
    /// schedule a fresh batch of failures via a new FakeSource instance).
    pub fn replace_source(&mut self, src: Box<dyn SessionSource>) {
        self.source = src;
        self.consecutive_failures = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct FakeSource {
        name: &'static str,
        fail_next: Cell<u32>,
    }

    impl FakeSource {
        fn new(name: &'static str, fails: u32) -> Self {
            Self {
                name,
                fail_next: Cell::new(fails),
            }
        }
    }

    impl SessionSource for FakeSource {
        fn detect(
            &mut self,
        ) -> Result<(Vec<DetectedSession>, DetectionDiagnostics), SessionDetectorError> {
            let n = self.fail_next.get();
            if n > 0 {
                self.fail_next.set(n - 1);
                return Err(SessionDetectorError::CliFailed("fake".into()));
            }
            Ok((Vec::new(), DetectionDiagnostics::default()))
        }
        fn backend_name(&self) -> &'static str {
            self.name
        }
    }

    #[test]
    fn detect_success_resets_counter() {
        let mut s = DetectorState::for_test(Box::new(FakeSource::new("cli", 0)), BackendMode::Auto);
        s.consecutive_failures = 3;
        let _ = s.detect().unwrap();
        assert_eq!(s.consecutive_failures, 0);
    }

    #[test]
    fn detect_failure_increments_counter() {
        let mut s = DetectorState::for_test(Box::new(FakeSource::new("cli", 1)), BackendMode::Auto);
        let _ = s.detect();
        assert_eq!(s.consecutive_failures, 1);
    }

    #[test]
    fn five_failures_in_auto_cli_mode_swap_to_legacy() {
        let mut s = DetectorState::for_test(Box::new(FakeSource::new("cli", 5)), BackendMode::Auto);
        for _ in 0..5 {
            let _ = s.detect();
        }
        assert_eq!(s.backend_name(), "legacy");
        assert_eq!(s.consecutive_failures, 0);
    }

    #[test]
    fn force_cli_mode_never_downgrades() {
        let mut s =
            DetectorState::for_test(Box::new(FakeSource::new("cli", 20)), BackendMode::ForceCli);
        for _ in 0..20 {
            let _ = s.detect();
        }
        assert_eq!(s.backend_name(), "cli");
    }

    #[test]
    fn legacy_backend_failures_do_not_swap() {
        let mut s =
            DetectorState::for_test(Box::new(FakeSource::new("legacy", 10)), BackendMode::Auto);
        for _ in 0..10 {
            let _ = s.detect();
        }
        assert_eq!(s.backend_name(), "legacy");
    }

    #[test]
    fn counter_resets_on_success_between_failures() {
        let mut s = DetectorState::for_test(Box::new(FakeSource::new("cli", 3)), BackendMode::Auto);
        for _ in 0..3 {
            let _ = s.detect();
        }
        let _ = s.detect();
        assert_eq!(s.consecutive_failures, 0);
        s.replace_source(Box::new(FakeSource::new("cli", 3)));
        for _ in 0..3 {
            let _ = s.detect();
        }
        assert_eq!(s.backend_name(), "cli");
    }

    #[test]
    fn recheck_no_swap_in_force_modes() {
        let mut s = DetectorState::for_test(
            Box::new(FakeSource::new("cli", 0)),
            BackendMode::ForceLegacy,
        );
        s.recheck_and_maybe_swap();
        assert_eq!(s.backend_name(), "cli");
    }

    #[test]
    fn supplement_appends_distinct_legacy_sessions() {
        let mut base = vec![DetectedSession::with_legacy_defaults(
            1,
            "/tmp/a".into(),
            "/tmp/a-project".into(),
            Some("sid-a".to_string()),
            "a".to_string(),
        )];
        let extras = vec![DetectedSession::with_legacy_defaults(
            2,
            "/tmp/b".into(),
            "/tmp/b-project".into(),
            Some("sid-b".to_string()),
            "b".to_string(),
        )];

        supplement_detected_sessions(&mut base, extras);

        assert_eq!(base.len(), 2);
        assert_eq!(base[1].pid, 2);
    }

    #[test]
    fn supplement_skips_duplicate_session_ids_and_pids() {
        let mut base = vec![DetectedSession::with_legacy_defaults(
            1,
            "/tmp/a".into(),
            "/tmp/a-project".into(),
            Some("sid-a".to_string()),
            "a".to_string(),
        )];
        let extras = vec![
            DetectedSession::with_legacy_defaults(
                2,
                "/tmp/a2".into(),
                "/tmp/a2-project".into(),
                Some("sid-a".to_string()),
                "a2".to_string(),
            ),
            DetectedSession::with_legacy_defaults(
                1,
                "/tmp/b".into(),
                "/tmp/b-project".into(),
                Some("sid-b".to_string()),
                "b".to_string(),
            ),
        ];

        supplement_detected_sessions(&mut base, extras);

        assert_eq!(base.len(), 1);
    }

    #[test]
    fn merge_diagnostics_keeps_legacy_process_counts() {
        let primary = DetectionDiagnostics::default();
        let supplement = DetectionDiagnostics {
            claude_processes_found: 3,
            processes_with_cwd: 2,
            fda_likely_needed: false,
        };

        let merged = merge_diagnostics(primary, supplement);

        assert_eq!(merged.claude_processes_found, 3);
        assert_eq!(merged.processes_with_cwd, 2);
        assert!(!merged.fda_likely_needed);
    }
}
