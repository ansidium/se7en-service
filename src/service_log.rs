#![forbid(unsafe_code)]

//! Bounded diagnostic log of the service in its protected data directory.
//!
//! One line per event, newest last. When the file would exceed its bound it is renamed to
//! `service-v1.log.1`, replacing the previous rotation, so the log never holds more than twice the
//! bound. Logging is best-effort: a failure to write never changes the outcome of an operation.
//! Lines contain stable error codes, details, Win32 statuses and job IDs, but no request payloads.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::MaintenanceError;

pub const SERVICE_LOG_FILE: &str = "service-v1.log";
const ROTATED_SUFFIX: &str = ".1";
const DEFAULT_MAX_BYTES: u64 = 256 * 1024;
const MAX_FIELD_CHARS: usize = 512;

pub struct ServiceLog {
    path: PathBuf,
    max_bytes: u64,
}

impl ServiceLog {
    #[must_use]
    pub fn in_directory(directory: &Path) -> Self {
        Self::with_limit(directory, DEFAULT_MAX_BYTES)
    }

    #[must_use]
    pub fn with_limit(directory: &Path, max_bytes: u64) -> Self {
        Self {
            path: directory.join(SERVICE_LOG_FILE),
            max_bytes,
        }
    }

    /// Appends `event` with free-form `detail`.
    pub fn record(&self, event: &str, detail: &str) {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        let line = format_line(seconds, event, detail);
        let _ = self.append(&line);
    }

    /// Appends `event` with the code, detail and platform status of `error`.
    pub fn record_error(&self, event: &str, error: &MaintenanceError) {
        self.record(event, &error.to_string());
    }

    fn append(&self, line: &str) -> std::io::Result<()> {
        let length = u64::try_from(line.len()).unwrap_or(u64::MAX);
        let current = fs::metadata(&self.path).map_or(0, |metadata| metadata.len());
        if current > 0 && current.saturating_add(length) > self.max_bytes {
            let mut rotated = self.path.clone().into_os_string();
            rotated.push(ROTATED_SUFFIX);
            fs::rename(&self.path, rotated)?;
        }
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?
            .write_all(line.as_bytes())
    }
}

/// Keeps a field on one line and within a fixed length.
fn sanitize(field: &str) -> String {
    field
        .chars()
        .take(MAX_FIELD_CHARS)
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

/// `YYYY-MM-DDThh:mm:ssZ event detail` with a trailing newline.
#[must_use]
pub fn format_line(unix_seconds: u64, event: &str, detail: &str) -> String {
    let days = unix_seconds / 86_400;
    let time = unix_seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z {} {}\n",
        time / 3_600,
        time % 3_600 / 60,
        time % 60,
        sanitize(event),
        sanitize(detail)
    )
}

/// Gregorian date of a day count since 1970-01-01 (H. Hinnant's `civil_from_days`).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn create() -> Self {
            let path = std::env::temp_dir().join(format!(
                "seven-maintenance-log-{}-{}",
                std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn lines_have_a_utc_timestamp_and_stay_on_one_line() {
        assert_eq!(
            format_line(0, "service-start", "version 1.0.3"),
            "1970-01-01T00:00:00Z service-start version 1.0.3\n"
        );
        assert_eq!(
            format_line(951_782_400 + 3_661, "leap", "day"),
            "2000-02-29T01:01:01Z leap day\n"
        );
        assert_eq!(
            format_line(1_791_590_399, "end", "of 2026"),
            "2026-10-09T23:59:59Z end of 2026\n"
        );
        let line = format_line(0, "event\nforged", "detail\r\n2026-01-01T00:00:00Z fake");
        assert_eq!(line.matches('\n').count(), 1);
        assert!(line.ends_with('\n'));
        let long = format_line(0, "event", &"x".repeat(10_000));
        assert!(long.len() < MAX_FIELD_CHARS + 64);
    }

    #[test]
    fn the_log_is_bounded_by_one_rotation() {
        let directory = TempDirectory::create();
        let log = ServiceLog::with_limit(&directory.0, 200);
        for index in 0..50 {
            log.record("request-failed", &format!("E_SERVICE_BUSY attempt {index}"));
        }
        let current = fs::read_to_string(directory.0.join(SERVICE_LOG_FILE)).unwrap();
        let rotated = fs::read_to_string(
            directory
                .0
                .join(format!("{SERVICE_LOG_FILE}{ROTATED_SUFFIX}")),
        )
        .unwrap();
        assert!(current.len() <= 200 && rotated.len() <= 200);
        assert!(current.contains("attempt 49"));
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 2);
    }

    #[test]
    fn a_missing_directory_does_not_fail_the_caller() {
        let directory = TempDirectory::create();
        let log = ServiceLog::in_directory(&directory.0.join("missing"));
        log.record("service-start", "no directory");
        assert!(!directory.0.join("missing").exists());
    }
}
