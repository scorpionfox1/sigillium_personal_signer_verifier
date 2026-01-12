// src/security_log/store.rs

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::platform;

use super::model::{
    SecurityEvent, SecurityEventClass, LOAD_TAIL_LINES, LOG_BACKUP_NAME, LOG_FILE_NAME,
    MAX_LOG_BYTES, MAX_LOG_EVENTS,
};

pub struct SecurityLog {
    path: PathBuf,
    buf: VecDeque<SecurityEvent>,
    next_id: u64,
    best_effort_warn_pending: bool,
}

impl SecurityLog {
    pub fn init(app_data_dir: &Path) -> Result<Self, String> {
        let path = app_data_dir.join(LOG_FILE_NAME);
        fs::create_dir_all(app_data_dir).map_err(|e| format!("security log dir create: {e}"))?;

        let mut log = Self {
            path,
            buf: VecDeque::with_capacity(MAX_LOG_EVENTS),
            next_id: 1,
            best_effort_warn_pending: false,
        };

        log.load_tail_best_effort();
        log.next_id = log.compute_next_id();

        if let Some(fail) = platform::restrict_dir_perms_best_effort(app_data_dir) {
            log.record_best_effort(
                SecurityEventClass::BestEffortFailure,
                fail.kind,
                "security_log_init",
                fail.errno,
                fail.msg,
            );
        }

        if log.path.exists() {
            if let Some(fail) = platform::restrict_file_perms_best_effort(&log.path) {
                log.record_best_effort(
                    SecurityEventClass::BestEffortFailure,
                    fail.kind,
                    "security_log_init",
                    fail.errno,
                    fail.msg,
                );
            }
        }

        Ok(log)
    }

    pub fn clear_in_memory(&mut self) {
        self.buf.clear();
    }

    pub fn record_best_effort(
        &mut self,
        class: SecurityEventClass,
        kind: &str,
        context: &str,
        errno: Option<i32>,
        msg: &str,
    ) {
        let ev = SecurityEvent {
            id: self.alloc_id(),
            ts_ms: now_ms(),
            class,
            kind: kind.to_string(),
            os: current_os().to_string(),
            context: context.to_string(),
            errno,
            msg: msg.to_string(),
        };

        if self.buf.len() >= MAX_LOG_EVENTS {
            self.buf.pop_front();
        }
        self.buf.push_back(ev.clone());

        if matches!(class, SecurityEventClass::BestEffortFailure) {
            self.best_effort_warn_pending = true;
        }

        let _ = self.rotate_if_needed_best_effort();
        let _ = self.append_jsonl_best_effort(&ev);
        let _ = self.trim_security_log_to_n_events(MAX_LOG_EVENTS);
    }

    pub fn record_intentional(&mut self, kind: &str, context: &str, msg: &str) {
        self.record_best_effort(
            SecurityEventClass::IntentionalSecurityEvent,
            kind,
            context,
            None,
            msg,
        );
    }

    pub fn recent(&self) -> Vec<SecurityEvent> {
        self.buf.iter().cloned().collect()
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        id
    }

    fn compute_next_id(&self) -> u64 {
        self.buf
            .iter()
            .map(|e| e.id)
            .max()
            .unwrap_or(0)
            .saturating_add(1)
    }

    fn rotate_if_needed_best_effort(&self) -> Result<(), String> {
        let meta = match fs::metadata(&self.path) {
            Ok(m) => m,
            Err(_) => return Ok(()),
        };

        if meta.len() <= MAX_LOG_BYTES {
            return Ok(());
        }

        let backup = self.path.with_file_name(LOG_BACKUP_NAME);
        let _ = fs::remove_file(&backup);
        fs::rename(&self.path, &backup).map_err(|e| format!("security log rotate: {e}"))?;

        if let Some(parent) = self.path.parent() {
            if let Ok(dir) = OpenOptions::new().read(true).open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }

    fn append_jsonl_best_effort(&self, ev: &SecurityEvent) -> Result<(), String> {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| format!("security log open: {e}"))?;

        let _ = platform::restrict_file_perms_best_effort(&self.path);

        let line = serde_json::to_string(ev).map_err(|e| format!("security log json: {e}"))?;
        f.write_all(line.as_bytes())
            .and_then(|_| f.write_all(b"\n"))
            .map_err(|e| format!("security log write: {e}"))?;

        let _ = f.flush();
        let _ = f.sync_all();
        Ok(())
    }

    fn trim_security_log_to_n_events(&self, n: usize) -> Result<(), String> {
        if n == 0 {
            return Ok(());
        }

        let Ok(file) = File::open(&self.path) else {
            return Ok(());
        };
        let reader = BufReader::new(file);

        let mut tail: VecDeque<String> = VecDeque::with_capacity(n.min(LOAD_TAIL_LINES));
        let mut exceeded = false;

        for line in reader.lines().flatten() {
            if tail.len() >= n {
                tail.pop_front();
                exceeded = true;
            }
            tail.push_back(line);
        }

        if !exceeded {
            return Ok(());
        }

        let tmp = self.path.with_extension("jsonl.tmp");
        {
            let mut out = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&tmp)
                .map_err(|e| format!("security log trim open tmp: {e}"))?;

            for line in tail {
                out.write_all(line.as_bytes())
                    .and_then(|_| out.write_all(b"\n"))
                    .map_err(|e| format!("security log trim write tmp: {e}"))?;
            }

            let _ = out.flush();
            let _ = out.sync_all();
        }

        fs::rename(&tmp, &self.path).map_err(|e| format!("security log trim rename: {e}"))?;

        // Mirror the existing parent-dir sync pattern used in rotate.
        if let Some(parent) = self.path.parent() {
            if let Ok(dir) = OpenOptions::new().read(true).open(parent) {
                let _ = dir.sync_all();
            }
        }

        Ok(())
    }

    fn load_tail_best_effort(&mut self) {
        let Ok(file) = File::open(&self.path) else {
            return;
        };
        let reader = BufReader::new(file);

        let mut tail: VecDeque<String> = VecDeque::with_capacity(LOAD_TAIL_LINES);
        for line in reader.lines().flatten() {
            if tail.len() >= LOAD_TAIL_LINES {
                tail.pop_front();
            }
            tail.push_back(line);
        }

        for line in tail {
            if let Ok(ev) = serde_json::from_str::<SecurityEvent>(&line) {
                if self.buf.len() >= MAX_LOG_EVENTS {
                    self.buf.pop_front();
                }
                self.buf.push_back(ev);
            }
        }
    }

    pub fn take_best_effort_warn_pending(&mut self) -> bool {
        let was = self.best_effort_warn_pending;
        self.best_effort_warn_pending = false;
        was
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn current_os() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "linux"
    }
    #[cfg(target_os = "windows")]
    {
        "windows"
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        "other"
    }
}
