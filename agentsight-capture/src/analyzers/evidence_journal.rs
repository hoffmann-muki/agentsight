// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use crate::analyzers::{Analyzer, AnalyzerError};
use crate::event::Event;
use crate::runners::EventStream;
use async_trait::async_trait;
use futures::stream::StreamExt;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

const JOURNAL_SCHEMA: &str = "agentsight-evidence/v1";
const FLUSH_INTERVAL: u64 = 128;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EvidenceStats {
    pub events_written: u64,
    pub write_errors: u64,
    pub first_capture_timestamp_ms: Option<u64>,
    pub last_capture_timestamp_ms: Option<u64>,
    pub events_by_source: BTreeMap<String, u64>,
    pub diagnostics_by_type: BTreeMap<String, u64>,
}

impl EvidenceStats {
    fn observe(&mut self, event: &Event, capture_timestamp_ms: u64) {
        self.events_written += 1;
        self.first_capture_timestamp_ms
            .get_or_insert(capture_timestamp_ms);
        self.last_capture_timestamp_ms = Some(capture_timestamp_ms);
        *self
            .events_by_source
            .entry(event.source.clone())
            .or_default() += 1;
        if event.source == "diagnostic"
            && let Some(diagnostic_type) = event.data.get("type").and_then(|value| value.as_str())
        {
            *self
                .diagnostics_by_type
                .entry(diagnostic_type.to_string())
                .or_default() += 1;
        }
    }
}

impl Default for EvidenceStats {
    fn default() -> Self {
        Self {
            events_written: 0,
            write_errors: 0,
            first_capture_timestamp_ms: None,
            last_capture_timestamp_ms: None,
            events_by_source: BTreeMap::new(),
            diagnostics_by_type: BTreeMap::new(),
        }
    }
}

#[derive(Clone)]
pub struct EvidenceStatsHandle {
    stats: Arc<Mutex<EvidenceStats>>,
}

impl EvidenceStatsHandle {
    pub fn snapshot(&self) -> EvidenceStats {
        self.stats
            .lock()
            .map(|stats| stats.clone())
            .unwrap_or_else(|_| EvidenceStats {
                write_errors: 1,
                ..EvidenceStats::default()
            })
    }
}

pub struct EvidenceJournal {
    writer: Arc<Mutex<JournalWriter>>,
    stats: EvidenceStatsHandle,
    profile_id: String,
    scope_id: String,
}

enum JournalWriter {
    Plain(BufWriter<File>),
    Zstd(Option<zstd::stream::write::Encoder<'static, BufWriter<File>>>),
}

impl JournalWriter {
    fn open(path: &Path) -> Result<Self, std::io::Error> {
        let file = File::options()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)?;
        if path.extension().and_then(|extension| extension.to_str()) == Some("zst") {
            return zstd::stream::write::Encoder::new(BufWriter::new(file), 3)
                .map(|encoder| Self::Zstd(Some(encoder)));
        }
        Ok(Self::Plain(BufWriter::new(file)))
    }

    fn finish(&mut self) -> Result<(), std::io::Error> {
        match self {
            Self::Plain(writer) => writer.flush(),
            Self::Zstd(encoder) => {
                let Some(encoder) = encoder.take() else {
                    return Ok(());
                };
                encoder.finish()?.flush()
            }
        }
    }
}

impl Write for JournalWriter {
    fn write(&mut self, buffer: &[u8]) -> Result<usize, std::io::Error> {
        match self {
            Self::Plain(writer) => writer.write(buffer),
            Self::Zstd(Some(encoder)) => encoder.write(buffer),
            Self::Zstd(None) => Err(std::io::Error::other("evidence journal is closed")),
        }
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        match self {
            Self::Plain(writer) => writer.flush(),
            Self::Zstd(Some(encoder)) => encoder.flush(),
            Self::Zstd(None) => Ok(()),
        }
    }
}

#[derive(Serialize)]
struct EvidenceRecord<'a> {
    schema: &'static str,
    sequence: u64,
    profile_id: &'a str,
    scope_id: &'a str,
    source_timestamp_ms: u64,
    capture_timestamp_ms: u64,
    source: &'a str,
    pid: u32,
    comm: &'a str,
    data: &'a serde_json::Value,
}

impl EvidenceJournal {
    pub fn open(
        path: impl AsRef<Path>,
        profile_id: impl Into<String>,
        scope_id: impl Into<String>,
    ) -> Result<(Self, EvidenceStatsHandle), std::io::Error> {
        let stats = EvidenceStatsHandle {
            stats: Arc::new(Mutex::new(EvidenceStats::default())),
        };
        Ok((
            Self {
                writer: Arc::new(Mutex::new(JournalWriter::open(path.as_ref())?)),
                stats: stats.clone(),
                profile_id: profile_id.into(),
                scope_id: scope_id.into(),
            },
            stats,
        ))
    }
}

#[async_trait]
impl Analyzer for EvidenceJournal {
    async fn process(&mut self, stream: EventStream) -> Result<EventStream, AnalyzerError> {
        let writer = self.writer.clone();
        let stats = self.stats.clone();
        let profile_id = self.profile_id.clone();
        let scope_id = self.scope_id.clone();
        let processed = stream.map(move |event| {
            let capture_timestamp_ms = current_timestamp_ms();
            let sequence = stats
                .stats
                .lock()
                .map(|stats| stats.events_written + 1)
                .unwrap_or_default();
            let record = EvidenceRecord {
                schema: JOURNAL_SCHEMA,
                sequence,
                profile_id: &profile_id,
                scope_id: &scope_id,
                source_timestamp_ms: event.timestamp,
                capture_timestamp_ms,
                source: &event.source,
                pid: event.pid,
                comm: &event.comm,
                data: &event.data,
            };
            let write_result = writer.lock().map_err(|_| ()).and_then(|mut writer| {
                serde_json::to_writer(&mut *writer, &record).map_err(|_| ())?;
                writer.write_all(b"\n").map_err(|_| ())?;
                if sequence.is_multiple_of(FLUSH_INTERVAL) {
                    writer.flush().map_err(|_| ())?;
                }
                Ok(())
            });
            if let Ok(mut stats) = stats.stats.lock() {
                if write_result.is_ok() {
                    stats.observe(&event, capture_timestamp_ms);
                } else {
                    stats.write_errors += 1;
                }
            }
            event
        });
        Ok(Box::pin(processed))
    }
}

impl Drop for EvidenceJournal {
    fn drop(&mut self) {
        if Arc::strong_count(&self.writer) == 1
            && let Ok(mut writer) = self.writer.lock()
            && writer.finish().is_err()
            && let Ok(mut stats) = self.stats.stats.lock()
        {
            stats.write_errors += 1;
        }
    }
}

fn current_timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runners::{FakeRunner, Runner};
    use futures::stream::StreamExt;

    #[tokio::test]
    async fn journal_preserves_events_with_source_and_capture_order() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("events.jsonl");
        let (journal, stats) =
            EvidenceJournal::open(&path, "profile-1", "host").expect("open journal");
        let mut runner = FakeRunner::new()
            .event_count(2)
            .add_analyzer(Box::new(journal));

        let events: Vec<_> = runner.run().await.unwrap().collect().await;
        drop(runner);

        let records: Vec<serde_json::Value> = std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.len(), events.len());
        assert_eq!(records[0]["schema"], JOURNAL_SCHEMA);
        assert_eq!(records[0]["sequence"], 1);
        assert_eq!(records[0]["profile_id"], "profile-1");
        assert_eq!(records[0]["scope_id"], "host");
        assert!(records[0]["capture_timestamp_ms"].as_u64().unwrap() > 0);
        assert_eq!(stats.snapshot().events_written, events.len() as u64);
        assert_eq!(stats.snapshot().write_errors, 0);
    }

    #[tokio::test]
    async fn zstd_journal_is_replayable() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("events.jsonl.zst");
        let (journal, _) =
            EvidenceJournal::open(&path, "profile-1", "container").expect("open journal");
        let mut runner = FakeRunner::new()
            .event_count(1)
            .add_analyzer(Box::new(journal));

        let _: Vec<_> = runner.run().await.unwrap().collect().await;
        drop(runner);

        let decoded = zstd::stream::decode_all(File::open(path).unwrap()).unwrap();
        let record: serde_json::Value =
            serde_json::from_slice(decoded.split(|byte| *byte == b'\n').next().unwrap()).unwrap();
        assert_eq!(record["schema"], JOURNAL_SCHEMA);
        assert_eq!(record["scope_id"], "container");
    }
}
