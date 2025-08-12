use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::{borrow::Cow, sync::Arc};

/// Unified progress reporting trait that supports deferred initialization and sub-operations
pub trait ProgressReporter: Send + Sync + Sized {
    /// Initialize the progress bar with a total count and message
    fn initialize(&self, total_items: u64);

    /// Progress the operation by one step
    fn progress(&self);

    /// Create a sub-operation under this reporter
    fn sub_progress(&self, name: Cow<'static, str>) -> Self;

    /// Finish this operation (called automatically on drop)
    fn finish(self) {
        drop(self)
    }
}

/// Simple progress reporter that does nothing (default)
pub struct NoOpProgressReporter;

impl ProgressReporter for NoOpProgressReporter {
    fn initialize(&self, _total_items: u64) {}
    fn progress(&self) {}
    fn sub_progress(&self, _name: Cow<'static, str>) -> Self {
        NoOpProgressReporter
    }
}

/// Indicatif-based progress reporter
pub struct IndicatifProgressBar {
    name: Cow<'static, str>,
    multi_progress: Option<MultiProgress>,
    progress_bar: Arc<std::sync::Mutex<Option<ProgressBar>>>,
}

impl IndicatifProgressBar {
    pub fn new(name: impl Into<Cow<'static, str>>, multi_progress: Option<MultiProgress>) -> Self {
        Self {
            name: name.into(),
            multi_progress,
            progress_bar: Arc::new(std::sync::Mutex::new(None)),
        }
    }
}

impl ProgressReporter for IndicatifProgressBar {
    fn initialize(&self, total_items: u64) {
        let mut pb_guard = self.progress_bar.lock().unwrap();
        if pb_guard.is_some() {
            return; // Already initialized
        }

        let pb = ProgressBar::new(total_items)
            .with_style(default_progress_style())
            .with_message(self.name.clone());

        if let Some(multi) = &self.multi_progress {
            multi.insert_from_back(2, pb.clone());
        }

        *pb_guard = Some(pb);
    }

    fn progress(&self) {
        if let Some(pb) = self.progress_bar.lock().unwrap().as_ref() {
            pb.inc(1);
        }
    }

    fn sub_progress(&self, name: Cow<'static, str>) -> Self {
        Self {
            name,
            multi_progress: self.multi_progress.clone(),
            progress_bar: Arc::new(std::sync::Mutex::new(None)),
        }
    }
}

impl Drop for IndicatifProgressBar {
    fn drop(&mut self) {
        if let Some(pb) = self.progress_bar.lock().unwrap().take() {
            pb.finish_and_clear();
            if let Some(multi) = &self.multi_progress {
                multi.remove(&pb);
            }
        }
    }
}

/// Text-based progress reporter
pub struct TextProgressBar<W: std::io::Write + Send + Sync + 'static> {
    name: Cow<'static, str>,
    writer: Arc<std::sync::Mutex<W>>,
}

impl<W: std::io::Write + Send + Sync + 'static> TextProgressBar<W> {
    pub fn new(name: impl Into<Cow<'static, str>>, writer: Arc<std::sync::Mutex<W>>) -> Self {
        Self {
            name: name.into(),
            writer,
        }
    }

    fn write_event(&self, message: &str) {
        if let Ok(mut writer) = self.writer.lock() {
            let _ = writeln!(writer, "{}", message);
            let _ = writer.flush();
        }
    }
}

impl<W: std::io::Write + Send + Sync + 'static> ProgressReporter for TextProgressBar<W> {
    fn initialize(&self, total_items: u64) {
        self.write_event(&format!(
            "Starting operation: {} ({} items)",
            self.name, total_items
        ));
    }

    fn progress(&self) {}

    fn sub_progress(&self, name: Cow<'static, str>) -> Self {
        TextProgressBar::new(name, self.writer.clone())
    }
}

impl<W: std::io::Write + Send + Sync + 'static> Drop for TextProgressBar<W> {
    fn drop(&mut self) {
        self.write_event(&format!("Completed operation {}", self.name));
    }
}

pub fn default_progress_style() -> ProgressStyle {
    ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({per_sec}, {eta}) {msg}")
        .unwrap()
        .progress_chars("#>-")
}
