use std::io;
use std::sync::mpsc::{channel, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap, BorderType},
    Frame, Terminal,
};

use crate::device::{list_devices, Device, StorageDevice};
use crate::errors::{RecoveryError, Result};
use crate::filesystem::{detect_filesystem, DeletedFile, FilesystemParser, RecoveryStatus};
use crate::scanner::{carve_device, CarvedFile, ScanProgress};
use crate::signatures::get_default_signatures;
use crate::utils;

pub mod widgets;
use widgets::{generate_dynamic_sector_map, generate_hex_dump};

// Professional Slate-and-Cyan Theme Color Palette
const BG_DARK: Color = Color::Reset;                  // Respect user's terminal background translucency
const FG_LIGHT: Color = Color::Rgb(150, 170, 190);    // Soft Slate Blue for borders and labels
const FG_CREAM: Color = Color::Rgb(220, 225, 230);    // Soft Off-White for main values/content
const ACCENT_GOLD: Color = Color::Rgb(60, 90, 110);    // Muted Slate Blue for selection/headers
const ERR_TERRACOTTA: Color = Color::Rgb(190, 110, 110); // Soft rose/terracotta red for warnings/errors
const OK_SAGE: Color = Color::Rgb(120, 170, 120);      // Soft sage green for success/recovered green

/// TUI Screen state indicator
#[derive(Clone, PartialEq)]
pub enum TuiScreen {
    DeviceSelect,
    Scanning,
    Results,
}

/// Scanning Modes
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    Quick, // Filesystem metadata parsing
    Deep,  // Raw signature carving
}

/// Messages sent from background threads to the main TUI event loop
pub enum TuiThreadUpdate {
    QuickScanDone(Result<Vec<DeletedFile>>),
    DeepCarveProgress(ScanProgress),
}

/// Main Application state for the TUI
pub struct TuiApp {
    pub screen: TuiScreen,
    
    // Device Select State
    pub devices: Vec<StorageDevice>,
    pub device_list_state: ListState,
    pub scan_mode: ScanMode,
    
    // Scanning State
    pub active_device: Option<StorageDevice>,
    pub scanned_sectors: u64,
    pub total_sectors: u64,
    pub scan_speed: f64,
    pub found_count: u32,
    pub file_offsets: Vec<u64>,
    pub error_offsets: Vec<u64>,
    pub rx: Option<Receiver<TuiThreadUpdate>>,
    pub scan_start_time: Option<Instant>,
    
    // Results State
    pub deleted_files: Vec<DeletedFile>,
    pub carved_files: Vec<CarvedFile>,
    pub results_list_state: ListState,
    pub hex_data: Vec<u8>,
    
    // Dialog / Prompt States
    pub show_prompt: bool,
    pub prompt_title: String,
    pub prompt_value: String,
    pub prompt_is_all: bool,
    pub alert_msg: Option<String>,

    // Search States
    pub search_query: String,
    pub show_search_prompt: bool,

    // Phase 2 Resolving State
    pub phase2_resolving: bool,
    pub phase2_current: u64,
    pub phase2_total: u64,

    // Android Acquisition State
    pub android_acquisition_path: Option<String>,
}

impl Default for TuiApp {
    fn default() -> Self {
        Self::new()
    }
}

impl TuiApp {
    pub fn new() -> Self {
        let mut device_list_state = ListState::default();
        device_list_state.select(Some(0));

        let mut results_list_state = ListState::default();
        results_list_state.select(Some(0));

        Self {
            screen: TuiScreen::DeviceSelect,
            devices: Vec::new(),
            device_list_state,
            scan_mode: ScanMode::Quick,
            active_device: None,
            scanned_sectors: 0,
            total_sectors: 0,
            scan_speed: 0.0,
            found_count: 0,
            file_offsets: Vec::new(),
            error_offsets: Vec::new(),
            rx: None,
            scan_start_time: None,
            deleted_files: Vec::new(),
            carved_files: Vec::new(),
            results_list_state,
            hex_data: Vec::new(),
            show_prompt: false,
            prompt_title: String::new(),
            prompt_value: String::new(),
            prompt_is_all: false,
            alert_msg: None,
            search_query: String::new(),
            show_search_prompt: false,
            phase2_resolving: false,
            phase2_current: 0,
            phase2_total: 0,
            android_acquisition_path: None,
        }
    }

    /// Loads the hex preview of the currently selected file.
    pub fn load_hex_preview(&mut self) {
        if self.screen != TuiScreen::Results {
            return;
        }

        self.hex_data.clear();
        let device_path = match &self.active_device {
            Some(d) => &d.path,
            None => return,
        };

        let dev = match Device::open(device_path) {
            Ok(d) => d,
            Err(_) => return,
        };

        match self.scan_mode {
            ScanMode::Quick => {
                let idx = match self.results_list_state.selected() {
                    Some(i) => i,
                    None => return,
                };
                let filtered = self.get_filtered_deleted_files();
                if idx < filtered.len() {
                    let file = &filtered[idx];
                    if let Ok(parser) = detect_filesystem(&dev) {
                        if let Ok(data) = read_file_preview(&*parser, &dev, file, 512) {
                            self.hex_data = data;
                        }
                    }
                }
            }
            ScanMode::Deep => {
                let idx = match self.results_list_state.selected() {
                    Some(i) => i,
                    None => return,
                };
                let filtered = self.get_filtered_carved_files();
                if idx < filtered.len() {
                    let file = &filtered[idx];
                    let to_read = std::cmp::min(512, file.size) as usize;
                    let mut buf = vec![0u8; to_read];
                    if dev.read_at(file.offset, &mut buf).is_ok() {
                        self.hex_data = buf;
                    }
                }
            }
        }
    }

    /// Runs a single file recovery based on selection.
    pub fn perform_single_recovery(&self, file_idx: usize, output_dir: &str) -> std::result::Result<String, String> {
        let dev_device = match &self.active_device {
            Some(d) => d,
            None => return Err("No active device".to_string()),
        };
        let dev = Device::open(&dev_device.path).map_err(|e| format!("Failed to open device: {}", e))?;
        
        match self.scan_mode {
            ScanMode::Quick => {
                let filtered = self.get_filtered_deleted_files();
                if file_idx >= filtered.len() {
                    return Err("Invalid file selection".to_string());
                }
                let file = &filtered[file_idx];
                let parser = detect_filesystem(&dev).map_err(|e| format!("Failed to detect filesystem: {}", e))?;
                crate::recovery::recover_file(&dev, &*parser, file, output_dir)
                    .map_err(|e| format!("Recovery failed: {}", e))?;
                Ok(format!("File '{}' successfully recovered to '{}'", file.name, output_dir))
            }
            ScanMode::Deep => {
                let filtered = self.get_filtered_carved_files();
                if file_idx >= filtered.len() {
                    return Err("Invalid file selection".to_string());
                }
                let file = &filtered[file_idx];
                crate::recovery::write_carved_files(&dev, std::slice::from_ref(file), output_dir)
                    .map_err(|e| format!("Recovery failed: {}", e))?;
                Ok(format!("Carved file ID {} successfully saved to '{}'", file.id, output_dir))
            }
        }
    }

    /// Runs recovery for all found items.
    pub fn perform_all_recovery(&self, output_dir: &str) -> std::result::Result<String, String> {
        let dev_device = match &self.active_device {
            Some(d) => d,
            None => return Err("No active device".to_string()),
        };
        let dev = Device::open(&dev_device.path).map_err(|e| format!("Failed to open device: {}", e))?;
        
        match self.scan_mode {
            ScanMode::Quick => {
                let filtered = self.get_filtered_deleted_files();
                if filtered.is_empty() {
                    return Err("No files to recover".to_string());
                }
                let parser = detect_filesystem(&dev).map_err(|e| format!("Failed to detect filesystem: {}", e))?;
                let mut count = 0;
                for file in &filtered {
                    if crate::recovery::recover_file(&dev, &*parser, file, output_dir).is_ok() {
                        count += 1;
                    }
                }
                Ok(format!("Recovered {}/{} files to '{}'", count, filtered.len(), output_dir))
            }
            ScanMode::Deep => {
                let filtered = self.get_filtered_carved_files();
                if filtered.is_empty() {
                    return Err("No files to recover".to_string());
                }
                crate::recovery::write_carved_files(&dev, &filtered, output_dir)
                    .map_err(|e| format!("Recovery failed: {}", e))?;
                Ok(format!("Successfully carved all {} files to '{}'", filtered.len(), output_dir))
            }
        }
    }

    pub fn get_filtered_deleted_files(&self) -> Vec<DeletedFile> {
        if self.search_query.is_empty() {
            self.deleted_files.clone()
        } else {
            let q = self.search_query.trim().to_lowercase();
            let q_clean = if q.starts_with('.') { &q[1..] } else { &q };
            self.deleted_files
                .iter()
                .filter(|file| {
                    let name_lower = file.name.to_lowercase();
                    name_lower.contains(&q) || name_lower.contains(q_clean)
                })
                .cloned()
                .collect()
        }
    }

    pub fn get_filtered_carved_files(&self) -> Vec<CarvedFile> {
        if self.search_query.is_empty() {
            self.carved_files.clone()
        } else {
            let q = self.search_query.trim().to_lowercase();
            let q_clean = if q.starts_with('.') { &q[1..] } else { &q };
            self.carved_files
                .iter()
                .filter(|file| {
                    file.signature.extension.to_lowercase().contains(q_clean)
                })
                .cloned()
                .collect()
        }
    }

}

/// Helper function to preview file contents up to a limit using the filesystem parser.
pub fn read_file_preview(
    parser: &dyn FilesystemParser,
    device: &Device,
    file: &DeletedFile,
    limit: usize,
) -> Result<Vec<u8>> {
    if file.size <= limit as u64 {
        return parser.read_file(device, file);
    }
    let mut dummy_file = file.clone();
    dummy_file.size = limit as u64;
    parser.read_file(device, &dummy_file)
}

/// Launches the interactive terminal user interface.
pub fn run_tui() -> Result<()> {
    enable_raw_mode().map_err(|e| RecoveryError::General(e.to_string()))?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).map_err(|e| RecoveryError::General(e.to_string()))?;
    
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(|e| RecoveryError::General(e.to_string()))?;

    // Setup global panic hook to restore terminal state if panic occurs
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        original_hook(panic_info);
    }));

    let mut app = TuiApp::new();
    app.devices = list_devices().unwrap_or_default();

    let result = run_app(&mut terminal, &mut app);

    // Restore terminal
    disable_raw_mode().map_err(|e| RecoveryError::General(e.to_string()))?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen).map_err(|e| RecoveryError::General(e.to_string()))?;
    terminal.show_cursor().map_err(|e| RecoveryError::General(e.to_string()))?;

    result
}

fn run_app<B: ratatui::backend::Backend>(terminal: &mut Terminal<B>, app: &mut TuiApp) -> Result<()> {
    loop {
        if let Some(path) = app.android_acquisition_path.take() {
            let _ = disable_raw_mode();
            let _ = execute!(io::stdout(), LeaveAlternateScreen);
            let _ = terminal.show_cursor();

            println!("\x1b[36m");
            println!("============================================================");
            println!("           ANDROID DEVICE ACQUISITION DASHBOARD");
            println!("============================================================\x1b[0m");

            if let Err(e) = crate::android::acquire_device(None, std::path::Path::new(&path), false, "sha256") {
                println!("\n\x1b[31mAcquisition Error: {}\x1b[0m", e);
            }

            println!("\nPress [ENTER] to return to Recover Droid dashboard...");
            let mut temp = String::new();
            let _ = std::io::stdin().read_line(&mut temp);

            let _ = enable_raw_mode();
            let _ = execute!(io::stdout(), EnterAlternateScreen);
            let _ = terminal.clear();
        }

        // Draw Frame
        terminal.draw(|f| draw_ui(f, app)).map_err(|e| RecoveryError::General(e.to_string()))?;



        // Background Thread Update Polling
        if app.screen == TuiScreen::Scanning {
            if let Some(rx) = app.rx.take() {
                let mut updates = Vec::new();
                while let Ok(update) = rx.try_recv() {
                    updates.push(update);
                }
                app.rx = Some(rx);

                for update in updates {
                    match update {
                        TuiThreadUpdate::QuickScanDone(res) => {
                            match res {
                                Ok(files) => {
                                    app.deleted_files = files;
                                    app.screen = TuiScreen::Results;
                                    app.results_list_state.select(Some(0));
                                    app.load_hex_preview();
                                }
                                Err(e) => {
                                    app.screen = TuiScreen::DeviceSelect;
                                    app.alert_msg = Some(format!("Error: {}", e));
                                }
                            }
                        }
                        TuiThreadUpdate::DeepCarveProgress(progress) => {
                            match progress {
                                ScanProgress::Started { total_sectors } => {
                                    app.total_sectors = total_sectors;
                                    app.phase2_resolving = false;
                                    app.phase2_current = 0;
                                    app.phase2_total = 0;
                                }
                                ScanProgress::Update { current_sector, speed, recovered_count, new_files } => {
                                    app.scanned_sectors = current_sector;
                                    app.scan_speed = speed;
                                    app.found_count = recovered_count;
                                    for file in new_files {
                                        app.file_offsets.push(file.offset);
                                    }
                                }
                                ScanProgress::ResolvingProgress { current, total } => {
                                    app.phase2_resolving = true;
                                    app.phase2_current = current;
                                    app.phase2_total = total;
                                }
                                ScanProgress::Finished(files) => {
                                    app.carved_files = files;
                                    app.phase2_resolving = false;
                                    app.screen = TuiScreen::Results;
                                    app.results_list_state.select(Some(0));
                                    app.load_hex_preview();
                                }
                            }
                        }
                    }
                }
            }
        }

        // Input Event Polling
        if event::poll(Duration::from_millis(50)).map_err(|e| RecoveryError::General(e.to_string()))? {
            if let Event::Key(key) = event::read().map_err(|e| RecoveryError::General(e.to_string()))? {
                if key.kind == KeyEventKind::Press && handle_input(key, app) {
                    break;
                }
            }
        }
    }
    Ok(())
}

fn handle_input(key: KeyEvent, app: &mut TuiApp) -> bool {
    // 1. Alert Modal Override
    if app.alert_msg.is_some() {
        app.alert_msg = None;
        return false;
    }

    // 2. Prompt Input Dialog Mode
    if app.show_prompt {
        match key.code {
            KeyCode::Enter => {
                let out_dir = if app.prompt_value.trim().is_empty() {
                    "recovered_files"
                } else {
                    app.prompt_value.trim()
                };

                if app.prompt_title == "Acquire Android Device" {
                    app.android_acquisition_path = Some(out_dir.to_string());
                } else {
                    let res = if app.prompt_is_all {
                        app.perform_all_recovery(out_dir)
                    } else {
                        let sel = app.results_list_state.selected().unwrap_or(0);
                        app.perform_single_recovery(sel, out_dir)
                    };

                    match res {
                        Ok(msg) => app.alert_msg = Some(msg),
                        Err(err) => app.alert_msg = Some(format!("Error: {}", err)),
                    }
                }

                app.show_prompt = false;
            }
            KeyCode::Esc => {
                app.show_prompt = false;
            }
            KeyCode::Backspace => {
                app.prompt_value.pop();
            }
            KeyCode::Char(c) => {
                app.prompt_value.push(c);
            }
            _ => {}
        }
        return false;
    }

    // 2b. Search Input Dialog Mode
    if app.show_search_prompt {
        match key.code {
            KeyCode::Enter => {
                app.show_search_prompt = false;
                app.results_list_state.select(Some(0));
                app.load_hex_preview();
            }
            KeyCode::Esc => {
                app.show_search_prompt = false;
            }
            KeyCode::Backspace => {
                app.search_query.pop();
                app.results_list_state.select(Some(0));
                app.load_hex_preview();
            }
            KeyCode::Char(c) => {
                app.search_query.push(c);
                app.results_list_state.select(Some(0));
                app.load_hex_preview();
            }
            _ => {}
        }
        return false;
    }

    // 3. Normal View Mode Input Handlers
    match app.screen {
        TuiScreen::DeviceSelect => match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return true,
            KeyCode::Up | KeyCode::Char('k') | KeyCode::Char('w') => {
                let sel = app.device_list_state.selected().unwrap_or(0);
                if sel > 0 {
                    app.device_list_state.select(Some(sel - 1));
                }
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Char('s') => {
                let sel = app.device_list_state.selected().unwrap_or(0);
                if !app.devices.is_empty() && sel < app.devices.len() - 1 {
                    app.device_list_state.select(Some(sel + 1));
                }
            }
            KeyCode::Tab => {
                app.scan_mode = match app.scan_mode {
                    ScanMode::Quick => ScanMode::Deep,
                    ScanMode::Deep => ScanMode::Quick,
                };
            }
            KeyCode::Char('a') | KeyCode::Char('A') => {
                match crate::android::list_android_devices() {
                    Ok(devices) => {
                        if devices.is_empty() {
                            app.alert_msg = Some(
                                "No connected Android devices found.\n\n\
                                 Please connect a device via USB, enable USB Debugging in Developer Options, \n\
                                 and authorize this computer."
                                    .to_string(),
                            );
                        } else {
                            app.prompt_title = "Acquire Android Device".to_string();
                            app.prompt_value = "android_acquisition".to_string();
                            app.prompt_is_all = false;
                            app.show_prompt = true;
                        }
                    }
                    Err(e) => {
                        app.alert_msg = Some(format!(
                            "Could not check connected Android devices:\n{}",
                            e
                        ));
                    }
                }
            }
            KeyCode::Enter => {
                let sel = app.device_list_state.selected().unwrap_or(0);
                if sel < app.devices.len() {
                    let dev = app.devices[sel].clone();
                    app.active_device = Some(dev.clone());
                    app.scanned_sectors = 0;
                    app.total_sectors = dev.size / dev.sector_size as u64;
                    app.scan_speed = 0.0;
                    app.found_count = 0;
                    app.file_offsets.clear();
                    app.error_offsets.clear();
                    app.scan_start_time = Some(Instant::now());
                    
                    let (tx, rx) = channel();
                    app.rx = Some(rx);
                    app.screen = TuiScreen::Scanning;

                    let dev_path = dev.path.clone();
                    let scan_mode = app.scan_mode;

                    match scan_mode {
                        ScanMode::Quick => {
                            thread::spawn(move || {
                                let run = || -> Result<Vec<DeletedFile>> {
                                    let device = Device::open(&dev_path)?;
                                    let parser = detect_filesystem(&device)?;
                                    parser.scan_deleted(&device)
                                };
                                let _ = tx.send(TuiThreadUpdate::QuickScanDone(run()));
                            });
                        }
                        ScanMode::Deep => {
                            thread::spawn(move || {
                                let (prog_tx, prog_rx) = channel();
                                let tx_clone = tx.clone();
                                
                                thread::spawn(move || {
                                    while let Ok(msg) = prog_rx.recv() {
                                        let _ = tx_clone.send(TuiThreadUpdate::DeepCarveProgress(msg));
                                    }
                                });

                                if let Ok(device) = Device::open(&dev_path) {
                                    let sigs = get_default_signatures();
                                    let _ = carve_device(&device, &sigs, Some(&prog_tx));
                                }
                            });
                        }
                    }
                }
            }
            _ => {}
        },
        TuiScreen::Scanning => if key.code == KeyCode::Esc {
            // Abort scan, clear background channels, go back
            app.rx = None;
            app.screen = TuiScreen::DeviceSelect;
        },
        TuiScreen::Results => match key.code {
            KeyCode::Char('q') | KeyCode::Esc => {
                app.screen = TuiScreen::DeviceSelect;
                app.search_query.clear();
            }
            KeyCode::Up | KeyCode::Char('k') | KeyCode::Char('w') => {
                let sel = app.results_list_state.selected().unwrap_or(0);
                if sel > 0 {
                    app.results_list_state.select(Some(sel - 1));
                    app.load_hex_preview();
                }
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Char('s') => {
                let sel = app.results_list_state.selected().unwrap_or(0);
                let len = match app.scan_mode {
                    ScanMode::Quick => app.get_filtered_deleted_files().len(),
                    ScanMode::Deep => app.get_filtered_carved_files().len(),
                };
                if len > 0 && sel < len - 1 {
                    app.results_list_state.select(Some(sel + 1));
                    app.load_hex_preview();
                }
            }
            KeyCode::PageUp => {
                let sel = app.results_list_state.selected().unwrap_or(0);
                let new_sel = sel.saturating_sub(10);
                app.results_list_state.select(Some(new_sel));
                app.load_hex_preview();
            }
            KeyCode::PageDown => {
                let sel = app.results_list_state.selected().unwrap_or(0);
                let len = match app.scan_mode {
                    ScanMode::Quick => app.get_filtered_deleted_files().len(),
                    ScanMode::Deep => app.get_filtered_carved_files().len(),
                };
                if len > 0 {
                    let new_sel = std::cmp::min(sel + 10, len - 1);
                    app.results_list_state.select(Some(new_sel));
                    app.load_hex_preview();
                }
            }
            KeyCode::Char('/') => {
                app.show_search_prompt = true;
            }
            KeyCode::Char('c') | KeyCode::Char('C') => {
                if !app.search_query.is_empty() {
                    app.search_query.clear();
                    app.results_list_state.select(Some(0));
                    app.load_hex_preview();
                }
            }
            KeyCode::Char('r') => {
                app.prompt_title = "Recover Selected File".to_string();
                app.prompt_value = "recovered_files".to_string();
                app.prompt_is_all = false;
                app.show_prompt = true;
            }
            KeyCode::Char('a') => {
                app.prompt_title = "Recover All Recoverable Files".to_string();
                app.prompt_value = "recovered_files".to_string();
                app.prompt_is_all = true;
                app.show_prompt = true;
            }
            _ => {}
        },
    }
    false
}

fn draw_ui(f: &mut Frame, app: &mut TuiApp) {
    let size = f.size();
    
    // Draw solid espresso dark brown background
    let bg_block = Block::default().style(Style::default().bg(BG_DARK));
    f.render_widget(bg_block, size);
    
    // Core Layout (Header, Main, Footer)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(size);

    // 1. Draw Title Bar Header
    let title = Paragraph::new(" RECOVER DROID - Interactive Forensic Data Recovery Utility ")
        .style(Style::default().fg(FG_CREAM).bg(ACCENT_GOLD).add_modifier(Modifier::BOLD))
        .alignment(ratatui::layout::Alignment::Center);
    f.render_widget(title, chunks[0]);

    // 2. Draw Main Screen content
    match app.screen {
        TuiScreen::DeviceSelect => draw_device_select(f, chunks[1], app),
        TuiScreen::Scanning => draw_scanning(f, chunks[1], app),
        TuiScreen::Results => draw_results(f, chunks[1], app),
    }

    // 3. Draw Help Footer bar
    let footer_text = match app.screen {
        TuiScreen::DeviceSelect => "  [▲/▼] Navigate  |  [TAB] Switch Scan Mode  |  [ENTER] Start Scan  |  [A] Acquire Android  |  [Q/ESC] Quit",
        TuiScreen::Scanning => "  [ESC] Abort Scan",
        TuiScreen::Results => {
            if app.search_query.is_empty() {
                "  [▲/▼] Browse Files  |  [/] Search Extension  |  [R] Recover Selected  |  [A] Recover All  |  [ESC] Back"
            } else {
                "  [▲/▼] Browse Files  |  [/] Edit Search  |  [C] Clear Search  |  [R] Recover Selected  |  [A] Recover All  |  [ESC] Back"
            }
        }
    };
    let footer = Paragraph::new(footer_text)
        .style(Style::default().fg(FG_CREAM).bg(ACCENT_GOLD).add_modifier(Modifier::BOLD));
    f.render_widget(footer, chunks[2]);

    // 4. Draw Overlay Modals
    if app.show_prompt {
        draw_prompt_modal(f, size, app);
    } else if app.show_search_prompt {
        draw_search_modal(f, size, app);
    } else if let Some(ref msg) = app.alert_msg {
        draw_alert_modal(f, size, msg);
    }
}

fn draw_device_select(f: &mut Frame, area: Rect, app: &mut TuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Left Side: Drive List
    let items: Vec<ListItem> = app.devices
        .iter()
        .map(|dev| {
            let desc = format!("  {}  ({} - {})", dev.path, utils::format_size(dev.size), dev.device_type);
            ListItem::new(desc)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .border_style(Style::default().fg(FG_LIGHT))
                .title(" Select Storage Device ")
        )
        .style(Style::default().bg(BG_DARK).fg(FG_CREAM))
        .highlight_style(
            Style::default()
                .bg(ACCENT_GOLD)
                .fg(FG_CREAM)
                .add_modifier(Modifier::BOLD),
        );

    f.render_stateful_widget(list, chunks[0], &mut app.device_list_state);

    // Right Side: Selected Info & Scanning Options
    let selected_idx = app.device_list_state.selected().unwrap_or(0);
    let mut details = vec![
        Line::from(vec![
            Span::styled("Scan Mode:     ", Style::default().fg(FG_LIGHT).add_modifier(Modifier::BOLD)),
            Span::styled(
                match app.scan_mode {
                    ScanMode::Quick => "QUICK SCAN (Filesystem-based recovery)",
                    ScanMode::Deep => "DEEP CARVING (Raw signature sector sweep)",
                },
                Style::default().fg(ACCENT_GOLD).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
    ];

    if selected_idx < app.devices.len() {
        let dev = &app.devices[selected_idx];
        details.push(Line::from(vec![
            Span::styled("Device Path:   ", Style::default().fg(FG_LIGHT)),
            Span::styled(&dev.path, Style::default().fg(FG_CREAM)),
        ]));
        details.push(Line::from(vec![
            Span::styled("Device Name:   ", Style::default().fg(FG_LIGHT)),
            Span::styled(&dev.name, Style::default().fg(FG_CREAM)),
        ]));
        details.push(Line::from(vec![
            Span::styled("Capacity:      ", Style::default().fg(FG_LIGHT)),
            Span::styled(utils::format_size(dev.size), Style::default().fg(FG_CREAM)),
        ]));
        details.push(Line::from(vec![
            Span::styled("Device Type:   ", Style::default().fg(FG_LIGHT)),
            Span::styled(&dev.device_type, Style::default().fg(FG_CREAM)),
        ]));
        details.push(Line::from(vec![
            Span::styled("Sector Size:   ", Style::default().fg(FG_LIGHT)),
            Span::styled(format!("{} bytes", dev.sector_size), Style::default().fg(FG_CREAM)),
        ]));
    } else {
        details.push(Line::from(Span::styled("No devices available. Please plug in a drive and restart.", Style::default().fg(ERR_TERRACOTTA))));
    }

    let dashboard_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(FG_LIGHT))
        .title(" Operations Dashboard ")
        .style(Style::default().bg(BG_DARK).fg(FG_CREAM));

    let inner_area = dashboard_block.inner(chunks[1]);
    f.render_widget(dashboard_block, chunks[1]);

    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(0)])
        .split(inner_area);

    let detail_p = Paragraph::new(details);
    f.render_widget(detail_p, right_chunks[0]);
}





fn draw_scanning(f: &mut Frame, area: Rect, app: &mut TuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(7), Constraint::Min(0)])
        .split(area);

    let dev_name = app.active_device.as_ref().map(|d| d.path.as_str()).unwrap_or("Unknown");
    
    // Calculate progress details
    let pct = if app.total_sectors > 0 {
        (app.scanned_sectors as f64 / app.total_sectors as f64 * 100.0) as u32
    } else {
        0
    };

    let elapsed = app.scan_start_time.map(|t| t.elapsed()).unwrap_or_default();
    let speed_fmt = utils::format_speed(app.scan_speed);
    
    let eta = if app.scan_speed > 0.0 && app.total_sectors > app.scanned_sectors {
        let remaining_bytes = (app.total_sectors - app.scanned_sectors) * 512;
        let secs = remaining_bytes as f64 / app.scan_speed;
        format!("{:02}:{:02}", (secs / 60.0) as u32, (secs % 60.0) as u32)
    } else {
        "--:--".to_string()
    };

    // 1. Stats Bar Pane
    let stats = vec![
        Line::from(vec![
            Span::styled("Target Device:  ", Style::default().fg(FG_LIGHT).add_modifier(Modifier::BOLD)),
            Span::styled(dev_name, Style::default().fg(FG_CREAM).add_modifier(Modifier::BOLD)),
            Span::styled("  |  Mode: ", Style::default().fg(FG_LIGHT)),
            Span::styled(
                match app.scan_mode {
                    ScanMode::Quick => "Quick Filesystem Scan",
                    ScanMode::Deep => "Deep Carving (Raw Sectors)",
                },
                Style::default().fg(ACCENT_GOLD).add_modifier(Modifier::BOLD),
            ),
        ]),
        if app.phase2_resolving {
            Line::from(vec![
                Span::styled("Progress:       ", Style::default().fg(FG_LIGHT).add_modifier(Modifier::BOLD)),
                Span::styled(format!("Resolving file sizes & footers... ({} / {} files)", app.phase2_current, app.phase2_total), Style::default().fg(FG_CREAM)),
            ])
        } else {
            Line::from(vec![
                Span::styled("Progress:       ", Style::default().fg(FG_LIGHT).add_modifier(Modifier::BOLD)),
                Span::styled(format!("{}%  ({} / {} sectors)", pct, app.scanned_sectors, app.total_sectors), Style::default().fg(FG_CREAM)),
            ])
        },
        Line::from(vec![
            Span::styled("Elapsed Time:   ", Style::default().fg(FG_LIGHT)),
            Span::styled(format!("{:02}:{:02}", elapsed.as_secs() / 60, elapsed.as_secs() % 60), Style::default().fg(FG_CREAM)),
            Span::styled("  |  Speed: ", Style::default().fg(FG_LIGHT)),
            Span::styled(if app.phase2_resolving { "N/A".to_string() } else { speed_fmt }, Style::default().fg(FG_CREAM)),
            Span::styled("  |  ETA: ", Style::default().fg(FG_LIGHT)),
            Span::styled(if app.phase2_resolving { "--:--".to_string() } else { eta }, Style::default().fg(FG_CREAM)),
        ]),
        Line::from(vec![
            Span::styled("Files Found:    ", Style::default().fg(FG_LIGHT).add_modifier(Modifier::BOLD)),
            Span::styled(format!("{}", app.found_count), Style::default().fg(OK_SAGE).add_modifier(Modifier::BOLD)),
        ]),
    ];

    let stats_p = Paragraph::new(stats)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .border_style(Style::default().fg(FG_LIGHT))
                .title(" Scan Metrics ")
                .style(Style::default().bg(BG_DARK).fg(FG_CREAM))
        );
    f.render_widget(stats_p, chunks[0]);

    // 2. Visual Sector Map Grid
    let map_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(FG_LIGHT))
        .title(" Live Disk Sector Map Grid ")
        .style(Style::default().bg(BG_DARK).fg(FG_CREAM));
    let inner_map_area = map_block.inner(chunks[1]);
    
    let map_p = generate_dynamic_sector_map(
        app.total_sectors,
        app.scanned_sectors,
        &app.file_offsets,
        &app.error_offsets,
        512,
        inner_map_area.width as usize,
        inner_map_area.height as usize,
    );
    
    f.render_widget(map_p.block(map_block), chunks[1]);
}

fn draw_results(f: &mut Frame, area: Rect, app: &mut TuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    let filtered_deleted = app.get_filtered_deleted_files();
    let filtered_carved = app.get_filtered_carved_files();

    // Left Column: Results List
    let list_title = if app.search_query.is_empty() {
        format!(" Found Files (Total: {}) ", match app.scan_mode {
            ScanMode::Quick => app.deleted_files.len(),
            ScanMode::Deep => app.carved_files.len(),
        })
    } else {
        format!(" Found Files (Filtered: {}/{} for \"{}\") ",
            match app.scan_mode {
                ScanMode::Quick => filtered_deleted.len(),
                ScanMode::Deep => filtered_carved.len(),
            },
            match app.scan_mode {
                ScanMode::Quick => app.deleted_files.len(),
                ScanMode::Deep => app.carved_files.len(),
            },
            app.search_query
        )
    };

    let items: Vec<ListItem> = match app.scan_mode {
        ScanMode::Quick => filtered_deleted
            .iter()
            .map(|file| {
                let status_color = match file.status {
                    RecoveryStatus::Recoverable => OK_SAGE,
                    RecoveryStatus::Partial => ACCENT_GOLD,
                    _ => ERR_TERRACOTTA,
                };
                let line = Line::from(vec![
                    Span::styled(format!("ID {:<3} ", file.id), Style::default().fg(FG_LIGHT)),
                    Span::styled(format!("{:<28} ", truncate_str(&file.name, 28)), Style::default().fg(FG_CREAM)),
                    Span::styled(format!("{:<8} ", utils::format_size(file.size)), Style::default().fg(ACCENT_GOLD)),
                    Span::styled(format!("{}", file.status), Style::default().fg(status_color).add_modifier(Modifier::BOLD)),
                ]);
                ListItem::new(line)
            })
            .collect(),
        ScanMode::Deep => filtered_carved
            .iter()
            .map(|file| {
                let display_name = if let Some(ref name) = file.name {
                    name.clone()
                } else {
                    format!("carved_file_{}", file.offset)
                };
                let line = Line::from(vec![
                    Span::styled(format!("ID {:<3} ", file.id), Style::default().fg(FG_LIGHT)),
                    Span::styled(format!("{:<28} ", truncate_str(&display_name, 28)), Style::default().fg(FG_CREAM)),
                    Span::styled(format!("{:<8} ", utils::format_size(file.size)), Style::default().fg(ACCENT_GOLD)),
                    Span::styled(file.signature.extension.to_uppercase(), Style::default().fg(OK_SAGE).add_modifier(Modifier::BOLD)),
                ]);
                ListItem::new(line)
            })
            .collect(),
    };

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .border_style(Style::default().fg(FG_LIGHT))
                .title(list_title)
        )
        .style(Style::default().bg(BG_DARK).fg(FG_CREAM))
        .highlight_style(
            Style::default()
                .bg(ACCENT_GOLD)
                .fg(FG_CREAM)
                .add_modifier(Modifier::BOLD),
        );
    f.render_stateful_widget(list, chunks[0], &mut app.results_list_state);

    // Right Column: Details Pane & Hex View
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(chunks[1]);

    // 1. Details Pane
    let sel_idx = app.results_list_state.selected().unwrap_or(0);
    let mut details = Vec::new();

    match app.scan_mode {
        ScanMode::Quick => {
            if sel_idx < filtered_deleted.len() {
                let file = &filtered_deleted[sel_idx];
                details.push(Line::from(vec![Span::styled("Name:        ", Style::default().fg(FG_LIGHT)), Span::styled(&file.name, Style::default().fg(FG_CREAM))]));
                details.push(Line::from(vec![Span::styled("Size:        ", Style::default().fg(FG_LIGHT)), Span::styled(utils::format_size(file.size), Style::default().fg(FG_CREAM))]));
                details.push(Line::from(vec![Span::styled("Start Clus:  ", Style::default().fg(FG_LIGHT)), Span::styled(file.start_cluster.to_string(), Style::default().fg(FG_CREAM))]));
                details.push(Line::from(vec![Span::styled("Status:      ", Style::default().fg(FG_LIGHT)), Span::styled(file.status.to_string(), Style::default().fg(FG_CREAM))]));
                details.push(Line::from(vec![Span::styled("Filesystem:  ", Style::default().fg(FG_LIGHT)), Span::styled(&file.filesystem, Style::default().fg(FG_CREAM))]));
                if let Some(created) = file.created {
                    details.push(Line::from(vec![
                        Span::styled("Created:     ", Style::default().fg(FG_LIGHT)),
                        Span::styled(utils::format_timestamp(created), Style::default().fg(FG_CREAM)),
                    ]));
                }
                if let Some(modified) = file.modified {
                    details.push(Line::from(vec![
                        Span::styled("Modified:    ", Style::default().fg(FG_LIGHT)),
                        Span::styled(utils::format_timestamp(modified), Style::default().fg(FG_CREAM)),
                    ]));
                }
            }
        }
        ScanMode::Deep => {
            if sel_idx < filtered_carved.len() {
                let file = &filtered_carved[sel_idx];
                let display_name = file.name.as_deref().unwrap_or("Unknown / Untracked");
                let fs_display = file.filesystem.as_deref().unwrap_or("None / RAW");
                details.push(Line::from(vec![Span::styled("Name:        ", Style::default().fg(FG_LIGHT)), Span::styled(display_name, Style::default().fg(FG_CREAM))]));
                details.push(Line::from(vec![Span::styled("ID:          ", Style::default().fg(FG_LIGHT)), Span::styled(file.id.to_string(), Style::default().fg(FG_CREAM))]));
                details.push(Line::from(vec![Span::styled("Disk Offset: ", Style::default().fg(FG_LIGHT)), Span::styled(format!("0x{:X}", file.offset), Style::default().fg(FG_CREAM))]));
                details.push(Line::from(vec![Span::styled("Length:      ", Style::default().fg(FG_LIGHT)), Span::styled(utils::format_size(file.size), Style::default().fg(FG_CREAM))]));
                details.push(Line::from(vec![Span::styled("File Type:   ", Style::default().fg(FG_LIGHT)), Span::styled(&file.signature.name, Style::default().fg(FG_CREAM))]));
                details.push(Line::from(vec![Span::styled("Extension:   ", Style::default().fg(FG_LIGHT)), Span::styled(&file.signature.extension, Style::default().fg(FG_CREAM))]));
                details.push(Line::from(vec![Span::styled("Filesystem:  ", Style::default().fg(FG_LIGHT)), Span::styled(fs_display, Style::default().fg(FG_CREAM))]));
            }
        }
    }

    let details_p = Paragraph::new(details)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .border_style(Style::default().fg(FG_LIGHT))
                .title(" Selected Metadata ")
                .style(Style::default().bg(BG_DARK).fg(FG_CREAM))
        );
    f.render_widget(details_p, right_chunks[0]);

    // 2. Hex Dump Preview Pane
    let hex_lines = generate_hex_dump(&app.hex_data);
    let hex_p = Paragraph::new(hex_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .border_style(Style::default().fg(FG_LIGHT))
                .title(" Raw File Header (First 512B) ")
                .style(Style::default().bg(BG_DARK).fg(FG_CREAM))
        );
    f.render_widget(hex_p, right_chunks[1]);
}

fn draw_prompt_modal(f: &mut Frame, area: Rect, app: &mut TuiApp) {
    let modal_area = centered_rect(60, 25, area);
    f.render_widget(Clear, modal_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(ACCENT_GOLD).bg(Color::Black))
        .title(format!(" {} ", app.prompt_title))
        .style(Style::default().bg(Color::Black).fg(FG_CREAM));

    let prompt_text = vec![
        Line::from(Span::styled("Specify the output directory folder path to write recovered files:", Style::default().fg(FG_CREAM))),
        Line::from(""),
        Line::from(vec![
            Span::styled("> ", Style::default().fg(ACCENT_GOLD).add_modifier(Modifier::BOLD)),
            Span::styled(&app.prompt_value, Style::default().fg(FG_CREAM).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(""),
        Line::from(Span::styled(" Press [ENTER] to Recover, [ESC] to Cancel ", Style::default().fg(Color::Gray))),
    ];

    let p = Paragraph::new(prompt_text)
        .block(block)
        .wrap(Wrap { trim: true });

    f.render_widget(p, modal_area);
}

fn draw_search_modal(f: &mut Frame, area: Rect, app: &mut TuiApp) {
    let modal_area = centered_rect(60, 25, area);
    f.render_widget(Clear, modal_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(ACCENT_GOLD).bg(Color::Black))
        .title(" Search Files by Extension ")
        .style(Style::default().bg(Color::Black).fg(FG_CREAM));

    let prompt_text = vec![
        Line::from(Span::styled("Type a file extension to filter the results (e.g., .pdf, png):", Style::default().fg(FG_CREAM))),
        Line::from(""),
        Line::from(vec![
            Span::styled("> ", Style::default().fg(ACCENT_GOLD).add_modifier(Modifier::BOLD)),
            Span::styled(&app.search_query, Style::default().fg(FG_CREAM).add_modifier(Modifier::BOLD)),
            Span::styled("█", Style::default().fg(ACCENT_GOLD)),
        ]),
        Line::from(""),
        Line::from(Span::styled(" Press [ENTER] or [ESC] to return to results list ", Style::default().fg(Color::Gray))),
    ];

    let p = Paragraph::new(prompt_text)
        .block(block)
        .wrap(Wrap { trim: true });

    f.render_widget(p, modal_area);
}

fn draw_alert_modal(f: &mut Frame, area: Rect, msg: &str) {
    let modal_area = centered_rect(70, 35, area);
    f.render_widget(Clear, modal_area);

    let is_error = msg.to_lowercase().contains("error") || msg.to_lowercase().contains("failed") || msg.to_lowercase().contains("unsupported");
    let theme_color = if is_error { ERR_TERRACOTTA } else { OK_SAGE };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(theme_color).bg(Color::Black))
        .title(" System Notification ")
        .style(Style::default().bg(Color::Black).fg(theme_color));

    let mut prompt_text = vec![
        Line::from(""),
    ];

    for line in msg.lines() {
        prompt_text.push(Line::from(Span::styled(line, Style::default().fg(theme_color).add_modifier(Modifier::BOLD))));
    }

    prompt_text.push(Line::from(""));
    prompt_text.push(Line::from(Span::styled(" Press [ANY KEY] to Dismiss ", Style::default().fg(Color::Gray))));

    let p = Paragraph::new(prompt_text)
        .block(block)
        .wrap(Wrap { trim: true });

    f.render_widget(p, modal_area);
}

/// Helper function to center a modal window on screen
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        let mut truncated = s[..max_len - 3].to_string();
        truncated.push_str("...");
        truncated
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::RecoveryStatus;
    use crate::signatures::Signature;

    #[test]
    fn test_tui_app_filter_deleted_files() {
        let mut app = TuiApp::new();
        app.deleted_files = vec![
            DeletedFile {
                id: 1,
                name: "document.pdf".to_string(),
                size: 1024,
                start_cluster: 2,
                status: RecoveryStatus::Recoverable,
                filesystem: "FAT32".to_string(),
                created: None,
                modified: None,
                accessed: None,
                hash: None,
            },
            DeletedFile {
                id: 2,
                name: "image.png".to_string(),
                size: 2048,
                start_cluster: 5,
                status: RecoveryStatus::Recoverable,
                filesystem: "FAT32".to_string(),
                created: None,
                modified: None,
                accessed: None,
                hash: None,
            },
            DeletedFile {
                id: 3,
                name: "REPORT.PDF".to_string(),
                size: 4096,
                start_cluster: 10,
                status: RecoveryStatus::Recoverable,
                filesystem: "FAT32".to_string(),
                created: None,
                modified: None,
                accessed: None,
                hash: None,
            },
        ];

        // Empty search returns all
        assert_eq!(app.get_filtered_deleted_files().len(), 3);

        // Search with extension including dot
        app.search_query = ".pdf".to_string();
        let filtered = app.get_filtered_deleted_files();
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].name, "document.pdf");
        assert_eq!(filtered[1].name, "REPORT.PDF");

        // Search with extension without dot
        app.search_query = "png".to_string();
        let filtered = app.get_filtered_deleted_files();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "image.png");

        // Case insensitive search
        app.search_query = "PdF".to_string();
        assert_eq!(app.get_filtered_deleted_files().len(), 2);
    }

    #[test]
    fn test_tui_app_filter_carved_files() {
        let mut app = TuiApp::new();
        let sig_pdf = Signature {
            name: "PDF Document".to_string(),
            extension: "pdf".to_string(),
            headers: vec![],
            footers: vec![],
            max_size: 1024,
            size_parser: None,
        };
        let sig_png = Signature {
            name: "PNG Image".to_string(),
            extension: "png".to_string(),
            headers: vec![],
            footers: vec![],
            max_size: 1024,
            size_parser: None,
        };

        app.carved_files = vec![
            CarvedFile {
                id: 1,
                offset: 100,
                size: 500,
                is_exact: true,
                signature: sig_pdf.clone(),
                name: None,
                filesystem: None,
            },
            CarvedFile {
                id: 2,
                offset: 1000,
                size: 200,
                is_exact: true,
                signature: sig_png,
                name: None,
                filesystem: None,
            },
            CarvedFile {
                id: 3,
                offset: 2000,
                size: 800,
                is_exact: true,
                signature: sig_pdf,
                name: None,
                filesystem: None,
            },
        ];

        // Empty search returns all
        assert_eq!(app.get_filtered_carved_files().len(), 3);

        // Search with extension including dot
        app.search_query = ".pdf".to_string();
        let filtered = app.get_filtered_carved_files();
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].id, 1);
        assert_eq!(filtered[1].id, 3);

        // Search with extension without dot
        app.search_query = "png".to_string();
        let filtered = app.get_filtered_carved_files();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, 2);

        // Case insensitive search
        app.search_query = "PNG".to_string();
        assert_eq!(app.get_filtered_carved_files().len(), 1);
    }

    #[test]
    fn test_tui_app_android_hotkey() {
        let mut app = TuiApp::new();
        app.screen = TuiScreen::DeviceSelect;

        let event = KeyEvent::new(KeyCode::Char('a'), event::KeyModifiers::NONE);
        handle_input(event, &mut app);

        // Since ADB might not be available or running, this should set the alert message
        assert!(app.alert_msg.is_some());
        let msg = app.alert_msg.unwrap();
        assert!(msg.contains("ADB") || msg.contains("Android") || msg.contains("devices") || msg.contains("path") || msg.contains("not found"));
    }
}
