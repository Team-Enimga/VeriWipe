//! Bare-Metal Terminal TUI (Crossterm) for headless live-boot or tty1 consoles.
//! Displays live device inventory, autonomous wipe trigger, and blockchain verification.

use crate::blockchain::crypto::KeyAuthority;
use crate::blockchain::BlockchainLedger;
use crate::config::RuntimePaths;
use crate::devices::detector::list_block_devices;
use crossterm::{
    cursor,
    event::{self, Event, KeyCode},
    execute,
    style::{Color, Print, ResetColor, SetBackgroundColor, SetForegroundColor},
    terminal::{self, ClearType},
};
use std::io::{stdout, Write};
use std::time::Duration;

pub fn run_tui() -> Result<(), Box<dyn std::error::Error>> {
    terminal::enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, terminal::EnterAlternateScreen, cursor::Hide)?;

    let mut selected_option = 0;
    let menu_options = [
        "1. Launch Autonomous One-Shot Decommissioning (Wipe All Non-Boot Disks)",
        "2. Run Deep Forensic Carver on Test/Target Image",
        "3. Verify Blockchain Audit Ledger Cryptographic Integrity",
        "4. Enumerate Hardware Block Devices & Bus Types",
        "5. Exit Console TUI",
    ];

    let mut status_message = "Ready. Use Up/Down arrows to navigate, Enter to select, 'q' to quit.".to_string();

    loop {
        execute!(stdout, terminal::Clear(ClearType::All), cursor::MoveTo(0, 0))?;

        // 1. Draw Title Bar
        execute!(
            stdout,
            SetForegroundColor(Color::Black),
            SetBackgroundColor(Color::Cyan),
            Print("  VERIWIPE: BARE-METAL FORENSICS & SECURE ERASURE APPLIANCE (NTRO PS 26149)   \r\n"),
            ResetColor
        )?;

        // 2. Draw Discovered Drives
        let devices = list_block_devices(true);
        println!("\r\n--- DETECTED HARDWARE STORAGE DEVICES ---");
        println!("DEV NODE   BUS TYPE        CAPACITY     MODEL                          STATUS");
        println!("--------------------------------------------------------------------------------");
        for dev in devices.iter().take(5) {
            let status = if dev.is_protected { "LOCKED 🔒 (Protected Boot/Root)" } else { "READY  ✅ (Target)" };
            println!("{:<10} {:<15} {:>6.1} GB    {:<30} {}",
                dev.path, dev.bus_type, dev.size_gb,
                if dev.model.len() > 30 { &dev.model[..30] } else { &dev.model },
                status);
        }
        println!("--------------------------------------------------------------------------------\r\n");

        // 3. Draw Menu
        println!("--- OPERATIONAL WORKFLOWS ---");
        for (i, opt) in menu_options.iter().enumerate() {
            if i == selected_option {
                execute!(
                    stdout,
                    SetForegroundColor(Color::Black),
                    SetBackgroundColor(Color::Green),
                    Print(format!(" > {} \r\n", opt)),
                    ResetColor
                )?;
            } else {
                println!("   {}", opt);
            }
        }

        // 4. Status Bar
        println!("\r\n================================================================================");
        println!("STATUS: {}", status_message);
        println!("================================================================================");
        stdout.flush()?;

        // 5. Handle Keyboard Events
        if event::poll(Duration::from_millis(500))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Up => {
                        if selected_option > 0 {
                            selected_option -= 1;
                        }
                    }
                    KeyCode::Down => {
                        if selected_option + 1 < menu_options.len() {
                            selected_option += 1;
                        }
                    }
                    KeyCode::Char('q') | KeyCode::Esc => {
                        break;
                    }
                    KeyCode::Enter => {
                        match selected_option {
                            0 => {
                                status_message = "Starting Autonuke Dry-Run Simulation...".to_string();
                                execute!(stdout, terminal::LeaveAlternateScreen, cursor::Show)?;
                                terminal::disable_raw_mode()?;
                                let _ = super::autonuke::run_autonuke(true, true, 5);
                                println!("\nPress Enter to return to TUI...");
                                let mut dummy = String::new();
                                std::io::stdin().read_line(&mut dummy)?;
                                terminal::enable_raw_mode()?;
                                execute!(stdout, terminal::EnterAlternateScreen, cursor::Hide)?;
                            }
                            2 => {
                                let paths = RuntimePaths::get();
                                let authority = KeyAuthority::load_or_generate(&paths.authority_privkey, &paths.authority_pubkey).unwrap();
                                let ledger = BlockchainLedger::load_or_create(&paths.ledger_file, &authority).unwrap();
                                let res = ledger.verify_chain();
                                status_message = format!("Blockchain Audit Chain: {} ({} blocks verified)",
                                    if res.is_valid { "CRYPTOGRAPHICALLY VALID ✅" } else { "TAMPERED ❌" },
                                    res.verified_blocks);
                            }
                            3 => {
                                status_message = format!("Discovered {} total block devices on bus.", devices.len());
                            }
                            4 => {
                                break;
                            }
                            _ => {
                                status_message = format!("Action {} selected.", selected_option + 1);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    execute!(stdout, terminal::LeaveAlternateScreen, cursor::Show)?;
    terminal::disable_raw_mode()?;
    Ok(())
}
