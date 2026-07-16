// Prevents an extra console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // Linux privileged-install child (#638): when this executable is relaunched
    // as root via `pkexec` with the fixed elevation token, run ONLY the headless
    // privileged install (the selection arrives over STDIN) and exit — NEVER start
    // the Tauri WebView (so no GUI ever runs as root). This branch is reached only
    // via `dig_installer::elevation::relaunch_elevated`, which builds a fixed,
    // pwnkit-safe argv (an absolute program path, the token, no shell).
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let mut args = std::env::args_os().skip(1);
        if args.next().as_deref()
            == Some(std::ffi::OsStr::new(
                dig_installer::elevation::ELEVATED_INSTALL_ARG,
            ))
        {
            match digstore_installer_lib::run_elevated_privileged_install_from_stdin() {
                Ok(()) => std::process::exit(0),
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
        }
    }

    // macOS privileged-install child (#639): when this executable is relaunched as
    // root via `osascript … with administrator privileges` with the fixed elevation
    // token, run ONLY the headless privileged install and exit — NEVER start the
    // Tauri WebView (so no GUI ever runs as root). The plan-file path is the second
    // positional argument (Authorization Services does not inherit stdin). This
    // branch is reached only via `elevation::relaunch_elevated_macos`, which builds a
    // fixed, injection-safe osascript argv (an absolute program path, the token, the
    // absolute plan path — each shell-quoted via AppleScript `quoted form of`).
    #[cfg(target_os = "macos")]
    {
        let mut args = std::env::args_os().skip(1);
        if args.next().as_deref()
            == Some(std::ffi::OsStr::new(
                dig_installer::elevation::ELEVATED_INSTALL_ARG,
            ))
        {
            let result = match args.next() {
                Some(plan_path) => {
                    digstore_installer_lib::run_elevated_privileged_install_from_file(
                        std::path::Path::new(&plan_path),
                    )
                }
                None => Err("elevated install: missing plan-file path argument".to_string()),
            };
            match result {
                Ok(()) => std::process::exit(0),
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
        }
    }

    digstore_installer_lib::run()
}
