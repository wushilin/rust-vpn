use std::process::Command;

fn main() {
    // --- BUILD_BRANCH ---
    let branch = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_else(|| "unknown".into())
        .trim()
        .to_string();

    // --- BUILD_TIME ---
    let now = chrono::Local::now();
    let build_time = now.format("%Y-%m-%dT%H:%M:%S%.3f").to_string();

    // --- BUILD_HOST ---
    let host = hostname::get()
        .ok()
        .and_then(|s| s.into_string().ok())
        .unwrap_or_else(|| "unknown".into());

    // --- Export to Cargo env ---
    println!("cargo:rustc-env=BUILD_BRANCH={}", branch);
    println!("cargo:rustc-env=BUILD_TIME={}", build_time);
    println!("cargo:rustc-env=BUILD_HOST={}", host);

    // Ensure build.rs only reruns when necessary
    println!("cargo:rerun-if-changed=build.rs");
}
