use std::env;
use std::process::Command;

fn main() {
    // Get the current directory
    let current_dir = env::current_dir().expect("Failed to get current directory");

    // Build the LKL wrapper library using make
    let output = Command::new("make")
        .arg("-f")
        .arg("Makefile.wrapper")
        .current_dir(&current_dir)
        .output()
        .expect("Failed to execute make");

    // Add the library search path for our built library
    println!("cargo:rustc-link-search=native={}", current_dir.display());

    if !output.status.success() {
        panic!(
            "Failed to build LKL wrapper library: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    println!("cargo:rustc-link-lib=static=lkl_wrapper");

    // Link other required system libraries
    println!("cargo:rustc-link-lib=rt");
    println!("cargo:rustc-link-lib=pthread");

    // Rerun if the library files change
    println!("cargo:rerun-if-changed=lkl_wrapper.c");
    println!("cargo:rerun-if-changed=Makefile.wrapper");
}
