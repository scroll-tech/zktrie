use std::env;
use std::io::{self, Write};
use std::path::Path;

fn main() {
    if let Some(target) = env::var("TARGET").ok() {
        if target.contains("android") || target.contains("ios") {
            println!("cargo:warning=Building for Android or iOS");
            return;
        }
    } else {
        println!("cargo:warning=Building for non-mobile platform");
    }

    let lib_name = "zktrie";
    let src_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let src_dir = Path::new(src_dir.as_str());

    //#[cfg(not(target_os = "windows"))]
    //let build_mode = gobuild::BuildMode::CArchive;
    //#[cfg(target_os = "windows")]
    let build_mode = gobuild::BuildMode::CShared;

    // Build
    if let Err(e) = gobuild::Build::new()
        .buildmode(build_mode)
        .try_compile(lib_name)
    {
        // The error type is private so have to check the error string
        if format!("{e}").starts_with("Failed to find tool.") {
            fail(
                " Failed to find Go. Please install Go 1.16 or later \
                following the instructions at https://golang.org/doc/install.
                On linux it is also likely available as a package."
                    .to_string(),
            );
        } else {
            fail(format!("{e}"));
        }
    }

    // file updating
    let srcs = ["types", "trie", "lib.go", "c.go"];
    for src in srcs {
        let p = src_dir.join(src);
        println!("cargo:rerun-if-changed={}", p.as_path().display());
    }
}

fn fail(message: String) {
    let _ = writeln!(
        io::stderr(),
        "\n\nError while building zktrie: {message}\n\n",
    );
    std::process::exit(1);
}
