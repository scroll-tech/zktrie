//use std::env;
use std::io::{self, Write};
use std::path::Path;

fn main() {
    let lib_name = "zktrie";
    //let out_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    // Build
    if let Err(e) = gobuild::Build::new()
        .buildmode(gobuild::BuildMode::CShared)
        .try_compile(lib_name)
    {
        // The error type is private so have to check the error string
        if format!("{}", e).starts_with("Failed to find tool.") {
            fail(
                " Failed to find Go. Please install Go 1.16 or later \
                following the instructions at https://golang.org/doc/install.
                On linux it is also likely available as a package."
                    .to_string(),
            );
        } else {
            fail(format!("{}", e));
        }
    }

    // file updating
    let srcs = ["./types", "./trie", "./lib.go", "./c.go"];
    for src in srcs {
        let p = Path::new(src);
        println!("cargo:rerun-if-changed={}", p.display());
    }
}

fn fail(message: String) {
    let _ = writeln!(
        io::stderr(),
        "\n\nError while building zktrie: {}\n\n",
        message
    );
    std::process::exit(1);
}
