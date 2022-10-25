use codesigned::CodeSigned;
use std::{io::stdin, path::PathBuf};
use structopt::StructOpt;

#[derive(StructOpt)]
struct Options {
    file: PathBuf,
    count: Option<u64>,
}

fn main() {
    let opts = Options::from_args();

    println!("Checking Signature of {}", opts.file.display());

    let count = opts.count.unwrap_or(1);

    println!("count: {}", count);

    for idx in 0..count {
        match CodeSigned::new(&opts.file) {
            Err(err) => {
                if idx == 0 {
                    println!("An error occurred while verifying signature: {}", err);
                }
            }
            Ok(cs) => {
                if idx == 0 {
                    println!("{:#?}", cs);
                }
            }
        }
    }

    if count > 1 {
        println!("Done, press enter to close");
        let stdin = stdin();
        let _ = stdin.lines().next().unwrap();
    }
}
