use codesigned::CodeSigned;
use std::env::args;

fn main() {
    let path = args()
        .nth(1)
        .expect("Provide the path to a file for signature check");

    println!("Checking Signature of {}", path);

    match CodeSigned::new(path) {
        Err(err) => println!("An error occurred while verifying signature: {}", err),
        Ok(cs) => println!("{:#?}", cs),
    }
}
