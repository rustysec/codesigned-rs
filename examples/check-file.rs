extern crate codesigned;

use codesigned::CodeSigned;
use std::env::args;

fn main() {
    let path = args()
        .nth(1)
        .expect("Provide the path to a file for signature check");

    println!("checking: {}", path);
    let mut cs = CodeSigned::new(path).expect("An error occured while verifying signature");
    println!("{:?}", cs);
}
