extern crate codesigned;

use std::env::args;
use codesigned::CodeSigned;

fn main() {
    //let path = args().nth(1).unwrap_or("C:\\program files\\nightly\\firefox.exe".to_owned());
    let path = args().nth(1).unwrap_or("C:\\windows\\system32\\notepad.exe".to_owned());
    println!("checking: {}", path);
    let mut cs = CodeSigned::default();
    cs.file(&path);

    println!("{:?}", cs);
}