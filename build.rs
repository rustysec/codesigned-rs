fn main() {
    #[cfg(feature = "with-bindgen")]
    {
        use std::path::PathBuf;

        // Tell cargo to invalidate the built crate whenever the wrapper changes
        println!("cargo:rerun-if-changed=wrapper.h");

        let mut bindings = bindgen::Builder::default()
            .header("wrapper.h")
            .allowlist_function("WinVerifyTrust")
            .allowlist_function("CryptMsgClose")
            .allowlist_function("CertCloseStore")
            .allowlist_function("CryptQueryObject")
            .allowlist_function("CryptMsgGetParam")
            .allowlist_function("CertGetNameStringA")
            .allowlist_function("CertFindCertificateInStore")
            .allowlist_function("CryptCATAdminAcquireContext")
            .allowlist_function("CryptCATAdminReleaseContext")
            .allowlist_function("CryptCATCatalogInfoFromContext")
            .allowlist_function("CryptCATAdminEnumCatalogFromHash")
            .allowlist_function("CryptCATAdminReleaseCatalogContext")
            .allowlist_function("CryptCATAdminCalcHashFromFileHandle")
            .allowlist_function("CryptCATAdminReleaseContextWrapper")
            .allowlist_type("CMSG_SIGNER_INFO")
            .layout_tests(false)
            .clang_arg("-target")
            .clang_arg("x86_64-w64-mingw32");

        if let Ok(include_path) = std::env::var("INCLUDE") {
            bindings = bindings.clang_arg("-I").clang_arg(include_path);
        }

        let bindings = bindings
            .generate()
            .expect("Unable to generate bindings")
            .to_string()
            .replace("extern \"C\"", "extern \"system\"");

        let out_path = PathBuf::from("src/api.rs");

        std::fs::write(out_path, bindings).expect("Couldn't write bindings!");
    }
}
