//! Interface for windows binary signing via Crypt32 APIs. Cryptographic signing
//! of executables helps ensure files are released by who they claim to be released
//! by, as well as verify they have not been tampered with between release and execution.
//!
//! More information is available from Microsoft
//! [here](https://docs.microsoft.com/en-us/windows/win32/seccrypto/cryptography-tools)
//!
//!
//! ```no_run
//! use codesigned::CodeSigned;
//! let signature = CodeSigned::new(r"c:\windows\system32\notepad.exe")?;
//! ```
//!

#![cfg(target_os = "windows")]
#![warn(missing_docs)]

mod api;
mod error;

use api::*;
use error::Error;
use std::ptr::{null, null_mut};
use widestring::{U16CStr, U16CString};

/// Result of code signing operations
type Result<T> = std::result::Result<T, Error>;

/// Type of signature found
#[derive(Clone, Debug, PartialEq)]
pub enum SignatureType {
    /// Not signed
    NotSigned,

    /// File has an embedded signature
    Embedded,

    /// Signature was found in a certificate catalog
    Catalog,
}

impl Default for SignatureType {
    fn default() -> Self {
        Self::NotSigned
    }
}

/// Information about the code signature.
#[derive(Clone, Default, Debug)]
pub struct CodeSigned {
    /// Path of the file accesses
    pub path: std::path::PathBuf,

    /// The type of signature found
    pub signature_type: SignatureType,

    /// The name of the certificate issuer
    pub issuer_name: Option<String>,

    /// The name of the owner of the file
    pub subject_name: Option<String>,

    /// The name of the timestamp issuer
    pub timestamp_issuer_name: Option<String>,

    /// The name of the subject receiving the timestamp
    pub timestamp_subject_name: Option<String>,

    /// The certificate serial number
    pub serial_number: Option<String>,
}

impl CodeSigned {
    /// Attempt to verify the signature status of a file at `path`.
    pub fn new<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let mut this = Self::default();
        this.path = path.as_ref().to_path_buf();

        let path = path.as_ref().to_str().ok_or(Error::Generic)?;
        let path = U16CString::from_str(path).map_err(|_| Error::Generic)?;

        let mut file_info = WinTrustFileInfo::from_path(&path);

        let mut win_trust_data = WinTrustData::default();
        win_trust_data.data = &mut file_info;

        let action = Guid::wintrust_action_generic_verify_v2();

        match unsafe { WinVerifyTrust(null(), &action, &win_trust_data) } {
            0 => this.embedded(&path)?,
            _ => this.catalog(&path)?,
        }

        win_trust_data.state_action = WTD_STATEACTION_CLOSE;

        unsafe {
            WinVerifyTrust(null(), &action, &win_trust_data);
        }

        Ok(this)
    }

    /// Determines if the file is signed
    pub fn signed(&self) -> bool {
        self.signature_type != SignatureType::NotSigned
    }

    fn embedded(&mut self, path: &U16CString) -> Result<()> {
        let mut encoding: u32 = 0;
        let mut content_type: u32 = 0;
        let mut format_type: u32 = 0;
        let mut h_store = CertStore::new();
        let mut h_msg = CryptMsg::new();

        if unsafe {
            CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                path.as_ptr() as *const _,
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                CERT_QUERY_FORMAT_FLAG_BINARY,
                0,
                &mut encoding,
                &mut content_type,
                &mut format_type,
                &mut h_store.raw_ptr(),
                &mut h_msg.raw_ptr(),
                null_mut(),
            )
        } == 0
        {
            return Err(Error::Generic);
        }

        let mut msg_signer_info: MsgSignerInfo = unsafe { std::mem::zeroed() };
        let mut data_len: u32 = 0;

        if unsafe {
            CryptMsgGetParam(
                h_msg.raw_ptr(),
                CMSG_SIGNER_INFO_PARAM,
                std::mem::size_of::<MsgSignerInfo>() as _,
                &mut msg_signer_info as *mut _ as _,
                &mut data_len,
            )
        } == 0
        {
            return Err(Error::Generic);
        }

        let mut cert_info = CertInfo::default();
        cert_info.serial_number.from(&msg_signer_info.serial_number);
        cert_info.issuer.from(&msg_signer_info.issuer);

        let context = CertStoreContext::new(unsafe {
            CertFindCertificateInStore(
                h_store.raw_ptr(),
                ENCODING,
                0,
                CERT_FIND_SUBJECT_CERT,
                &cert_info,
                null(),
            )
        });

        let needed: u32 = unsafe {
            CertGetNameStringA(
                context.context(),
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                null(),
                null(),
                0,
            )
        };

        let mut subject_name_data: Vec<u8> = vec![0; needed as usize];

        unsafe {
            CertGetNameStringA(
                context.context(),
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                null(),
                subject_name_data.as_mut_ptr() as _,
                needed as u32,
            );
        }

        self.serial_number = Some(msg_signer_info.serial_number.to_string());
        self.issuer_name = Some(msg_signer_info.issuer.to_string());
        self.subject_name = String::from_utf8(
            subject_name_data
                .into_iter()
                .take(needed as usize - 1)
                .collect::<Vec<u8>>(),
        )
        .ok();
        self.signature_type = SignatureType::Embedded;

        Ok(())
    }

    fn catalog(&mut self, path: &U16CString) -> Result<()> {
        let mut result = Ok(());

        let f = FileHandle::new().with_file(&path)?;

        if let Some(handle) = f.handle() {
            let mut hash_length: u32 = 0;

            if unsafe {
                CryptCATAdminCalcHashFromFileHandle(handle, &mut hash_length, null_mut(), 0)
            } == 0
            {
                println!("Could not obtain file hash for {}", path.to_string_lossy());
                return Err(Error::Generic);
            }

            self.signature_type = SignatureType::Catalog;
            let mut hash_data: Vec<u8> = vec![0; hash_length as usize];
            unsafe {
                CryptCATAdminCalcHashFromFileHandle(
                    handle,
                    &mut hash_length,
                    hash_data.as_mut_ptr() as _,
                    0,
                );
            }

            let driver_action = Guid::driver_action_verify();
            let mut admin_context = AdminContext::new();
            if unsafe {
                CryptCATAdminAcquireContext(&mut admin_context.mut_ptr(), &driver_action, 0)
            } == 0
            {
                return Err(Error::Generic);
            }

            loop {
                let cat = AdminCatalog::new(&admin_context, hash_data.as_ptr(), hash_length);

                if cat.is_null() {
                    result = Err(Error::ExhaustedCatalogs);
                    break;
                }

                let mut cat_info = CatalogInfo::default();
                if 0 == unsafe { CryptCATCatalogInfoFromContext(cat.ptr(), &mut cat_info, 0) } {
                    result = Err(Error::ExhaustedCatalogs);
                    break;
                }

                let cat_path = U16CStr::from_slice_with_nul(&cat_info.catalog_file)
                    .map_err(|_| Error::ExhaustedCatalogs)?
                    .to_ucstring();

                self.signature_type = SignatureType::Catalog;
                self.embedded(&cat_path)?;
            }
        }

        result
    }
}
