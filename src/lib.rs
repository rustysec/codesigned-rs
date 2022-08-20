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
//! let signature = CodeSigned::new(r"c:\windows\system32\notepad.exe").unwrap();
//! ```
//!

#![cfg(target_os = "windows")]
#![warn(missing_docs)]

#[allow(dead_code, non_camel_case_types, non_snake_case)]
mod api;
mod error;

use api::*;
use error::Error;
use std::{
    mem::{size_of, zeroed},
    path::{Path, PathBuf},
    ptr::{null, null_mut, read},
    slice::from_raw_parts_mut,
};
use widestring::{U16CStr, U16CString};
use winapi::{
    shared::ntdef::LPCWSTR,
    um::{
        fileapi::{CreateFileW, OPEN_EXISTING},
        wincrypt::{
            CertNameToStrA, CERT_FIND_SUBJECT_CERT, CERT_NAME_SIMPLE_DISPLAY_TYPE,
            CERT_NAME_STR_REVERSE_FLAG, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE, CERT_SIMPLE_NAME_STR,
            CMSG_SIGNER_INFO_PARAM, CRYPTOAPI_BLOB, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
        },
        winnt::{FILE_SHARE_READ, GENERIC_READ},
        wintrust::{WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_STATEACTION_CLOSE},
    },
};

const ENCODING: u32 = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

/// Result of code signing operations
type Result<T> = std::result::Result<T, Error>;

fn wintrust_action_generic_verify_v2() -> GUID {
    GUID {
        Data1: 0xaa_c56b,
        Data2: 0xcd44,
        Data3: 0x11d0,
        Data4: [0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee],
    }
}

fn driver_action_verify() -> GUID {
    GUID {
        Data1: 0xf750_e6c3,
        Data2: 0x38ee,
        Data3: 0x11d1,
        Data4: [0x85, 0xe5, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee],
    }
}

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

trait BlobToString {
    fn crypt_string(&mut self) -> Option<String>;
    fn to_string(&mut self) -> Option<String>;
}

impl BlobToString for _CRYPTOAPI_BLOB {
    fn to_string(&mut self) -> Option<String> {
        if self.cbData == 0 {
            return None;
        }

        let bytes = unsafe { from_raw_parts_mut(self.pbData, self.cbData as _) };
        bytes.reverse();

        Some(
            bytes
                .into_iter()
                .map(|byte| format!("{:02X}", byte))
                .collect::<Vec<_>>()
                .join(""),
        )
    }

    fn crypt_string(&mut self) -> Option<String> {
        let mut blob = CRYPTOAPI_BLOB {
            cbData: self.cbData,
            pbData: self.pbData,
        };

        let length = unsafe {
            CertNameToStrA(
                X509_ASN_ENCODING,
                &mut blob,
                CERT_SIMPLE_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
                null_mut(),
                0,
            )
        };

        if length == 0 {
            return None;
        }

        let mut data: Vec<u8> = vec![0; length as usize];
        unsafe {
            CertNameToStrA(
                X509_ASN_ENCODING,
                &mut blob,
                CERT_SIMPLE_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
                data.as_mut_ptr() as _,
                blob.cbData,
            );
        }

        String::from_utf8(data[0..data.len() - 1].to_vec()).ok()
    }
}

/// Information about the code signature.
#[derive(Clone, Default, Debug)]
pub struct CodeSigned {
    /// Path of the file accesses
    pub path: PathBuf,

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

fn wintrust_file_info(path: LPCWSTR) -> WINTRUST_FILE_INFO {
    WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as _,
        pcwszFilePath: path,
        hFile: null_mut(),
        pgKnownSubject: null(),
    }
}

impl CodeSigned {
    /// Attempt to verify the signature status of a file at `path`.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut this = Self::default();
        this.path = path.as_ref().to_path_buf();

        let path = path.as_ref().to_str().ok_or(Error::Unspecified)?;
        let path = U16CString::from_str(path).map_err(|_| Error::Unspecified)?;

        let mut file_info = wintrust_file_info(path.as_ptr());

        let mut win_trust_data = WINTRUST_DATA::default();

        unsafe {
            *(win_trust_data.u.pFile_mut()) = &mut file_info;
        }

        let mut action = wintrust_action_generic_verify_v2();

        match unsafe { WinVerifyTrust(null_mut(), &mut action, &mut win_trust_data as *mut _ as _) }
        {
            0 => this.embedded(&path)?,
            _ => this.catalog(&path)?,
        }

        win_trust_data.dwStateAction = WTD_STATEACTION_CLOSE;

        unsafe {
            WinVerifyTrust(null_mut(), &mut action, &mut win_trust_data as *mut _ as _);
        }

        Ok(this)
    }

    /// Determines if the file is signed
    pub fn signed(&self) -> bool {
        self.signature_type != SignatureType::NotSigned
    }

    fn embedded(&mut self, path: &U16CString) -> Result<()> {
        println!("getting embedded signature...");

        let mut encoding: u32 = 0;
        let mut content_type: u32 = 0;
        let mut format_type: u32 = 0;
        let mut h_store = null_mut();
        let mut h_msg = null_mut();

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
                &mut h_store as _,
                &mut h_msg as _,
                null_mut(),
            )
        } == 0
        {
            return Err(Error::Unspecified);
        }

        let mut data_len: u32 = 0;

        // get the parameter size
        unsafe {
            CryptMsgGetParam(h_msg, CMSG_SIGNER_INFO_PARAM, 0, null_mut(), &mut data_len);
        }

        let mut msg_signer_info_data = vec![0u8; data_len as usize];
        if unsafe {
            CryptMsgGetParam(
                h_msg,
                CMSG_SIGNER_INFO_PARAM,
                0,
                msg_signer_info_data.as_mut_ptr() as _,
                &mut data_len,
            )
        } == 0
        {
            return Err(Error::Unspecified);
        }

        let mut msg_signer_info: CMSG_SIGNER_INFO =
            unsafe { read(msg_signer_info_data.as_mut_ptr() as _) };

        let mut cert_info: _CERT_INFO = unsafe { zeroed() };
        cert_info.SerialNumber = msg_signer_info.SerialNumber;
        cert_info.Issuer = msg_signer_info.Issuer;

        let context = unsafe {
            CertFindCertificateInStore(
                h_store,
                ENCODING,
                0,
                CERT_FIND_SUBJECT_CERT,
                &cert_info as *const _ as _,
                null(),
            )
        };

        let needed: u32 = unsafe {
            CertGetNameStringA(
                context,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                null_mut(),
                null_mut(),
                0,
            )
        };

        let mut subject_name_data: Vec<u8> = vec![0; needed as usize];

        unsafe {
            CertGetNameStringA(
                context,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                null_mut(),
                subject_name_data.as_mut_ptr() as _,
                needed as u32,
            );
        }

        self.serial_number = msg_signer_info.SerialNumber.to_string();
        self.issuer_name = msg_signer_info.Issuer.crypt_string();
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
        println!("getting catalog signature...");

        let file_handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ,
                null_mut(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        };

        if file_handle.is_null() {
            return Err(Error::OpenFileFailed);
        }

        let mut hash_length: u32 = 0;

        if unsafe {
            CryptCATAdminCalcHashFromFileHandle(file_handle as _, &mut hash_length, null_mut(), 0)
        } == 0
        {
            return Err(Error::UnableToHash(path.to_string_lossy()));
        }

        self.signature_type = SignatureType::Catalog;
        let mut hash_data: Vec<u8> = vec![0; hash_length as usize];
        unsafe {
            CryptCATAdminCalcHashFromFileHandle(
                file_handle as _,
                &mut hash_length,
                hash_data.as_mut_ptr() as _,
                0,
            );
        }

        println!("hash: {:?}", &hash_data[0..hash_length as usize]);

        let driver_action = driver_action_verify();

        let mut admin_context: HCATADMIN = null_mut();
        if unsafe { CryptCATAdminAcquireContext(&mut admin_context, &driver_action, 0) } == 0 {
            return Err(Error::AdminContext);
        }

        println!("admin context null? {}", admin_context.is_null());

        let mut admin_catalog = unsafe {
            CryptCATAdminEnumCatalogFromHash(
                admin_context as _,
                hash_data.as_mut_ptr(),
                hash_length,
                0,
                null_mut(),
            )
        };

        loop {
            println!("loop!!");

            let mut cat_info: CATALOG_INFO = unsafe { zeroed() };
            cat_info.cbStruct = size_of::<CATALOG_INFO>() as _;

            if 0 == unsafe { CryptCATCatalogInfoFromContext(admin_catalog, &mut cat_info, 0) } {
                println!("cannot get cat info");
                return Err(Error::ExhaustedCatalogs);
            }

            let cat_path = U16CStr::from_slice_with_nul(&cat_info.wszCatalogFile)
                .map_err(Error::WideStringConversion)?
                .to_ucstring();

            self.signature_type = SignatureType::Catalog;

            self.embedded(&cat_path)?;

            admin_catalog = unsafe {
                CryptCATAdminEnumCatalogFromHash(
                    admin_context as _,
                    hash_data.as_mut_ptr(),
                    hash_length,
                    0,
                    &mut admin_catalog as _,
                )
            };

            if admin_catalog.is_null() {
                println!("admin catalog is finally null");
                return Ok(());
            }
        }
    }
}
