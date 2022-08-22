//! Interface for windows binary signing via Crypt32 APIs. Cryptographic signing
//! of executables helps ensure files are released by who they claim to be released
//! by, as well as verify they have not been tampered with between release and execution.
//!
//! More information is available from Microsoft
//! [here](https://docs.microsoft.com/en-us/windows/win32/seccrypto/cryptography-tools)
//! and [here](https://docs.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust)
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
mod types;

use api::*;
use error::Error;
use std::{
    ffi::{c_void, CStr},
    mem::{size_of, zeroed},
    path::{Path, PathBuf},
    ptr::{null, null_mut, read},
    slice::from_raw_parts_mut,
};
use types::*;
use widestring::{U16CStr, U16CString};
use winapi::um::{
    fileapi::{CreateFileW, OPEN_EXISTING},
    handleapi::CloseHandle,
    wincrypt::{
        szOID_RSA_counterSign, CryptDecodeObject, CERT_FIND_SUBJECT_CERT,
        CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE, CMSG_SIGNER_INFO_PARAM,
        PKCS7_SIGNER_INFO,
    },
    winnt::{FILE_SHARE_READ, GENERIC_READ},
    wintrust::{WINTRUST_DATA, WTD_CHOICE_FILE, WTD_STATEACTION_CLOSE, WTD_UI_NONE},
};

/// Type of signature found
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
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

#[derive(Clone, Debug, PartialEq)]
struct CertData {
    pub serial_number: Option<String>,
    pub issuer_name: Option<String>,
    pub subject_name: Option<String>,
}

/// Information about the code signature.
#[derive(Clone, Default, Debug)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct CodeSigned {
    /// Path of the file accesses
    pub path: PathBuf,

    /// The type of signature found
    pub signature_type: SignatureType,

    /// The name of the certificate issuer
    pub issuer_name: Option<String>,

    /// The name of the owner of the file
    pub subject_name: Option<String>,

    /// The certificate serial number
    pub serial_number: Option<String>,

    /// The name of the timestamp issuer
    #[cfg_attr(feature = "serialize", serde(skip_serializing_if = "Option::is_none"))]
    pub timestamp_issuer_name: Option<String>,

    /// The name of the subject receiving the timestamp
    #[cfg_attr(feature = "serialize", serde(skip_serializing_if = "Option::is_none"))]
    pub timestamp_subject_name: Option<String>,

    /// The name of the subject receiving the timestamp
    #[cfg_attr(feature = "serialize", serde(skip_serializing_if = "Option::is_none"))]
    pub timestamp_serial_number: Option<String>,
}

impl CodeSigned {
    /// Attempt to verify the signature status of a file at `path`.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut this = Self::default();
        this.path = path.as_ref().to_path_buf();

        let path = path.as_ref().to_str().ok_or(Error::Unspecified)?;
        let path = U16CString::from_str(path).map_err(|_| Error::Unspecified)?;

        let mut file_info = wintrust_file_info(path.as_ptr())?;

        let mut win_trust_data = WINTRUST_DATA::default();
        win_trust_data.cbStruct = size_of::<WINTRUST_DATA>() as _;
        win_trust_data.dwUIChoice = WTD_UI_NONE;
        win_trust_data.dwUnionChoice = WTD_CHOICE_FILE;

        unsafe {
            *(win_trust_data.u.pFile_mut()) = &mut file_info;
        }

        let mut action = wintrust_action_generic_verify_v2();

        match unsafe { WinVerifyTrust(null_mut(), &mut action, &mut win_trust_data as *mut _ as _) }
        {
            0 => this.process_embedded(&path)?,
            _err => this.process_catalog(&path)?,
        }

        win_trust_data.dwStateAction = WTD_STATEACTION_CLOSE;

        unsafe {
            WinVerifyTrust(null_mut(), &mut action, &mut win_trust_data as *mut _ as _);
        }

        Ok(this)
    }

    /// Returns if the file is signed
    pub fn is_signed(&self) -> bool {
        self.signature_type != SignatureType::NotSigned
    }

    /// Returns if the file is signed in a catalog
    pub fn is_catalog(&self) -> bool {
        self.signature_type != SignatureType::Catalog
    }

    /// Returns if the file is signed with an embedded certificate
    pub fn is_embedded(&self) -> bool {
        self.signature_type == SignatureType::Embedded
    }

    /// Query for embeded certificate of a file.
    fn process_embedded(&mut self, path: &U16CString) -> Result<()> {
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
            Self::release_embebed_cert(h_store, h_msg);
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
            Self::release_embebed_cert(h_store, h_msg);
            return Err(Error::Unspecified);
        }

        let mut msg_signer_info: CMSG_SIGNER_INFO =
            unsafe { read(msg_signer_info_data.as_mut_ptr() as _) };

        if let Ok(cert_data) = self.cert_data(h_store, &mut msg_signer_info) {
            self.serial_number = cert_data.serial_number;
            self.issuer_name = cert_data.issuer_name;
            self.subject_name = cert_data.subject_name;
        }

        self.timestamp_info(h_store, msg_signer_info);

        Self::release_embebed_cert(h_store, h_msg);
        Ok(())
    }

    /// Enumerates all the signature catalogs for one containing the hash of the file provided.
    /// If found the certificate information of the catalog is returned.
    fn process_catalog(&mut self, path: &U16CString) -> Result<()> {
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

        let driver_action = driver_action_verify();

        let mut admin_context: HCATADMIN = null_mut();
        if unsafe { CryptCATAdminAcquireContext(&mut admin_context, &driver_action, 0) } == 0 {
            return Err(Error::AdminContext);
        }

        unsafe {
            CloseHandle(file_handle);
        }

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
            let mut cat_info: CATALOG_INFO = unsafe { zeroed() };
            cat_info.cbStruct = size_of::<CATALOG_INFO>() as _;

            if 0 == unsafe { CryptCATCatalogInfoFromContext(admin_catalog, &mut cat_info, 0) } {
                Self::release_catalog_enum(admin_context, admin_catalog);
                return Err(Error::ExhaustedCatalogs);
            }

            let cat_path = U16CStr::from_slice_with_nul(&cat_info.wszCatalogFile)
                .map_err(Error::WideStringConversion)?
                .to_ucstring();

            self.process_embedded(&cat_path)?;
            self.signature_type = SignatureType::Catalog;

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
                Self::release_catalog_enum(admin_context, admin_catalog);
                return Ok(());
            }
        }
    }

    fn cert_data(
        &self,
        h_store: *mut c_void,
        msg_signer_info: &mut CMSG_SIGNER_INFO,
    ) -> Result<CertData> {
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

        Ok(CertData {
            serial_number: msg_signer_info.SerialNumber.to_string(),
            issuer_name: msg_signer_info.Issuer.crypt_string(),
            subject_name: String::from_utf8(
                subject_name_data
                    .into_iter()
                    .take(needed as usize - 1)
                    .collect::<Vec<u8>>(),
            )
            .ok(),
        })
    }

    fn timestamp_info(&mut self, h_store: *mut c_void, msg_signer_info: CMSG_SIGNER_INFO) {
        // Try to find timestamp information
        let unauth_count = msg_signer_info.UnauthAttrs.cAttr;
        let attrs =
            unsafe { from_raw_parts_mut(msg_signer_info.UnauthAttrs.rgAttr, unauth_count as _) };

        for attr in attrs {
            if let Ok(oid) = unsafe { CStr::from_ptr(attr.pszObjId).to_str().map(String::from) } {
                if oid == szOID_RSA_counterSign {
                    let mut attr_needed = 0;

                    let attr_blobs = unsafe { from_raw_parts_mut(attr.rgValue, attr.cValue as _) };

                    for blob in attr_blobs {
                        if unsafe {
                            CryptDecodeObject(
                                ENCODING,
                                PKCS7_SIGNER_INFO,
                                blob.pbData as _,
                                blob.cbData,
                                0,
                                null_mut(),
                                &mut attr_needed,
                            ) == 0
                        } {
                            break;
                        }

                        let mut timestamp_data = vec![0u8; attr_needed as _];

                        if unsafe {
                            CryptDecodeObject(
                                ENCODING,
                                PKCS7_SIGNER_INFO,
                                blob.pbData as _,
                                blob.cbData,
                                timestamp_data.len() as _,
                                timestamp_data.as_mut_ptr() as _,
                                &mut attr_needed,
                            ) == 0
                        } {}

                        let mut timestamp: CMSG_SIGNER_INFO =
                            unsafe { read(timestamp_data.as_mut_ptr() as _) };

                        if let Ok(cert_data) = self.cert_data(h_store, &mut timestamp) {
                            self.timestamp_serial_number = cert_data.serial_number;
                            self.timestamp_subject_name = cert_data.subject_name;
                            self.timestamp_issuer_name = cert_data.issuer_name;
                        }
                    }
                }
            }
        }
    }

    fn release_catalog_enum(admin_context: *mut c_void, catalog: *mut c_void) {
        unsafe {
            CryptCATAdminReleaseCatalogContext(admin_context, catalog, 0);
            CryptCATAdminReleaseContext(admin_context, 0);
        }
    }

    fn release_embebed_cert(store: *mut c_void, msg: *mut c_void) {
        if !store.is_null() {
            unsafe {
                CertCloseStore(store, 0);
            }
        }
        if !msg.is_null() {
            unsafe {
                CryptMsgClose(store);
            }
        }
    }
}
