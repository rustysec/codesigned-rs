#![cfg(target_os = "windows")]

#[macro_use]
extern crate log;

mod api;
mod error;

use api::*;
use std::ptr::{null, null_mut, read};
use widestring::U16CString;
use winapi::ctypes::c_void;

/// Result of code signing operations
type Result<T> = std::result::Result<T, error::Error>;

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
    pub fn open<P: AsRef<std::path::Path>>(&mut self, path: P) {
        path.as_ref().to_str().and_then(|path_str| {
            U16CString::from_str(path_str).ok().map(|path| {
                let mut file_info = WinTrustFileInfo::from_path(&path);
                let mut win_trust_data = WinTrustData::default();
                win_trust_data.data = &mut file_info;

                let action = Guid::wintrust_action_generic_verify_v2();
                match unsafe { WinVerifyTrust(null(), &action, &win_trust_data) } {
                    0 => self.embedded(&path),
                    _ => self.catalog(&path),
                }

                win_trust_data.state_action = WTD_STATEACTION_CLOSE;
                unsafe {
                    WinVerifyTrust(null(), &action, &win_trust_data);
                }
            })
        });
    }

    /// Determines if the file is signed
    pub fn signed(&self) -> bool {
        self.signature_type != SignatureType::NotSigned
    }

    fn embedded(&mut self, path: &U16CString) {
        let mut encoding: u32 = 0;
        let mut content_type: u32 = 0;
        let mut format_type: u32 = 0;
        let mut h_store: *mut c_void = null_mut();
        let mut h_msg: *mut c_void = null_mut();

        match unsafe {
            CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                path.as_ptr() as *const _,
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                CERT_QUERY_FORMAT_FLAG_BINARY,
                0,
                &mut encoding,
                &mut content_type,
                &mut format_type,
                &mut h_store,
                &mut h_msg,
                null_mut(),
            )
        } {
            0 => { /* error */ }
            _ => {
                let mut data_len: u32 = 0;
                unsafe {
                    CryptMsgGetParam(h_msg, CMSG_SIGNER_INFO_PARAM, 0, null_mut(), &mut data_len);
                }

                let mut data: Vec<u8> = vec![0; data_len as usize];
                match unsafe {
                    CryptMsgGetParam(
                        h_msg,
                        CMSG_SIGNER_INFO_PARAM,
                        0,
                        data.as_mut_ptr(),
                        &mut data_len,
                    )
                } {
                    0 => { /* error */ }
                    _ => {
                        let msg: MsgSignerInfo = unsafe { read(data.as_mut_ptr() as *const _) };

                        let mut cert_info = CertInfo::default();
                        cert_info.serial_number.from(&msg.serial_number);
                        cert_info.issuer.from(&msg.issuer);

                        let context = CertStoreContext::new(unsafe {
                            CertFindCertificateInStore(
                                h_store,
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

                        self.serial_number = Some(msg.serial_number.to_string());
                        self.issuer_name = Some(msg.issuer.to_string());
                        self.subject_name = String::from_utf8(
                            (&subject_name_data[0..needed as usize - 1]).to_vec(),
                        )
                        .ok();
                        self.signature_type = SignatureType::Embedded;

                        unsafe {
                            CryptMsgClose(h_msg);
                            CertCloseStore(h_store, 2);
                        }
                    }
                }
            }
        }
    }

    fn catalog(&mut self, path: &U16CString) {
        let f = FileHandle::new().with_file(&path);
        if let Some(handle) = f.handle() {
            let mut hash_length: u32 = 0;
            match unsafe {
                CryptCATAdminCalcHashFromFileHandle(handle, &mut hash_length, null_mut(), 0)
            } {
                0 => warn!("Could not obtain file hash for {}", path.to_string_lossy()),
                _ => {
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
                    let mut admin_context: *mut c_void = null_mut();
                    if unsafe { CryptCATAdminAcquireContext(&mut admin_context, &driver_action, 0) }
                        == 0
                    {
                        /* error? */
                        return;
                    }

                    let mut cat = unsafe {
                        CryptCATAdminEnumCatalogFromHash(
                            admin_context,
                            hash_data.as_ptr() as _,
                            hash_length,
                            0,
                            null_mut(),
                        )
                    };
                    loop {
                        let mut cat_info = CatalogInfo::default();
                        if 0 == unsafe {
                            CryptCATCatalogInfoFromContext(cat as _, &mut cat_info, 0)
                        } {
                            /* out of catalogs */
                            break;
                        }
                        let cat_path = unsafe {
                            U16CString::from_ptr_str(&cat_info.catalog_file as *const u16)
                        };
                        self.signature_type = SignatureType::Catalog;
                        self.embedded(&cat_path);
                        cat = unsafe {
                            CryptCATAdminEnumCatalogFromHash(
                                admin_context,
                                hash_data.as_ptr() as _,
                                hash_length,
                                0,
                                &mut cat as *mut _ as *mut _,
                            )
                        };
                        if cat.is_null() {
                            break;
                        }
                    }

                    unsafe {
                        CryptCATAdminReleaseCatalogContext(admin_context as _, cat, 0);
                        CryptCATAdminReleaseContext(admin_context, 0);
                    }
                }
            }
        }
    }
}
