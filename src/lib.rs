#[macro_use]
extern crate log;

mod winapi;

extern crate widestring;

use std::ptr::{null_mut, null, read};
use widestring::WideCString;
use winapi::*;

#[derive(Clone,Default,Debug)]
pub struct CodeSigned {
    pub path: String,
    pub signed: Option<bool>,
    pub catalog: bool,
    pub issuer_name: String,
    pub subject_name: String,
    pub timestamp_issuer_name: String,
    pub timestamp_subject_name: String,
    pub serial_number: String,
}

impl CodeSigned {
    pub fn file(&mut self, path: &str) {
        self.path = path.to_owned();
        if let Ok(path) = WideCString::from_str(path) {
            let mut file_info = WinTrustFileInfo::from_path(&path);
            let mut win_trust_data = WinTrustData::default();
            win_trust_data.data = &mut file_info;

            let action = Guid::wintrust_action_generic_verify_v2();
            match unsafe {
                WinVerifyTrust(null(), &action, &win_trust_data)
            } {
                0 => self.embedded(&path),
                _ => self.catalog(&path)
            }

            win_trust_data.state_action = WTD_STATEACTION_CLOSE;
            unsafe { WinVerifyTrust(null(), &action, &win_trust_data); }
        }
    }

    fn embedded(&mut self, path: &WideCString) {
        let mut encoding: u32 = 0;
        let mut content_type: u32 = 0;
        let mut format_type: u32 = 0;
        let mut h_store: *mut u8 = null_mut();
        let mut h_msg: *mut u8 = null_mut();


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
                null_mut()
            )
        } {
            0 => { /* error */ },
            _ => {
                let mut data_len: u32 = 0;
                unsafe {
                    CryptMsgGetParam(
                        h_msg,
                        CMSG_SIGNER_INFO_PARAM,
                        0,
                        null_mut(),
                        &mut data_len
                    );
                }

                let mut data: Vec<u8> = vec![0; data_len as usize];
                match unsafe {
                    CryptMsgGetParam(
                        h_msg,
                        CMSG_SIGNER_INFO_PARAM,
                        0,
                        data.as_mut_ptr(),
                        &mut data_len
                    )
                } {
                    0 => { /* error */ },
                    _ => {
                        let msg: MsgSignerInfo = unsafe {
                            read(data.as_mut_ptr() as *const _)
                        };

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
                                null()
                            )
                        });

                        let mut needed: u32 = unsafe {
                            CertGetNameStringA(
                                context.context(),
                                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                0,
                                null(),
                                null(),
                                0
                            )
                        };
                        let mut subject_name_data: Vec<u8> = vec![0; needed as usize];
                        unsafe {
                            CertGetNameStringA(
                                context.context(),
                                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                0,
                                null(),
                                subject_name_data.as_mut_ptr(),
                                needed as u32
                            );
                        }

                        self.serial_number = msg.serial_number.to_string();
                        self.issuer_name = msg.issuer.to_string();
                        self.subject_name = String::from_utf8((&subject_name_data[0..needed as usize -1]).to_vec()).unwrap_or("(unknown)".to_owned());
                        self.signed = Some(true);
                        unsafe {
                            CryptMsgClose(h_msg);
                            CertCloseStore(h_store, 2);
                        }
                    }
                }
            }
        }
    }

    fn catalog(&mut self, path: &WideCString) {
        let f = FileHandle::new().with_file(&path);
        if let Some(handle) = f.handle() {
            let mut hash_length: u32 = 0;
            match unsafe {
                CryptCATAdminCalcHashFromFileHandle(
                    handle,
                    &mut hash_length,
                    null_mut(),
                    0
                )
            } {
                0 => warn!("Could not obtain file hash for {}", path.to_string_lossy()),
                _ => {
                    self.signed = Some(false);
                    let mut hash_data: Vec<u8> = vec![0; hash_length as usize];
                    unsafe {
                        CryptCATAdminCalcHashFromFileHandle(
                            handle,
                            &mut hash_length,
                            hash_data.as_mut_ptr(),
                            0
                        );
                    }

                    let driver_action = Guid::driver_action_verify();
                    let mut admin_context: *mut u8 = null_mut();
                    if unsafe { CryptCATAdminAcquireContext(&mut admin_context, &driver_action, 0) } == 0 {
                        /* error? */
                        return;
                    }

                    let mut cat = unsafe { CryptCATAdminEnumCatalogFromHash(admin_context, hash_data.as_ptr(), hash_length, 0, null_mut()) };
                    loop {
                        let mut cat_info = CatalogInfo::default();
                        if 0 == unsafe { CryptCATCatalogInfoFromContext(cat, &mut cat_info, 0) } {
                            /* out of catalogs */
                            break;
                        }
                        let cat_path = unsafe { WideCString::from_ptr_str(&cat_info.catalog_file as *const u16) };
                        self.catalog = true;
                        self.embedded(&cat_path);
                        cat = unsafe { CryptCATAdminEnumCatalogFromHash(admin_context, hash_data.as_ptr(), hash_length, 0, &mut cat) };
                        if cat == null_mut() { break; }
                    }

                    unsafe {
                        CryptCATAdminReleaseCatalogContext(admin_context, cat, 0);
                        CryptCATAdminReleaseContext(admin_context, 0);
                    }
                }
            }
        }
    }
}