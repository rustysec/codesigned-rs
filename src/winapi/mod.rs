mod constants;

extern crate widestring;

use std::mem::{ size_of };
use std::ptr::{null, null_mut};
use std::slice::from_raw_parts_mut;
use std::string::ToString;
use widestring::WideCString;

pub use self::constants::*;

#[repr(C)]
#[derive(Debug)]
pub struct CryptoAttribute {
    pub obj_id: *const u8,
    pub c_value: u32,
    pub rg_value: *const CryptoApiBlob,
}

#[repr(C)]
#[derive(Debug)]
pub struct CryptoAttributes {
    pub c_attr: u32,
    pub rg_attr: *const CryptoAttribute,
}

#[repr(C)]
#[derive(Debug)]
pub struct CryptoAlgorithmIdentifier {
    pub obj_id: *const u8,
    pub parameters: CryptoApiBlob,
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct CryptoApiBlob {
    pub len: u32,
    pub data: *mut u8,
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct CryptoApiSerialNumberBlob {
    pub len: u32,
    pub data: *mut u8,
}

impl ToString for CryptoApiSerialNumberBlob {
    fn to_string(&self) -> String {
        match self.len {
            0 => "".to_owned(),
            _ => {
                let x = unsafe { from_raw_parts_mut(self.data, self.len as usize) };
                x.reverse();
                let x: Vec<String> = x.iter().map(|i| {
                    format!("{:02x}", i)
                }).collect();
                x.join("").to_owned()
            }
        }
    }
}

impl ToString for CryptoApiBlob {
    fn to_string(&self) -> String {
        let derp = self.clone();
        let string_len = unsafe {
            CertNameToStrA(X509_ASN_ENCODING, &derp as *const _, CERT_SIMPLE_NAME_STR | CERT_NAME_STR_REVERSE_FLAG, null_mut(), 0)
        };

        let mut data: Vec<u8> = vec![0; string_len as usize];
        unsafe {
            CertNameToStrA(X509_ASN_ENCODING, &derp as *const _, CERT_SIMPLE_NAME_STR | CERT_NAME_STR_REVERSE_FLAG, data.as_mut_ptr(), self.len);
        }

        String::from_utf8(data[0..data.len()-1].to_vec()).unwrap_or("(unknown)".to_owned())
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct MsgSignerInfo {
    pub version: u32,
    pub issuer: CryptoApiBlob,
    pub serial_number: CryptoApiSerialNumberBlob,
    pub hash_algorithm: CryptoAlgorithmIdentifier,
    pub hash_encryption_algorithm: CryptoAlgorithmIdentifier,
    pub encrypted_hash: CryptoApiBlob,
    pub auth_attrs: CryptoAttributes,
    pub unauth_attrs: CryptoAttributes,
}

impl MsgSignerInfo {
}

#[repr(C)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    pub fn wintrust_action_generic_verify_v2() -> Guid {
        Guid {
            data1: 0xaac56b,
            data2: 0xcd44,
            data3: 0x11d0,
            data4: [0x8c,0xc2,0x00,0xc0,0x4f,0xc2,0x95,0xee]
        }
    }

    pub fn driver_action_verify() -> Guid {
        Guid {
            data1: 0xf750e6c3,
            data2: 0x38ee,
            data3: 0x11d1,
            data4: [0x85,0xe5,0x00,0xc0,0x4f,0xc2,0x95,0xee]
        }
    }
}

#[repr(C)]
pub struct WinTrustFileInfo
{
    pub size: u32,
    pub file_path: *const u16,
    pub file_handle: *const u8,
    pub known_subject_guid: *const Guid,
}

impl Default for WinTrustFileInfo {
    fn default() -> WinTrustFileInfo {
        WinTrustFileInfo {
            size: size_of::<WinTrustFileInfo>() as u32,
            file_path: null(),
            file_handle: null(),
            known_subject_guid: null(),
        }
    }
}

impl WinTrustFileInfo {
    pub fn from_path(path: &WideCString) -> WinTrustFileInfo {
        let mut wtfi = WinTrustFileInfo::default();
        wtfi.file_path = path.as_ptr();
        wtfi
    }
}

#[repr(C)]
pub struct WinTrustData
{
    pub size: u32,
    pub policy_callback_data: *const u8,
    pub sip_client_data: *const u8,
    pub ui_choice: u32,
    pub revocation_check: u32,
    pub union_choice: u32,
    pub data: *const WinTrustFileInfo,
    pub state_action: u32,
    pub wvt_state_data: *const u8,
    pub url_reference: *const u16,
    pub prov_flags: u32,
    pub ui_context: u32,
    pub signature_settings: *const u8,
}

impl Default for WinTrustData {
    fn default() -> WinTrustData {
        WinTrustData {
            size: size_of::<WinTrustData>() as u32,
            policy_callback_data: null(),
            sip_client_data: null(),
            ui_choice: WTD_UI_NONE,
            revocation_check: WTD_REVOKE_NONE,
            union_choice: WTD_CHOICE_FILE,
            data: null(),
            state_action: WTD_STATEACTION_VERIFY,
            wvt_state_data: null(),
            url_reference: null(),
            prov_flags: WTD_CACHE_ONLY_URL_RETRIEVAL,
            ui_context: 0,
            signature_settings: null(),
        }
    }
}

pub struct FileHandle {
    handle: Option<*const u8>,
    path: Option<String>,
}

impl FileHandle {
    pub fn new() -> FileHandle {
        FileHandle {
            handle: None,
            path: None
        }
    }

    pub fn handle(&self) -> Option<*const u8> {
        self.handle
    }

    pub fn open_file(&mut self, path: &WideCString) {
        match unsafe {
            CreateFileW(path.as_ptr(), GENERIC_READ, FILE_SHARE_READ, null(), OPEN_EXISTING, 0, null())
        } {
            i if i as usize == 0 => println!("nope!"),
            f => {
                self.handle = Some(f);
                if let Ok(p) = path.to_string() {
                    self.path = Some(p)
                }
            }
        }
    }

    pub fn with_file(mut self, path: &WideCString) -> Self {
        self.open_file(&path);
        self
    }
}

impl Drop for FileHandle {
    fn drop(&mut self) {
        if let Some(ref p) = self.path {
            println!("Dropping handle to {}", p);
        }
        if let Some(ref h) = self.handle {
            unsafe { CloseHandle(*h); }
        }
    }
}

#[repr(C)]
pub struct CatalogInfo
{
    pub size: u32,
    pub catalog_file: [u16; MAX_PATH],
}

impl Default for CatalogInfo {
    fn default() -> CatalogInfo {
        CatalogInfo {
            size: size_of::<CatalogInfo>() as u32,
            catalog_file: [0; MAX_PATH],
        }
    }
}

#[link(name = "crypt32")]
extern "system" {
    pub fn CryptQueryObject(
        object_type: u32,
        object: *const u8,
        expected_content_type_flags: u32,
        expected_format_type_flags: u32,
        flags: u32,
        msg_and_cert_encoding_type: *mut u32,
        content_type: *mut u32,
        format_type: *mut u32,
        cert_store: *mut *mut u8,
        msg: *mut *mut u8,
        context: *mut *mut u8,
    ) -> u32;

    pub fn CryptMsgGetParam(
        crypt_msg: *const u8,
        param_type: u32,
        index: u32,
        data: *mut u8,
        data_len: *mut u32
    ) -> u32;

    pub fn CertNameToStrA(
        cert_encoding_type: u32,
        name: *const CryptoApiBlob,
        str_type: u32,
        psz: *mut u8,
        csz: u32
    ) -> u32;

    pub fn CryptCATAdminAcquireContext(
        admin: *mut *mut u8,
        action: *const Guid,
        _: u32
    ) -> u32;

    pub fn CryptCATAdminCalcHashFromFileHandle(
        handle: *const u8,
        hash_length: &mut u32,
        hash: *mut u8,
        flags: u32
    ) -> u32;

    pub fn CryptCATAdminEnumCatalogFromHash(
        cat_admin: *const u8,
        hash: *const u8,
        hash_lenght: u32,
        flags: u32,
        prev_cat_info: *mut *mut u8,
    ) -> *mut u8;

    pub fn CryptCATAdminReleaseCatalogContext(
        admin: *mut u8,
        info: *mut u8,
        flags: u32
    ) -> u32;

    pub fn CryptCATCatalogInfoFromContext(
        info_context: *const u8,
        info: *mut CatalogInfo,
        flags: u32
    ) -> u32;
}

#[link(name = "wintrust")]
extern "system" {
    pub fn WinVerifyTrust(
        wnd: *const u8,
        action_id: *const Guid,
        wvt_data: *const WinTrustData
    ) -> u32;
}

extern "system" {
    pub fn CloseHandle(handle: *const u8) -> u32;

    pub fn CreateFileW(
        file_name: *const u16,
        desired_access: u32,
        share_mode: u32,
        security_attributes: *const u8,
        creation_disposition: u32,
        flags_and_attributes: u32,
        template_file: *const u8,
    ) -> *const u8;
}
