mod constants;
mod oids;

pub use self::constants::*;
pub use self::oids::*;
use crate::{Error, Result};
use cellophane::{
    CryptCATAdminReleaseCatalogContextWrapper, CryptCATAdminReleaseContextWrapper, HasPointer,
};
use std::mem::size_of;
use std::ptr::{null, null_mut};
use std::slice::from_raw_parts_mut;
use std::string::ToString;
use widestring::WideCString;
use winapi::{ctypes::c_void, shared::minwindef::DWORD};

#[repr(C)]
#[derive(Debug, Clone)]
pub struct CryptoAttribute {
    pub obj_id: *const c_void,
    pub c_value: u32,
    pub rg_value: *const CryptoApiBlob,
}

impl Default for CryptoAttribute {
    fn default() -> CryptoAttribute {
        CryptoAttribute {
            obj_id: null(),
            c_value: 0,
            rg_value: null(),
        }
    }
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

impl Default for CryptoAlgorithmIdentifier {
    fn default() -> CryptoAlgorithmIdentifier {
        CryptoAlgorithmIdentifier {
            obj_id: null(),
            parameters: Default::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct CryptoApiBlob {
    pub len: u32,
    pub data: *mut u8,
}

impl CryptoApiBlob {
    pub fn from(&mut self, blob: &CryptoApiBlob) {
        self.len = blob.len;
        self.data = blob.data;
    }
}

impl ToString for CryptoApiBlob {
    fn to_string(&self) -> String {
        let this = self.clone();
        let string_len = unsafe {
            CertNameToStrA(
                X509_ASN_ENCODING,
                &this as *const _,
                CERT_SIMPLE_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
                null_mut(),
                0,
            )
        };

        let mut data: Vec<u8> = vec![0; string_len as usize];
        unsafe {
            CertNameToStrA(
                X509_ASN_ENCODING,
                &this as *const _,
                CERT_SIMPLE_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
                data.as_mut_ptr() as _,
                self.len,
            );
        }

        String::from_utf8(data[0..data.len() - 1].to_vec())
            .unwrap_or_else(|_| String::from("(unknown)"))
    }
}

impl Default for CryptoApiBlob {
    fn default() -> CryptoApiBlob {
        CryptoApiBlob {
            len: 0,
            data: null_mut(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct CryptoApiSerialNumberBlob {
    pub len: u32,
    pub data: *mut u8,
}

impl Default for CryptoApiSerialNumberBlob {
    fn default() -> CryptoApiSerialNumberBlob {
        CryptoApiSerialNumberBlob {
            len: 0,
            data: null_mut(),
        }
    }
}

impl CryptoApiSerialNumberBlob {
    pub fn from(&mut self, blob: &CryptoApiSerialNumberBlob) {
        self.len = blob.len;
        self.data = blob.data;
    }
}

impl ToString for CryptoApiSerialNumberBlob {
    fn to_string(&self) -> String {
        match self.len {
            0 => "".to_owned(),
            _ => {
                let x = unsafe { from_raw_parts_mut(self.data, self.len as usize) };
                x.reverse();
                let x: Vec<String> = x.iter().map(|i| format!("{:02x}", i)).collect();
                x.join("")
            }
        }
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

impl MsgSignerInfo {}

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
            data1: 0xaa_c56b,
            data2: 0xcd44,
            data3: 0x11d0,
            data4: [0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee],
        }
    }

    pub fn driver_action_verify() -> Guid {
        Guid {
            data1: 0xf750_e6c3,
            data2: 0x38ee,
            data3: 0x11d1,
            data4: [0x85, 0xe5, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee],
        }
    }
}

#[repr(C)]
pub struct WinTrustFileInfo {
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
pub struct WinTrustData {
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
    handle: Option<*const c_void>,
    path: Option<String>,
}

impl FileHandle {
    pub fn new() -> FileHandle {
        FileHandle {
            handle: None,
            path: None,
        }
    }

    pub fn handle(&self) -> Option<*const c_void> {
        self.handle
    }

    pub fn open_file(&mut self, path: &WideCString) -> Result<()> {
        match unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ,
                null(),
                OPEN_EXISTING,
                0,
                null(),
            )
        } {
            i if i as usize == 0 => Err(Error::OpenFileFailed),
            f => {
                self.handle = Some(f);
                if let Ok(p) = path.to_string() {
                    self.path = Some(p)
                }
                Ok(())
            }
        }
    }

    pub fn with_file(mut self, path: &WideCString) -> Result<Self> {
        self.open_file(&path)?;
        Ok(self)
    }
}

impl Drop for FileHandle {
    fn drop(&mut self) {
        if let Some(ref h) = self.handle {
            unsafe {
                CloseHandle(*h);
            }
        }
    }
}

#[repr(C)]
pub struct CatalogInfo {
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

#[repr(C)]
#[derive(Debug, Default)]
pub struct FileTime {
    u1: u32,
    u2: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct CryptoBitBlob {
    pub size: u32,
    pub data: *const c_void,
    pub unused_bits: u32,
}

impl Default for CryptoBitBlob {
    fn default() -> CryptoBitBlob {
        CryptoBitBlob {
            size: 0,
            data: null(),
            unused_bits: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct CertPublicKeyInfo {
    pub algorithm: CryptoAlgorithmIdentifier,
    pub public_key: CryptoBitBlob,
}

#[repr(C)]
#[derive(Debug)]
pub struct CertInfo {
    pub version: u32,
    pub serial_number: CryptoApiSerialNumberBlob,
    pub signature_algorithm: CryptoAlgorithmIdentifier,
    pub issuer: CryptoApiBlob,
    pub not_before: FileTime,
    pub not_after: FileTime,
    pub subject: CryptoApiBlob,
    pub subject_public_key_info: CertPublicKeyInfo,
    pub issuer_unique_id: CryptoBitBlob,
    pub subject_unique_id: CryptoBitBlob,
    pub c_extension: u32,
    pub rg_extension: *const c_void,
}

impl Default for CertInfo {
    fn default() -> CertInfo {
        CertInfo {
            version: 0,
            serial_number: Default::default(),
            signature_algorithm: Default::default(),
            issuer: Default::default(),
            not_before: Default::default(),
            not_after: Default::default(),
            subject: Default::default(),
            subject_public_key_info: Default::default(),
            issuer_unique_id: Default::default(),
            subject_unique_id: Default::default(),
            c_extension: 0,
            rg_extension: null(),
        }
    }
}

pub struct CertStoreContext {
    context: Option<*const c_void>,
}

impl CertStoreContext {
    pub fn new(ctx: *const c_void) -> CertStoreContext {
        match ctx {
            i if i as usize == 0 => CertStoreContext { context: None },
            _ => CertStoreContext { context: Some(ctx) },
        }
    }

    pub fn context(&self) -> *const c_void {
        match self.context {
            Some(ctx) => ctx,
            None => null(),
        }
    }
}

impl Drop for CertStoreContext {
    fn drop(&mut self) {
        if let Some(ctx) = self.context {
            unsafe {
                CertFreeCertificateContext(ctx);
            }
        }
    }
}

/// Warpper around AdminCatalog
pub(crate) struct AdminCatalog<'ctx> {
    catalog: CryptCATAdminReleaseCatalogContextWrapper<'ctx>,
}

impl<'ctx> AdminCatalog<'ctx> {
    pub fn new(
        admin_context: &'ctx CryptCATAdminReleaseContextWrapper,
        hash_data: *const u8,
        hash_length: DWORD,
    ) -> Self {
        Self {
            catalog: CryptCATAdminReleaseCatalogContextWrapper::new(
                unsafe {
                    CryptCATAdminEnumCatalogFromHash(
                        admin_context.ptr(),
                        hash_data as _,
                        hash_length,
                        0,
                        null_mut(),
                    )
                },
                admin_context,
            ),
        }
    }

    pub fn ptr(&self) -> *const c_void {
        self.catalog.ptr()
    }

    pub fn is_null(&self) -> bool {
        self.catalog.ptr().is_null()
    }
}

#[link(name = "crypt32")]
extern "system" {
    pub fn CryptQueryObject(
        object_type: DWORD,
        object: *const c_void,
        expected_content_type_flags: DWORD,
        expected_format_type_flags: DWORD,
        flags: DWORD,
        msg_and_cert_encoding_type: *mut DWORD,
        content_type: *mut DWORD,
        format_type: *mut DWORD,
        cert_store: *mut *mut c_void,
        msg: *mut *mut c_void,
        context: *mut *mut c_void,
    ) -> DWORD;

    pub fn CryptMsgGetParam(
        crypt_msg: *const c_void,
        param_type: DWORD,
        index: DWORD,
        data: *mut c_void,
        data_len: *mut DWORD,
    ) -> DWORD;

    pub fn CertNameToStrA(
        cert_encoding_type: DWORD,
        name: *const CryptoApiBlob,
        str_type: DWORD,
        psz: *mut c_void,
        csz: DWORD,
    ) -> DWORD;

    pub fn CryptCATAdminAcquireContext(
        admin: *mut *mut c_void,
        action: *const Guid,
        _: DWORD,
    ) -> DWORD;

    pub fn CryptCATAdminCalcHashFromFileHandle(
        handle: *const c_void,
        hash_length: &mut DWORD,
        hash: *mut c_void,
        flags: DWORD,
    ) -> DWORD;

    pub fn CryptCATAdminEnumCatalogFromHash(
        cat_admin: *const c_void,
        hash: *const c_void,
        hash_lenght: DWORD,
        flags: DWORD,
        prev_cat_info: *mut *mut c_void,
    ) -> *mut c_void;

    pub fn CryptCATCatalogInfoFromContext(
        info_context: *const c_void,
        info: *mut CatalogInfo,
        flags: u32,
    ) -> u32;

    pub fn CertFindCertificateInStore(
        cert_store: *const c_void,
        cert_encoding_type: DWORD,
        find_flags: DWORD,
        find_type: DWORD,
        find_para: *const CertInfo,
        prev_cert_context: *const c_void,
    ) -> *const c_void;

    pub fn CertGetNameStringA(
        cert_context: *const c_void,
        name_type: DWORD,
        flags: DWORD,
        type_para: *const c_void,
        name_string: *const c_void,
        name_length: DWORD,
    ) -> DWORD;

    pub fn CertFreeCertificateContext(context: *const c_void) -> DWORD;
}

#[link(name = "wintrust")]
extern "system" {
    pub fn WinVerifyTrust(
        wnd: *const c_void,
        action_id: *const Guid,
        wvt_data: *const WinTrustData,
    ) -> DWORD;
}

extern "system" {
    #[allow(dead_code)]
    pub fn GetLastError() -> DWORD;

    pub fn CloseHandle(handle: *const c_void) -> DWORD;

    pub fn CreateFileW(
        file_name: *const u16,
        desired_access: DWORD,
        share_mode: DWORD,
        security_attributes: *const c_void,
        creation_disposition: DWORD,
        flags_and_attributes: DWORD,
        template_file: *const c_void,
    ) -> *const c_void;
}
