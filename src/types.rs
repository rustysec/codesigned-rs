use crate::{
    api::{GUID, _CRYPTOAPI_BLOB},
    error::Error,
};
use std::{
    mem::size_of,
    ptr::{null, null_mut},
    slice::from_raw_parts_mut,
};
use winapi::{
    shared::ntdef::LPCWSTR,
    um::{
        handleapi::CloseHandle,
        wincrypt::{
            CertNameToStrA, CERT_NAME_STR_REVERSE_FLAG, CERT_SIMPLE_NAME_STR, CRYPTOAPI_BLOB,
            PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
        },
        wintrust::WINTRUST_FILE_INFO,
    },
};

/// Result of code signing operations
pub type Result<T> = std::result::Result<T, Error>;

pub struct WinTrustFileInfo(pub WINTRUST_FILE_INFO);

pub const ENCODING: u32 = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

pub fn wintrust_action_generic_verify_v2() -> GUID {
    GUID {
        Data1: 0xaa_c56b,
        Data2: 0xcd44,
        Data3: 0x11d0,
        Data4: [0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee],
    }
}

pub fn driver_action_verify() -> GUID {
    GUID {
        Data1: 0xf750_e6c3,
        Data2: 0x38ee,
        Data3: 0x11d1,
        Data4: [0x85, 0xe5, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee],
    }
}

pub trait BlobToString {
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
                .iter_mut()
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

pub fn wintrust_file_info(path: LPCWSTR) -> Result<WinTrustFileInfo> {
    Ok(WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as _,
        pcwszFilePath: path,
        hFile: null_mut(),
        pgKnownSubject: null(),
    }
    .into())
}

impl From<WINTRUST_FILE_INFO> for WinTrustFileInfo {
    fn from(file_info: WINTRUST_FILE_INFO) -> Self {
        Self(file_info)
    }
}

impl Drop for WinTrustFileInfo {
    fn drop(&mut self) {
        if !self.0.hFile.is_null() {
            unsafe {
                CloseHandle(self.0.hFile);
            }
        }
    }
}
