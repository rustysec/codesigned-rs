#![allow(dead_code)]
pub const MAX_PATH: usize = 260;

pub const CERT_QUERY_OBJECT_FILE: u32 = 1;
pub const CERT_QUERY_OBJECT_BLOB: u32 = 2;

pub const CERT_COMPARE_SUBJECT_CERT: u32 = 11;
pub const CERT_COMPARE_SHIFT: u32 = 16;
pub const CERT_FIND_SUBJECT_CERT: u32 = CERT_COMPARE_SUBJECT_CERT << CERT_COMPARE_SHIFT;

pub const CERT_NAME_EMAIL_TYPE: u32 = 1;
pub const CERT_NAME_RDN_TYPE: u32 = 2;
pub const CERT_NAME_ATTR_TYPE: u32 = 3;
pub const CERT_NAME_SIMPLE_DISPLAY_TYPE: u32 = 4;
pub const CERT_NAME_FRIENDLY_DISPLAY_TYPE: u32 = 5;
pub const CERT_NAME_DNS_TYPE: u32 = 6;
pub const CERT_NAME_URL_TYPE: u32 = 7;
pub const CERT_NAME_UPN_TYPE: u32 = 8;

pub const CERT_NAME_ISSUER_FLAG: u32 = 0x0000_0001;

pub const CERT_QUERY_CONTENT_CERT: u32 = 1;
pub const CERT_QUERY_CONTENT_CTL: u32 = 2;
pub const CERT_QUERY_CONTENT_CRL: u32 = 3;
pub const CERT_QUERY_CONTENT_SERIALIZED_STORE: u32 = 4;
pub const CERT_QUERY_CONTENT_SERIALIZED_CERT: u32 = 5;
pub const CERT_QUERY_CONTENT_SERIALIZED_CTL: u32 = 6;
pub const CERT_QUERY_CONTENT_SERIALIZED_CRL: u32 = 7;
pub const CERT_QUERY_CONTENT_PKCS7_SIGNED: u32 = 8;
pub const CERT_QUERY_CONTENT_PKCS7_UNSIGNED: u32 = 9;
pub const CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED: u32 = 10;
pub const CERT_QUERY_CONTENT_PKCS10: u32 = 11;
pub const CERT_QUERY_CONTENT_PFX: u32 = 12;
pub const CERT_QUERY_CONTENT_CERT_PAIR: u32 = 13;

pub const CERT_QUERY_CONTENT_FLAG_CERT: u32 = 1 << CERT_QUERY_CONTENT_CERT;
pub const CERT_QUERY_CONTENT_FLAG_CTL: u32 = 1 << CERT_QUERY_CONTENT_CTL;
pub const CERT_QUERY_CONTENT_FLAG_CRL: u32 = 1 << CERT_QUERY_CONTENT_CRL;
pub const CERT_QUERY_CONTENT_FLAG_SERIALIZED_STORE: u32 = 1 << CERT_QUERY_CONTENT_SERIALIZED_STORE;
pub const CERT_QUERY_CONTENT_FLAG_SERIALIZED_CERT: u32 = 1 << CERT_QUERY_CONTENT_SERIALIZED_CERT;
pub const CERT_QUERY_CONTENT_FLAG_SERIALIZED_CTL: u32 = 1 << CERT_QUERY_CONTENT_SERIALIZED_CTL;
pub const CERT_QUERY_CONTENT_FLAG_SERIALIZED_CRL: u32 = 1 << CERT_QUERY_CONTENT_SERIALIZED_CRL;
pub const CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED: u32 = 1 << CERT_QUERY_CONTENT_PKCS7_SIGNED;
pub const CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED: u32 = 1 << CERT_QUERY_CONTENT_PKCS7_UNSIGNED;
pub const CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED: u32 =
    1 << CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED;
pub const CERT_QUERY_CONTENT_FLAG_PKCS10: u32 = 1 << CERT_QUERY_CONTENT_PKCS10;
pub const CERT_QUERY_CONTENT_FLAG_PFX: u32 = 1 << CERT_QUERY_CONTENT_PFX;
pub const CERT_QUERY_CONTENT_FLAG_CERT_PAIR: u32 = 1 << CERT_QUERY_CONTENT_CERT_PAIR;

pub const CERT_QUERY_CONTENT_FLAG_ALL: u32 = CERT_QUERY_CONTENT_FLAG_CERT
    | CERT_QUERY_CONTENT_FLAG_CTL
    | CERT_QUERY_CONTENT_FLAG_CRL
    | CERT_QUERY_CONTENT_FLAG_SERIALIZED_STORE
    | CERT_QUERY_CONTENT_FLAG_SERIALIZED_CERT
    | CERT_QUERY_CONTENT_FLAG_SERIALIZED_CTL
    | CERT_QUERY_CONTENT_FLAG_SERIALIZED_CRL
    | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED
    | CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED
    | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED
    | CERT_QUERY_CONTENT_FLAG_PKCS10
    | CERT_QUERY_CONTENT_FLAG_PFX
    | CERT_QUERY_CONTENT_FLAG_CERT_PAIR;

pub const CERT_QUERY_FORMAT_BINARY: u32 = 1;
pub const CERT_QUERY_FORMAT_BASE64_ENCODED: u32 = 2;
pub const CERT_QUERY_FORMAT_ASN_ASCII_HEX_ENCODED: u32 = 3;

pub const CERT_QUERY_FORMAT_FLAG_BINARY: u32 = 1 << CERT_QUERY_FORMAT_BINARY;
pub const CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED: u32 = 1 << CERT_QUERY_FORMAT_BASE64_ENCODED;
pub const CERT_QUERY_FORMAT_FLAG_ASN_ASCII_HEX_ENCODED: u32 =
    1 << CERT_QUERY_FORMAT_ASN_ASCII_HEX_ENCODED;

pub const CMSG_TYPE_PARAM: u32 = 1;
pub const CMSG_CONTENT_PARAM: u32 = 2;
pub const CMSG_BARE_CONTENT_PARAM: u32 = 3;
pub const CMSG_INNER_CONTENT_TYPE_PARAM: u32 = 4;
pub const CMSG_SIGNER_COUNT_PARAM: u32 = 5;
pub const CMSG_SIGNER_INFO_PARAM: u32 = 6;
pub const CMSG_SIGNER_CERT_INFO_PARAM: u32 = 7;
pub const CMSG_SIGNER_HASH_ALGORITHM_PARAM: u32 = 8;
pub const CMSG_SIGNER_AUTH_ATTR_PARAM: u32 = 9;
pub const CMSG_SIGNER_UNAUTH_ATTR_PARAM: u32 = 10;
pub const CMSG_CERT_COUNT_PARAM: u32 = 11;
pub const CMSG_CERT_PARAM: u32 = 12;
pub const CMSG_CRL_COUNT_PARAM: u32 = 13;
pub const CMSG_CRL_PARAM: u32 = 14;
pub const CMSG_ENVELOPE_ALGORITHM_PARAM: u32 = 15;
pub const CMSG_RECIPIENT_COUNT_PARAM: u32 = 17;
pub const CMSG_RECIPIENT_INDEX_PARAM: u32 = 18;
pub const CMSG_RECIPIENT_INFO_PARAM: u32 = 19;
pub const CMSG_HASH_ALGORITHM_PARAM: u32 = 20;
pub const CMSG_HASH_DATA_PARAM: u32 = 21;
pub const CMSG_COMPUTED_HASH_PARAM: u32 = 22;
pub const CMSG_ENCRYPT_PARAM: u32 = 26;
pub const CMSG_ENCRYPTED_DIGEST: u32 = 27;
pub const CMSG_ENCODED_SIGNER: u32 = 28;
pub const CMSG_ENCODED_MESSAGE: u32 = 29;
pub const CMSG_VERSION_PARAM: u32 = 30;
pub const CMSG_ATTR_CERT_COUNT_PARAM: u32 = 31;
pub const CMSG_ATTR_CERT_PARAM: u32 = 32;
pub const CMSG_CMS_RECIPIENT_COUNT_PARAM: u32 = 33;
pub const CMSG_CMS_RECIPIENT_INDEX_PARAM: u32 = 34;
pub const CMSG_CMS_RECIPIENT_ENCRYPTED_KEY_INDEX_PARAM: u32 = 35;
pub const CMSG_CMS_RECIPIENT_INFO_PARAM: u32 = 36;
pub const CMSG_UNPROTECTED_ATTR_PARAM: u32 = 37;
pub const CMSG_SIGNER_CERT_ID_PARAM: u32 = 38;
pub const CMSG_CMS_SIGNER_INFO_PARAM: u32 = 39;

pub const CRYPT_ASN_ENCODING: u32 = 0x0000_0001;
pub const CRYPT_NDR_ENCODING: u32 = 0x0000_0002;
pub const X509_ASN_ENCODING: u32 = 0x0000_0001;
pub const X509_NDR_ENCODING: u32 = 0x0000_0002;
pub const PKCS_7_ASN_ENCODING: u32 = 0x0001_0000;
pub const PKCS_7_NDR_ENCODING: u32 = 0x0002_0000;
pub const ENCODING: u32 = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

pub const CERT_SIMPLE_NAME_STR: u32 = 1;
pub const CERT_OID_NAME_STR: u32 = 2;
pub const CERT_X500_NAME_STR: u32 = 3;
pub const CERT_NAME_STR_SEMICOLON_FLAG: u32 = 0x4000_0000;
pub const CERT_NAME_STR_NO_PLUS_FLAG: u32 = 0x2000_0000;
pub const CERT_NAME_STR_NO_QUOTING_FLAG: u32 = 0x1000_0000;
pub const CERT_NAME_STR_CRLF_FLAG: u32 = 0x0800_0000;
pub const CERT_NAME_STR_COMMA_FLAG: u32 = 0x0400_0000;
pub const CERT_NAME_STR_REVERSE_FLAG: u32 = 0x0200_0000;
pub const CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAG: u32 = 0x0004_0000;
pub const CERT_NAME_STR_ENABLE_T61_UNICODE_FLAG: u32 = 0x0002_0000;
pub const CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG: u32 = 0x0001_0000;

pub const WTD_UI_ALL: u32 = 1;
pub const WTD_UI_NONE: u32 = 2;
pub const WTD_UI_NOBAD: u32 = 3;
pub const WTD_UI_NOGOOD: u32 = 4;
pub const WTD_REVOKE_NONE: u32 = 0;
pub const WTD_REVOKE_WHOLECHAIN: u32 = 1;
pub const WTD_CHOICE_FILE: u32 = 1;
pub const WTD_CHOICE_CATALOG: u32 = 2;
pub const WTD_CHOICE_BLOB: u32 = 3;
pub const WTD_CHOICE_SIGNER: u32 = 4;
pub const WTD_CHOICE_CERT: u32 = 5;

pub const WTD_STATEACTION_IGNORE: u32 = 0;
pub const WTD_STATEACTION_VERIFY: u32 = 1;
pub const WTD_STATEACTION_CLOSE: u32 = 2;
pub const WTD_STATEACTION_AUTO_CACHE: u32 = 3;
pub const WTD_STATEACTION_AUTO_CACHE_FLUSH: u32 = 4;
pub const WTD_PROV_FLAGS_MASK: u32 = 0x0000_ffff;
pub const WTD_USE_IE4_TRUST_FLAG: u32 = 0x0000_0001;
pub const WTD_NO_IE4_CHAIN_FLAG: u32 = 0x0000_0002;
pub const WTD_NO_POLICY_USAGE_FLAG: u32 = 0x0000_0004;
pub const WTD_REVOCATION_CHECK_NONE: u32 = 0x0000_0010;
pub const WTD_REVOCATION_CHECK_END_CERT: u32 = 0x0000_0020;
pub const WTD_REVOCATION_CHECK_CHAIN: u32 = 0x0000_0040;
pub const WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT: u32 = 0x0000_0080;
pub const WTD_SAFER_FLAG: u32 = 0x0000_0100;
pub const WTD_HASH_ONLY_FLAG: u32 = 0x0000_0200;
pub const WTD_USE_DEFAULT_OSVER_CHECK: u32 = 0x0000_0400;
pub const WTD_LIFETIME_SIGNING_FLAG: u32 = 0x0000_0800;
pub const WTD_CACHE_ONLY_URL_RETRIEVAL: u32 = 0x0000_1000;
pub const WTD_UICONTEXT_EXECUTE: u32 = 0;
pub const WTD_UICONTEXT_INSTALL: u32 = 1;

pub const FILE_SHARE_READ: u32 = 0x0000_0001;
pub const FILE_SHARE_WRITE: u32 = 0x0000_0002;
pub const FILE_SHARE_DELETE: u32 = 0x0000_0004;

pub const GENERIC_READ: u32 = 0x8000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const GENERIC_EXECUTE: u32 = 0x2000_0000;
pub const GENERIC_ALL: u32 = 0x1000_0000;

pub const CREATE_NEW: u32 = 1;
pub const CREATE_ALWAYS: u32 = 2;
pub const OPEN_EXISTING: u32 = 3;
pub const OPEN_ALWAYS: u32 = 4;
pub const TRUNCATE_EXISTING: u32 = 5;
