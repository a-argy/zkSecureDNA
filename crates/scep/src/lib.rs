// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

mod base64;
pub mod cookie;
pub mod error;
pub mod mutual_authentication;
pub mod nonce;
pub mod states;
pub mod steps;
pub mod types;

pub const OPEN_ENDPOINT: &str = "/scep/open";
pub const AUTHENTICATE_ENDPOINT: &str = "/scep/authenticate";
pub const KEYSERVE_ENDPOINT: &str = "/scep/keyserve";
/// zkSecureDNA: like keyserve, but the response ends with a DLEQ proof.
pub const KEYSERVE_PROVED_ENDPOINT: &str = "/scep/keyserve-proved";
pub const KEYSERVE_PROVED_CONTENT_TYPE: &str = "application/x-zksecuredna-keyserve-v1";
pub const SCREEN_ENDPOINT: &str = "/scep/screen";
pub const SCREEN_AND_VERIFY_ENDPOINT: &str = "/scep/screen-and-verify";
pub const SCREEN_WITH_EXEMPTION_ENDPOINT: &str = "/scep/screen-with-exemption";
pub const EXEMPTION_ENDPOINT: &str = "/scep/exemption";
pub const EXEMPTION_SEQ_HASHES_ENDPOINT: &str = "/scep/exemption-seq-hashes";
pub const EXEMPTION_SCREEN_HASHES_ENDPOINT: &str = "/scep/exemption-screen-hashes";
