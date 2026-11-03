//! # OidcIdentityStore — (iss, sub) -> localpart binding map
//!
//! Namespace registration landed with the WriteBatch.putIfAbsent contract;
//! the store implementation follows.

const backend_mod = @import("backend");

pub const NAMESPACE = backend_mod.registered("oidc_identities");
