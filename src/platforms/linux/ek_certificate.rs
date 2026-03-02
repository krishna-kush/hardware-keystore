use tss_esapi::abstraction::{ek, AsymmetricAlgorithmSelection};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::structures::Public;
use tss_esapi::Context;

use super::manufacturer;

fn retrieve_from_nv(ctx: &mut Context) -> Option<Vec<u8>> {
    ek::retrieve_ek_pubcert(ctx, AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256))
        .or_else(|_| {
            ek::retrieve_ek_pubcert(ctx, AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048))
        })
        .ok()
}

pub(super) fn retrieve_with_fallback(
    ctx: &mut Context,
    ek_public: &Public,
) -> (Option<Vec<u8>>, Option<String>) {
    match crate::first_present_source!(
        "manufacturer_service" => manufacturer::retrieve(ctx, ek_public),
        "local_nv_index" => retrieve_from_nv(ctx),
    ) {
        Some((source, cert)) => (Some(cert), Some(source)),
        None => (None, None),
    }
}
