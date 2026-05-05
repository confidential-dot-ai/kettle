// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::{Quote, QuoteError};
use openssl::pkey::{PKey, Public};
use openssl::{hash::MessageDigest, sha::Sha256, sign::Verifier};
use thiserror::Error;
use tss_esapi::structures::{Attest, AttestInfo};
use tss_esapi::traits::UnMarshall;

#[non_exhaustive]
#[derive(Error, Debug)]
pub enum VerifyError {
    #[error("tss error")]
    Tss(#[from] tss_esapi::Error),
    #[error("openssl error")]
    OpenSsl(#[from] openssl::error::ErrorStack),
    #[error("quote is not signed by key")]
    SignatureMismatch,
    #[error("nonce mismatch")]
    NonceMismatch,
    #[error("quote error")]
    Quote(#[from] QuoteError),
    #[error("pcr mismatch")]
    PcrMismatch,
}

impl Quote {
    /// Verify a Quote's signature and nonce
    ///
    /// # Arguments
    ///
    /// * `pub_key` - A public key to verify the Quote's signature
    ///
    /// * `nonce` - A byte slice to verify the Quote's nonce
    pub fn verify(&self, pub_key: &PKey<Public>, nonce: &[u8]) -> Result<(), VerifyError> {
        self.verify_signature(pub_key)?;

        let quote_nonce = &self.nonce()?;
        if nonce != quote_nonce {
            return Err(VerifyError::NonceMismatch);
        }

        self.verify_pcrs()?;

        Ok(())
    }

    /// Verify a Quote's signature
    ///
    /// # Arguments
    ///
    /// * `pub_key` - A public key to verify the Quote's signature
    pub fn verify_signature(&self, pub_key: &PKey<Public>) -> Result<(), VerifyError> {
        let mut verifier = Verifier::new(MessageDigest::sha256(), pub_key)?;
        verifier.update(&self.message)?;
        let is_verified = verifier.verify(&self.signature)?;
        if !is_verified {
            return Err(VerifyError::SignatureMismatch);
        }
        Ok(())
    }

    /// Verify that the TPM Quote's PCR digest matches the digest of the bundled PCR values
    ///
    pub fn verify_pcrs(&self) -> Result<(), VerifyError> {
        let attest = Attest::unmarshall(&self.message)?;
        let AttestInfo::Quote { info } = attest.attested() else {
            return Err(VerifyError::Quote(QuoteError::NotAQuote));
        };

        let pcr_digest = info.pcr_digest();

        // Read hashes of all the PCRs.
        let mut hasher = Sha256::new();
        for pcr in self.pcrs.iter() {
            hasher.update(pcr);
        }

        let digest = hasher.finish();
        if digest[..] != pcr_digest[..] {
            return Err(VerifyError::PcrMismatch);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deserialize Quote from binary format
    /// The test fixture is stored in a binary format that was previously bincode-encoded.
    /// This deserializer reconstructs the Quote struct from the binary data.
    fn deserialize_quote(data: &[u8]) -> Result<Quote, String> {
        use std::io::{Cursor, Read};

        let mut cursor = Cursor::new(data);

        // Read signature (Vec<u8>)
        let mut signature_len_bytes = [0u8; 8];
        cursor
            .read_exact(&mut signature_len_bytes)
            .map_err(|e| format!("Failed to read signature length: {e}"))?;
        let signature_len = u64::from_le_bytes(signature_len_bytes) as usize;
        let mut signature = vec![0u8; signature_len];
        cursor
            .read_exact(&mut signature)
            .map_err(|e| format!("Failed to read signature: {e}"))?;

        // Read message (Vec<u8>)
        let mut message_len_bytes = [0u8; 8];
        cursor
            .read_exact(&mut message_len_bytes)
            .map_err(|e| format!("Failed to read message length: {e}"))?;
        let message_len = u64::from_le_bytes(message_len_bytes) as usize;
        let mut message = vec![0u8; message_len];
        cursor
            .read_exact(&mut message)
            .map_err(|e| format!("Failed to read message: {e}"))?;

        // Read pcrs (Vec<[u8; 32]>)
        let mut pcrs_len_bytes = [0u8; 8];
        cursor
            .read_exact(&mut pcrs_len_bytes)
            .map_err(|e| format!("Failed to read pcrs length: {e}"))?;
        let pcrs_len = u64::from_le_bytes(pcrs_len_bytes) as usize;
        let mut pcrs = Vec::with_capacity(pcrs_len);
        for _ in 0..pcrs_len {
            let mut pcr = [0u8; 32];
            cursor
                .read_exact(&mut pcr)
                .map_err(|e| format!("Failed to read pcr: {e}"))?;
            pcrs.push(pcr);
        }

        Ok(Quote {
            signature,
            message,
            pcrs,
        })
    }

    // // Use this code to generate the scriptures for the test on an AMD CVM.
    //
    // use az_snp_vtpm::vtpm;
    // use rsa;
    // use rsa::pkcs8::EncodePublicKey;
    // use std::error::Error;
    // use std::fs;
    //
    // fn main() -> Result<(), Box<dyn Error>> {
    //     // Extract the AK public key.
    //     let foo = vtpm::get_ak_pub()?.to_public_key_pem(rsa::pkcs8::LineEnding::LF)?;
    //     fs::write("/tmp/akpub.pem", foo)?;
    //
    //     // Save the PCRs into binary file.
    //     let nonce = "challenge".as_bytes().to_vec();
    //     let quote = vtpm::get_quote(&nonce)?;
    //     let quote_encoded: Vec<u8> = bincode::serialize(&quote).unwrap();
    //     fs::write("/tmp/quote.bin", quote_encoded)?;
    //
    //     Ok(())
    // }

    #[cfg(feature = "verifier")]
    #[test]
    fn test_quote_validation() {
        // Can be retrieved by `get_ak_pub()` or via tpm2-tools:
        // sudo tpm2_readpublic -c 0x81000003 -f pem -o akpub.pem
        let pem = include_bytes!("../../test/akpub.pem");
        let pkey = PKey::public_key_from_pem(pem).unwrap();

        // Can be retrieved by `get_quote()` or via tpm2-tools:
        // For message and signature:
        // sudo tpm2_quote -c 0x81000003 -l sha256:5,8 -q challenge -m quote_msg -s quote_sig
        //
        // For PCR values:
        // sudo tpm2_pcrread sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23
        let quote_bytes = include_bytes!("../../test/quote.bin");
        // Using custom deserializer to read the test fixture
        let quote: Quote = deserialize_quote(quote_bytes).expect("Failed to deserialize quote");

        // proper nonce in message
        let nonce = "challenge".as_bytes().to_vec();
        let result = quote.verify(&pkey, &nonce);
        assert!(result.is_ok(), "Quote verification should not fail");

        // wrong signature
        let mut wrong_quote = quote.clone();
        wrong_quote.signature.reverse();
        let result = wrong_quote.verify(&pkey, &nonce);
        let error = result.unwrap_err();
        assert!(
            matches!(error, VerifyError::SignatureMismatch),
            "Expected signature mismatch"
        );

        // improper nonce
        let nonce = vec![1, 2, 3, 4];
        let result = quote.verify(&pkey, &nonce);
        let error = result.unwrap_err();
        assert!(
            matches!(error, VerifyError::NonceMismatch),
            "Expected nonce verification error"
        );
    }

    #[test]
    fn test_pcr_values() {
        let quote_bytes = include_bytes!("../../test/quote.bin");
        // Using custom deserializer to read the test fixture
        let quote: Quote = deserialize_quote(quote_bytes).expect("Failed to deserialize quote");
        let result = quote.verify_pcrs();
        assert!(result.is_ok(), "PCR verification should not fail");
    }
}
