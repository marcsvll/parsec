// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::{utils, Provider};
use crate::authenticators::ApplicationIdentity;
use crate::key_info_managers::KeyIdentity;
use parsec_interface::operations::psa_algorithm::{Algorithm, AsymmetricEncryption};
use parsec_interface::operations::{psa_asymmetric_decrypt, psa_asymmetric_encrypt};
use parsec_interface::requests::{ResponseStatus, Result};
use std::convert::TryInto;
use std::ops::Deref;
use tss_esapi::constants::TpmFormatOneError;
use tss_esapi::error::TpmResponseCode;
use tss_esapi::Error;
use tss_esapi::ReturnCode;

impl Provider {
    pub(super) fn psa_asymmetric_encrypt_internal(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_asymmetric_encrypt::Operation,
    ) -> Result<psa_asymmetric_encrypt::Result> {
        let key_identity = KeyIdentity::new(
            application_identity.clone(),
            self.provider_identity.clone(),
            op.key_name.clone(),
        );

        let password_context = self.get_key_ctx(&key_identity)?;
        let key_attributes = self.key_info_store.get_key_attributes(&key_identity)?;

        let mut esapi_context = self
            .esapi_context
            .lock()
            .expect("ESAPI Context lock poisoned");

        op.validate(key_attributes)?;

        match esapi_context.rsa_encrypt(
            password_context.key_material().clone(),
            utils::parsec_to_tpm_params(key_attributes)?,
            Some(
                password_context
                    .auth_value()
                    .try_into()
                    .map_err(utils::to_response_status)?,
            ),
            op.plaintext
                .deref()
                .clone()
                .try_into()
                .map_err(utils::to_response_status)?,
            match op.salt {
                Some(salt) => Some(
                    salt.deref()
                        .to_vec()
                        .try_into()
                        .map_err(utils::to_response_status)?,
                ),
                None => None,
            },
        ) {
            Ok(ciphertext) => Ok(psa_asymmetric_encrypt::Result {
                ciphertext: ciphertext.value().to_vec().into(),
            }),
            Err(tss_error) => {
                let error = utils::to_response_status(tss_error);
                format_error!("Encryption failed", tss_error);
                Err(error)
            }
        }
    }

    pub(super) fn psa_asymmetric_decrypt_internal(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_asymmetric_decrypt::Operation,
    ) -> Result<psa_asymmetric_decrypt::Result> {
        let key_identity = KeyIdentity::new(
            application_identity.clone(),
            self.provider_identity.clone(),
            op.key_name.clone(),
        );

        let password_context = self.get_key_ctx(&key_identity)?;
        let key_attributes = self.key_info_store.get_key_attributes(&key_identity)?;

        let mut esapi_context = self
            .esapi_context
            .lock()
            .expect("ESAPI Context lock poisoned");

        op.validate(key_attributes)?;

        match esapi_context.rsa_decrypt(
            password_context.key_material().clone(),
            utils::parsec_to_tpm_params(key_attributes)?,
            Some(
                password_context
                    .auth_value()
                    .try_into()
                    .map_err(utils::to_response_status)?,
            ),
            op.ciphertext
                .deref()
                .clone()
                .try_into()
                .map_err(utils::to_response_status)?,
            match op.salt {
                Some(salt) => Some(
                    salt.deref()
                        .to_vec()
                        .try_into()
                        .map_err(utils::to_response_status)?,
                ),
                None => None,
            },
        ) {
            Ok(plaintext) => Ok(psa_asymmetric_decrypt::Result {
                plaintext: plaintext.value().to_vec().into(),
            }),
            Err(tss_error) => {
                // If the algorithm is RSA with PKCS#1 v1.5 padding and we get TPM_RC_VALUE back,
                // it means the padding has been deemed invalid and we should let the caller know
                // about that. This allows clients to mitigate attacks that leverage padding
                // oracles a la Bleichenbacher.
                // See https://cryptosense.com/blog/why-pkcs1v1-5-encryption-should-be-put-out-of-our-misery
                // for more details.
                if let Algorithm::AsymmetricEncryption(AsymmetricEncryption::RsaPkcs1v15Crypt) =
                    key_attributes.policy.permitted_algorithms
                {
                    if let Error::TssError(ReturnCode::Tpm(TpmResponseCode::FormatOne(err))) =
                        tss_error
                    {
                        if err.error_number() == TpmFormatOneError::Value {
                            format_error!("Wrong plaintext padding", tss_error);
                            return Err(ResponseStatus::PsaErrorInvalidPadding);
                        }
                    }
                }
                let error = utils::to_response_status(tss_error);
                format_error!("Encryption failed", tss_error);
                Err(error)
            }
        }
    }
}
