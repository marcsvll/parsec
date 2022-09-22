// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::{utils, Provider};
use crate::authenticators::ApplicationIdentity;
use crate::key_info_managers::KeyIdentity;
use crate::utils::config::TpmRotConfig;
use log::error;
use parsec_interface::operations::{attest_key, prepare_key_attestation};
use parsec_interface::requests::{AuthType, ResponseStatus, Result};
use parsec_interface::secrecy::zeroize::Zeroizing;
use std::convert::TryFrom;
use tss_esapi::constants::TpmFormatOneError;
use tss_esapi::error::TpmResponseCode;
use tss_esapi::structures::{PcrSelectionListBuilder, PcrSlot};
use tss_esapi::{abstraction::transient::ObjectWrapper, structures::Auth};
use tss_esapi::{Error, ReturnCode};

impl Provider {
    pub(super) fn prepare_key_attestation_internal(
        &self,
        application_identity: &ApplicationIdentity,
        op: prepare_key_attestation::Operation,
    ) -> Result<prepare_key_attestation::Result> {
        match op {
            prepare_key_attestation::Operation::ActivateCredential {
                attested_key_name,
                attesting_key_name,
            } => self.prepare_activate_credential(
                application_identity,
                attested_key_name,
                attesting_key_name,
            ),
            _ => {
                error!("Key attestation mechanism is not supported");
                Err(ResponseStatus::PsaErrorNotSupported)
            }
        }
    }

    // Get the parameters required for a MakeCredential operation
    //
    // If the `attesting_key_name` is not given, a default, RSA decryption
    // Endorsement Key will be used.
    fn prepare_activate_credential(
        &self,
        application_identity: &ApplicationIdentity,
        attested_key_name: String,
        attesting_key_name: Option<String>,
    ) -> Result<prepare_key_attestation::Result> {
        if attesting_key_name.is_some() {
            error!("Attesting with a non-default key is currently not supported");
            return Err(ResponseStatus::PsaErrorNotSupported);
        }

        let key_identity = KeyIdentity::new(
            application_identity.clone(),
            self.provider_identity.clone(),
            attested_key_name,
        );
        let pass_context = self.get_key_ctx(&key_identity)?;
        let key_attributes = self.key_info_store.get_key_attributes(&key_identity)?;
        let params = utils::parsec_to_tpm_params(key_attributes)?;
        let auth = Some(
            Auth::try_from(pass_context.auth_value().to_vec())
                .map_err(utils::to_response_status)?,
        );
        let attested_key = ObjectWrapper {
            material: pass_context.key_material().clone(),
            auth,
            params,
        };

        let mut esapi_context = self
            .esapi_context
            .lock()
            .expect("ESAPI Context lock poisoned");

        let params = esapi_context
            .get_make_cred_params(attested_key, None)
            .map_err(|e| {
                format_error!("Failed to get MakeCredential parameters", e);
                key_attest_response_status(e)
            })?;

        Ok(prepare_key_attestation::Result::ActivateCredential {
            name: params.name.into(),
            attesting_key_pub: utils::ek_pub_key_to_bytes(params.attesting_key_pub)?.into(),
            public: params.public.into(),
        })
    }

    pub(super) fn attest_key_internal(
        &self,
        application_identity: &ApplicationIdentity,
        op: attest_key::Operation,
    ) -> Result<attest_key::Result> {
        match op {
            attest_key::Operation::ActivateCredential {
                attested_key_name,
                attesting_key_name,
                credential_blob,
                secret,
            } => self.activate_credential(
                application_identity,
                attested_key_name,
                attesting_key_name,
                credential_blob,
                secret,
            ),
            attest_key::Operation::CertifyAndQuote {
                attested_key_name,
                nonce,
                attesting_key_name,
            } => self.certify_and_quote(
                application_identity,
                attested_key_name,
                attesting_key_name,
                nonce,
            ),
            _ => {
                error!("Key attestation mechanism is not supported");
                Err(ResponseStatus::PsaErrorNotSupported)
            }
        }
    }

    fn activate_credential(
        &self,
        application_identity: &ApplicationIdentity,
        attested_key_name: String,
        attesting_key_name: Option<String>,
        credential_blob: Zeroizing<Vec<u8>>,
        secret: Zeroizing<Vec<u8>>,
    ) -> Result<attest_key::Result> {
        if attesting_key_name.is_some() {
            error!("Attesting with a non-default key is currently not supported");
            return Err(ResponseStatus::PsaErrorNotSupported);
        }

        let key_identity = KeyIdentity::new(
            application_identity.clone(),
            self.provider_identity.clone(),
            attested_key_name,
        );
        let pass_context = self.get_key_ctx(&key_identity)?;
        let key_attributes = self.key_info_store.get_key_attributes(&key_identity)?;
        let params = utils::parsec_to_tpm_params(key_attributes)?;
        let auth = Some(
            Auth::try_from(pass_context.auth_value().to_vec())
                .map_err(utils::to_response_status)?,
        );
        let attested_key = ObjectWrapper {
            material: pass_context.key_material().clone(),
            auth,
            params,
        };

        let mut esapi_context = self
            .esapi_context
            .lock()
            .expect("ESAPI Context lock poisoned");

        let credential = esapi_context
            .activate_credential(
                attested_key,
                None,
                credential_blob.to_vec(),
                secret.to_vec(),
            )
            .map_err(|e| {
                format_error!("Failed to activate credential", e);
                key_attest_response_status(e)
            })?;

        Ok(attest_key::Result::ActivateCredential {
            credential: credential.into(),
        })
    }

    fn certify_and_quote(
        &self,
        application_identity: &ApplicationIdentity,
        attested_key_name: String,
        attesting_key_name: Option<String>,
        nonce: Vec<u8>,
    ) -> Result<attest_key::Result> {
        if attesting_key_name.is_some() {
            error!("Attesting with a non-default key is currently not supported");
            return Err(ResponseStatus::PsaErrorNotSupported);
        }

        let attested_key_identity = KeyIdentity::new(
            application_identity.clone(),
            self.provider_identity.clone(),
            attested_key_name,
        );
        let attested_key_pass_context = self.get_key_ctx(&attested_key_identity)?;
        let attested_key_attributes = self
            .key_info_store
            .get_key_attributes(&attested_key_identity)?;
        let attested_key_params = utils::parsec_to_tpm_params(attested_key_attributes)?;
        let attested_key_auth = Some(
            Auth::try_from(attested_key_pass_context.auth_value().to_vec())
                .map_err(utils::to_response_status)?,
        );
        let attested_key = ObjectWrapper {
            material: attested_key_pass_context.key_material().clone(),
            auth: attested_key_auth,
            params: attested_key_params,
        };

        let attesting_key_identity = KeyIdentity::new(
            ApplicationIdentity::new(String::from("Provider"), AuthType::NoAuth),
            self.provider_identity.clone(),
            String::from("Attesting Key"),
        );
        let attesting_key_pass_context = self.get_key_ctx(&attesting_key_identity)?;
        let attesting_key_attributes = self
            .key_info_store
            .get_key_attributes(&attesting_key_identity)?;
        let attesting_key_params = utils::parsec_to_tpm_params(attesting_key_attributes)?;
        let attesting_key_auth = Some(
            Auth::try_from(attesting_key_pass_context.auth_value().to_vec())
                .map_err(utils::to_response_status)?,
        );
        let attesting_key = ObjectWrapper {
            material: attesting_key_pass_context.key_material().clone(),
            auth: attesting_key_auth,
            params: attesting_key_params,
        };

        let mut esapi_context = self
            .esapi_context
            .lock()
            .expect("ESAPI Context lock poisoned");

        let pcr_selection_list = match self.root_of_trust.clone() {
            None => {
                error!("TPM RoT config does not exist");
                return Err(ResponseStatus::PsaErrorGenericError);
            }
            Some(TpmRotConfig {
                pcr_list: Some(pcr_list),
                pcr_hash_alg: Some(pcr_hash_alg),
            }) => {
                if pcr_list.iter().any(|value| *value > 31) {
                    error!("PCR index invalid");
                    return Err(ResponseStatus::PsaErrorGenericError);
                }
                PcrSelectionListBuilder::new()
                    .with_selection(
                        pcr_hash_alg.into(),
                        &pcr_list
                            .iter()
                            .map(|pcr_slot| PcrSlot::try_from(1_u32 << pcr_slot).unwrap())
                            .collect::<Vec<PcrSlot>>(),
                    )
                    .build()
                    .expect("Failed to create first PcrSelectionList for pcr_read call")
            }
            _ => {
                error!("TPM RoT config invalid");
                return Err(ResponseStatus::PsaErrorGenericError);
            }
        };

        let key_statement = esapi_context
            .certify(attested_key.clone(), attesting_key, nonce.clone())
            .map_err(|e| {
                format_error!("Failed to certify", e);
                key_attest_response_status(e)
            })?;

        let platform_statement = esapi_context
            .quote(attested_key, nonce, pcr_selection_list)
            .map_err(|e| {
                format_error!("Failed to quote", e);
                key_attest_response_status(e)
            })?;

        Ok(attest_key::Result::CertifyAndQuote {
            key_attestation_certificate: key_statement
                .encode()
                .map_err(|e| {
                    format_error!("Failed to encode key attestation certificate", e);
                    key_attest_response_status(e)
                })?
                .into(),
            platform_attestation_certificate: platform_statement
                .encode()
                .map_err(|e| {
                    format_error!("Failed to encode platform attestation certificate", e);
                    key_attest_response_status(e)
                })?
                .into(),
        })
    }
}

fn key_attest_response_status(error: Error) -> ResponseStatus {
    match error {
        Error::TssError(e) => match e {
            ReturnCode::Tpm(TpmResponseCode::FormatOne(err))
                if err.error_number() == TpmFormatOneError::BadAuth =>
            {
                error!("Wrong authentication value for attesting key");
                ResponseStatus::PsaErrorGenericError
            }
            ReturnCode::Tpm(TpmResponseCode::FormatOne(err))
                if err.error_number() == TpmFormatOneError::Value =>
            {
                error!("Wrong parameter value for key attestation");
                ResponseStatus::PsaErrorInvalidArgument
            }
            ReturnCode::Tpm(TpmResponseCode::FormatOne(err))
                if err.error_number() == TpmFormatOneError::Size =>
            {
                error!("Wrong parameter size for key attestation");
                ResponseStatus::PsaErrorInvalidArgument
            }
            _ => utils::to_response_status(error),
        },
        _ => utils::to_response_status(error),
    }
}
