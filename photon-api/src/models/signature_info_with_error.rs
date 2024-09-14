/*
 * photon-indexer
 *
 * Solana indexer for general compression
 *
 * The version of the OpenAPI document: 0.45.0
 *
 * Generated by: https://openapi-generator.tech
 */

use crate::models;

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignatureInfoWithError {
    /// An Unix timestamp (seconds)
    #[serde(rename = "blockTime")]
    pub block_time: i32,
    #[serde(
        rename = "error",
        default,
        with = "::serde_with::rust::double_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub error: Option<Option<String>>,
    /// A Solana transaction signature.
    #[serde(rename = "signature")]
    pub signature: String,
    #[serde(rename = "slot")]
    pub slot: i32,
}

impl SignatureInfoWithError {
    pub fn new(block_time: i32, signature: String, slot: i32) -> SignatureInfoWithError {
        SignatureInfoWithError {
            block_time,
            error: None,
            signature,
            slot,
        }
    }
}