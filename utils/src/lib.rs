use std::{
    env,
    io::{self, prelude::*},
    process::{Command, Stdio},
    thread::spawn,
};

use ark_ff::PrimeField;
use num_bigint::BigUint;

use solana_program::keccak::hashv;
use thiserror::Error;

pub mod bigint;
pub mod fee;
pub mod prime;
pub mod rand;

#[derive(Debug, Error, PartialEq)]
pub enum UtilsError {
    #[error("Invalid input size, expected at most {0}")]
    InputTooLarge(usize),
    #[error("Invalid chunk size")]
    InvalidChunkSize,
    #[error("Invalid seeds")]
    InvalidSeeds,
    #[error("Invalid rollover thresold")]
    InvalidRolloverThreshold,
}

// NOTE(vadorovsky): Unfortunately, we need to do it by hand. `num_derive::ToPrimitive`
// doesn't support data-carrying enums.
impl From<UtilsError> for u32 {
    fn from(e: UtilsError) -> u32 {
        match e {
            UtilsError::InputTooLarge(_) => 12001,
            UtilsError::InvalidChunkSize => 12002,
            UtilsError::InvalidSeeds => 12003,
            UtilsError::InvalidRolloverThreshold => 12004,
        }
    }
}

impl From<UtilsError> for solana_program::program_error::ProgramError {
    fn from(e: UtilsError) -> Self {
        solana_program::program_error::ProgramError::Custom(e.into())
    }
}

pub fn is_smaller_than_bn254_field_size_be(bytes: &[u8; 32]) -> Result<bool, UtilsError> {
    let bigint = BigUint::from_bytes_be(bytes);
    if bigint < ark_bn254::Fr::MODULUS.into() {
        Ok(true)
    } else {
        Ok(false)
    }
}

pub fn hash_to_bn254_field_size_be(bytes: &[u8]) -> Option<([u8; 32], u8)> {
    let mut bump_seed = [std::u8::MAX];
    // Loops with decreasing bump seed to find a valid hash which is less than
    // bn254 Fr modulo field size.
    for _ in 0..std::u8::MAX {
        {
            let mut hashed_value: [u8; 32] = hashv(&[bytes, bump_seed.as_ref()]).to_bytes();
            // TODO: revisit truncation (without truncation it takes up to 30
            // hashes to find a valid one, this is not acceptable onchain)
            // truncate to 31 bytes so that value is less than bn254 Fr modulo
            // field size
            hashed_value[0] = 0;
            if let Ok(true) = is_smaller_than_bn254_field_size_be(&hashed_value) {
                return Some((hashed_value, bump_seed[0]));
            }
        }
        bump_seed[0] -= 1;
    }
    None
}

/// Applies `rustfmt` on the given string containing Rust code. The purpose of
/// this function is to be able to format autogenerated code (e.g. with `quote`
/// macro).
pub fn rustfmt(code: String) -> Result<Vec<u8>, anyhow::Error> {
    let mut cmd = match env::var_os("RUSTFMT") {
        Some(r) => Command::new(r),
        None => Command::new("rustfmt"),
    };

    let mut cmd = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let mut stdin = cmd.stdin.take().unwrap();
    let mut stdout = cmd.stdout.take().unwrap();

    let stdin_handle = spawn(move || {
        stdin.write_all(code.as_bytes()).unwrap();
    });

    let mut formatted_code = vec![];
    io::copy(&mut stdout, &mut formatted_code)?;

    let _ = cmd.wait();
    stdin_handle.join().unwrap();

    Ok(formatted_code)
}

#[cfg(test)]
mod tests {

    use solana_program::pubkey::Pubkey;

    use super::*;

    #[test]
    fn test_hash_to_bn254_field_size_be() {
        for _ in 0..10_000 {
            let input_bytes = Pubkey::new_unique().to_bytes(); // Sample input
            let (hashed_value, bump) = hash_to_bn254_field_size_be(input_bytes.as_slice())
                .expect("Failed to find a hash within BN254 field size");
            assert_eq!(bump, 255, "Bump seed should be 0");
            assert!(
                is_smaller_than_bn254_field_size_be(&hashed_value).unwrap(),
                "Hashed value should be within BN254 field size"
            );
        }
    }
}
