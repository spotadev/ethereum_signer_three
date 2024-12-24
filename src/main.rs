// See https://docs.rs/k256/latest/k256/ecdsa/?ref=spark.litprotocol.com
//
// Note that we need to combine the recId with the signature:
// Signature: In the secp256k1 curve, the ECDSA signature (r, s) is typically 64 bytes.
// Recovery ID (recid): The recovery ID is a single byte (8 bits).
// You can add the Recovery ID on the end of the signature


use ecdsa::SigningKey;
use rand_core::OsRng;
use k256::Secp256k1;

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

use hex::{encode, decode};
use generic_array::GenericArray;
use generic_array::typenum::U32;
use sha3::{Keccak256, Digest};
use k256::PublicKey;
use std::error::Error;

struct EthKeyPair {
    private_key: String,
    public_key: String,
}

fn generate_eth_keypair() -> EthKeyPair {
    // Generate a new signing key - note we are using the OsRng seed. ICP smart 
    // contracts do not allow us to use random() therefore we need to call a canister
    // to get the random needed by SigningKey instead (when porting this code to ICP)
    let signing_key: SigningKey<Secp256k1> = SigningKey::random(&mut OsRng);

    // Extract the private key as bytes and convert to hex string
    let private_key_bytes = signing_key.to_bytes();
    let private_key_hex = encode(private_key_bytes);

    // Derive the public key and convert to uncompressed SEC1 bytes
    let verifying_key = signing_key.verifying_key();
    let encoded_point = verifying_key.to_encoded_point(false); // Store the encoded point
    let public_key_bytes = encoded_point.as_bytes(); // Use the bytes from the stored encoded point
    let public_key_hex = hex::encode(public_key_bytes);

    EthKeyPair {
        private_key: private_key_hex,
        public_key: public_key_hex
    }
}

fn create_signature(private_key: String, message_to_sign: String) -> Result<String, Box<dyn std::error::Error>> {
// fn create_signature(public_key: String, message_to_sign: String) -> String {
    let private_key_bytes = decode(private_key)?; 
    let private_key_array: &GenericArray<u8, U32> = GenericArray::from_slice(&private_key_bytes); 
    let signing_key: SigningKey<Secp256k1> = SigningKey::from_bytes(&private_key_array)?;
    let digest = Keccak256::new_with_prefix(message_to_sign.to_string());
    let (signature, recid) = signing_key.sign_digest_recoverable(digest)?;

    println!("recid {:#?}", recid);

    // Convert the signature and recovery ID to bytes and combine them 
    let mut combined_signature = signature.to_bytes().to_vec();  
    combined_signature.push(recid.to_byte());
    let signature_in_hex = encode(combined_signature);
    return Ok(signature_in_hex);
}

fn get_ethereum_address(public_key_hex: &String) -> Result<String, Box<dyn std::error::Error>> {
    // Decode the public key from hex string to bytes
    let public_key_bytes = 
        decode(public_key_hex).map_err(|e| e.to_string())?;
    
    // Create a PublicKey object from the bytes
    let public_key = 
        PublicKey::from_sec1_bytes(&public_key_bytes)
        .map_err(|e| e.to_string())?;

    let mut hasher = Keccak256::new();

    // Perform Keccak-256 hash on the public key bytes (skip the first byte, which is the prefix)
    hasher.update(&public_key.to_sec1_bytes()[1..]);
    let hash_bytes = hasher.finalize();

    // Take the last 20 bytes of the hash output
    let address_bytes = &hash_bytes[hash_bytes.len() - 20..];
    let address_hex = format!("0x{}", encode(address_bytes));
    return Ok(address_hex);
}

fn validate_signature(signature: String, address: String, message: String) -> Result<bool, Box<dyn std::error::Error>> {
    println!("Inside validate_signature");
    
    // The signature has the 64 bytes of signature and the recid as the 65th byte
    let combined_signature_bytes = decode(signature)?;

    println!("combined_signature_bytes {:#?}", combined_signature_bytes);
    println!("combined_signature_bytes.len() {:#?}", combined_signature_bytes.len());

    // Gere we separate them out
    let (signature_bytes, recid_byte) = 
        combined_signature_bytes.split_at(combined_signature_bytes.len() - 1);

    println!("signature_bytes {:#?}", signature_bytes);
    println!("recid_byte {:#?}", recid_byte);

    let recid_single_byte = recid_byte[0];
    println!("recid_single_byte {:#?}", recid_single_byte);

    // let signature = Signature::try_from(value)  try_from(signature_as_bytes).as_slice();
    // let signature = Signature::from_der(&signature_bytes)?;
    let signature = Signature::try_from(signature_bytes)?;
    println!("signature {:#?}", signature);
    
    let recid = RecoveryId::try_from(recid_single_byte)?;
    let digest = Keccak256::new_with_prefix(message);

    println!("digest {:#?}", digest);

    let recovered_key = VerifyingKey::recover_from_digest(
        digest,
        &signature,
        recid
    )?;

    println!("recovered_key {:#?}", recovered_key);

    let encoded_point = recovered_key.to_encoded_point(false);
    let recovered_public_key_bytes = encoded_point.as_bytes();
    let mut hasher = Keccak256::new();
    
    // Skip the 0x04 prefix byte 
    hasher.update(&recovered_public_key_bytes[1..]); 
    let recovered_hash_public_key: GenericArray<u8, U32> = hasher.finalize();

    let recovered_address_bytes = 
        &recovered_hash_public_key[recovered_hash_public_key.len() - 20..];

    let recovered_address_hex = format!("0x{}", hex::encode(recovered_address_bytes));
    Ok(recovered_address_hex.to_lowercase() == address.to_lowercase())
}


fn main() {
    let key_pair = generate_eth_keypair();
    println!("Private Key: {}", key_pair.private_key);
    println!("Public Key: {}", key_pair.public_key);

    let message_to_sign = "Sign in at UTU";
    
    let public_key = key_pair.public_key;
    let private_key: String = key_pair.private_key;

    let signature = 
        create_signature(private_key.clone(), message_to_sign.to_string());

    let ethereum_address_result: Result<String, Box<dyn Error>> = 
        get_ethereum_address(&public_key);
    
    let ethereum_address: String = ethereum_address_result.unwrap();
    
    let is_valid_result: Result<bool, Box<dyn Error>> =  
        validate_signature(signature.unwrap(), ethereum_address, 
            message_to_sign.to_string());
        
    match is_valid_result {
        Ok(is_valid) => println!("Is signature valid? {}", is_valid),
        Err(e) => println!("Error validating signature: {}", e),
    }
}
