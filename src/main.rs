// See https://docs.rs/k256/latest/k256/ecdsa/?ref=spark.litprotocol.com
//
// Note that we need to combine the recId with the signature:
// Signature: In the secp256k1 curve, the ECDSA signature (r, s) is typically 64 bytes.
// Recovery ID (recid): The recovery ID is a single byte (8 bits).
// You can add the Recovery ID on the end of the signature
//
// Important Ethereum-specific details for signature compatibility:
// 1. The message prefix is crucial - Ethereum's personal_sign prepends "\x19Ethereum Signed Message:\n"
//    plus the message length. This prefix prevents signed messages from being used as transactions.
// 2. Public keys in Ethereum are 65 bytes long, where the first byte (0x04) indicates uncompressed
//    format. When generating addresses, we skip this prefix as it's not part of the actual key data.
// 3. We add 27 to the recovery ID to maintain compatibility with Ethereum's signature scheme.
//    This is a historical artifact from Bitcoin's implementation that Ethereum maintained.

use ecdsa::SigningKey;
use generic_array::{typenum::U32, GenericArray};
use hex::{decode, encode};
use k256::{
    ecdsa::{RecoveryId, Signature, VerifyingKey},
    Secp256k1,
};
use rand_core::OsRng;
use sha3::{Digest, Keccak256};

struct EthKeyPair {
    private_key: String,
    public_key: String,
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

fn eth_message(message: &str) -> Vec<u8> {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut eth_message = prefix.as_bytes().to_vec();
    eth_message.extend_from_slice(message.as_bytes());
    eth_message
}

fn generate_eth_keypair() -> EthKeyPair {
    // Generate a new signing key - note we are using the OsRng seed. ICP smart
    // contracts do not allow us to use random() therefore we need to call a canister
    // to get the random needed by SigningKey instead (when porting this code to ICP)
    let signing_key: SigningKey<Secp256k1> = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let private_key_hex = encode(signing_key.to_bytes());
    // Store the encoded_point before getting bytes to keep it alive long enough.
    // This is a Rust lifetime requirement - the as_bytes() result must not outlive
    // the encoded_point.
    let encoded_point = verifying_key.to_encoded_point(false);
    let public_key_bytes = encoded_point.as_bytes();

    println!("public_key_bytes: {:#?}", public_key_bytes);
    let public_key_hex = encode(public_key_bytes);

    EthKeyPair {
        private_key: private_key_hex,
        public_key: public_key_hex,
    }
}

fn create_signature(
    private_key: String,
    message: String,
) -> Result<String, Box<dyn std::error::Error>> {
    let private_key_bytes = decode(private_key)?;
    let private_key_array: &GenericArray<u8, U32> = GenericArray::from_slice(&private_key_bytes);
    let signing_key: SigningKey<Secp256k1> = SigningKey::from_bytes(private_key_array)?;

    let message_bytes = eth_message(&message);
    let message_hash = keccak256(&message_bytes);
    println!("Message bytes: {:#?}", message_bytes);
    println!("Message hash in create_signature: {:#?}", message_hash);

    let mut hasher = Keccak256::new();
    hasher.update(&message_hash);

    let (signature, recid) = signing_key.sign_digest_recoverable(hasher)?;
    println!("signature: {:#?}", signature);
    println!("recid: {:#?}", recid);

    let mut combined_signature = signature.to_bytes().to_vec();
    combined_signature.push(recid.to_byte() + 27);
    Ok(encode(combined_signature))
}

fn get_ethereum_address(public_key_hex: &String) -> Result<String, Box<dyn std::error::Error>> {
    let public_key_bytes = decode(public_key_hex)?;

    let mut hasher = Keccak256::new();
    hasher.update(&public_key_bytes[1..]);
    let hash = hasher.finalize();

    let address_bytes = &hash[12..];
    Ok(format!("0x{}", encode(address_bytes)))
}

fn validate_signature(
    signature: String,
    address: String,
    message: String,
) -> Result<bool, Box<dyn std::error::Error>> {
    println!("Inside validate_signature");

    let sig_bytes = decode(signature)?;
    if sig_bytes.len() != 65 {
        return Err("Invalid signature length".into());
    }

    println!("combined_signature_bytes: {:#?}", sig_bytes);
    println!("combined_signature_bytes.len(): {:#?}", sig_bytes.len());

    let (signature_bytes, rec_id_bytes) = sig_bytes.split_at(64);
    println!("signature_bytes: {:#?}", signature_bytes);
    println!("recid_byte: {:#?}", rec_id_bytes);

    let signature = Signature::try_from(signature_bytes)?;
    let recovery_id = RecoveryId::try_from(rec_id_bytes[0] - 27)?;
    println!("signature: {:#?}", signature);

    let message_bytes = eth_message(&message);
    let message_hash = keccak256(&message_bytes);
    println!("Message bytes in validate_signature: {:#?}", message_bytes);
    println!("digest in validate_signature: {:#?}", message_hash);

    let mut hasher = Keccak256::new();
    hasher.update(&message_hash);

    let recovered_key = VerifyingKey::recover_from_digest(hasher, &signature, recovery_id)?;
    println!("recovered_key: {:#?}", recovered_key);

    let encoded_point = recovered_key.to_encoded_point(false);
    let mut hasher = Keccak256::new();
    hasher.update(&encoded_point.as_bytes()[1..]);
    let hash = hasher.finalize();

    let recovered_address = format!("0x{}", encode(&hash[12..]));
    println!("recovered_address_hex: {}", recovered_address);
    println!("address: {}", address);

    Ok(recovered_address.to_lowercase() == address.to_lowercase())
}

fn main() {
    let key_pair = generate_eth_keypair();
    println!("Private Key: {}", key_pair.private_key);
    println!("Public Key: {}", key_pair.public_key);

    let message = "Sign in at UTU";
    println!("\nSigning message: {}", message);

    match create_signature(key_pair.private_key.clone(), message.to_string()) {
        Ok(signature) => match get_ethereum_address(&key_pair.public_key) {
            Ok(address) => {
                println!("\nGenerated address: {}", address);
                match validate_signature(signature.clone(), address.clone(), message.to_string()) {
                    Ok(is_valid) => {
                        println!("\nSignature: {}", signature);
                        println!("Is signature valid? {}", is_valid);

                        if !is_valid {
                            panic!("Signature validation failed!");
                        }
                    }
                    Err(e) => println!("Validation error: {}", e),
                }
            }
            Err(e) => println!("Address generation error: {}", e),
        },
        Err(e) => println!("Signature creation error: {}", e),
    }
}