use hex::{decode, encode};
use secp256k1::rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

// Gera um novo par de chaves pública e privada
fn generate_keypair() -> (String, String) {
    let secp = Secp256k1::new();
    let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);
    // Converter as chaves para hexadecimal
    let secret_key_hex = encode(secret_key.secret_bytes());
    let public_key_serialized = public_key.serialize_uncompressed(); // Ethereum usa a forma descomprimida
    let public_key_hex = encode(&public_key_serialized[1..]); // Ignora o byte inicial que indica a compressão
    (secret_key_hex, public_key_hex)
}

// Gera a chave pública a partir de uma chave privada fornecida
fn public_key_from_private(private_key_hex: &str) -> Result<String, String> {
    let secp = Secp256k1::new();
    let private_key_hex_clean = private_key_hex.trim_start_matches("0x"); // Remove o prefixo "0x" se presente
    match decode(private_key_hex_clean) {
        Ok(private_key_bytes) => {
            match SecretKey::from_slice(&private_key_bytes) {
                Ok(secret_key) => {
                    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
                    let public_key_serialized = public_key.serialize_uncompressed();
                    let public_key_hex = format!("0x{}", encode(&public_key_serialized[1..])); // Adiciona "0x"
                    Ok(public_key_hex)
                }
                Err(_) => Err("Erro ao criar a chave secreta a partir do hex".into()),
            }
        }
        Err(_) => Err("Erro ao decodificar a chave privada em hex".into()),
    }
}
fn main() {
    // Gera um novo par de chaves e imprime
    let (private_key, public_key) = generate_keypair();
    println!("Nova chave privada: {}", private_key);
    println!("Nova chave pública: {}", public_key);

    // Use sua própria chave privada em hexadecimal aqui
    let your_private_key_hex = "0x521b8475d12bfc7a8f6223f396f4c32fe7fa399b9c6c0f3c8d9cd624e06e78a1";

    match public_key_from_private(your_private_key_hex) {
        Ok(pub_key) => {
            println!("Chave privada informada: {}", your_private_key_hex);
            println!("Chave pública gerada: {}", pub_key);
        }
        Err(e) => println!("Erro: {}", e),
    }
}
