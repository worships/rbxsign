use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rand::rngs::OsRng;
use std::fs::File;
use std::io::Write;
use base64::{engine::general_purpose, Engine};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(short, long)]
    bits: usize,

    #[arg(long, default_value = "PrivateKey.pem")]
    priv_out: String,

    #[arg(long, default_value = "PublicKey.pem")]
    pub_out: String,

    #[arg(long, default_value = "PublicKeyBlob.txt")]
    blob_out: String,
}

fn export_csp_public_blob(public_key: &RsaPublicKey, mod_len: usize) -> Vec<u8> {
    let modulus = public_key.n().to_bytes_le();
    let mut mod_bytes = vec![0u8; mod_len];
    mod_bytes[..modulus.len()].copy_from_slice(&modulus);

    let exp_bytes_vec = public_key.e().to_bytes_le();
    let mut exp_bytes = [0u8; 4];
    for (i, b) in exp_bytes_vec.iter().enumerate().take(4) {
        exp_bytes[i] = *b;
    }
    let exp_3bytes = &exp_bytes[..3];

    let mut blob = vec![];

    blob.extend_from_slice(&[
        0x06,
        0x02,
        0x00, 0x00,
        0x00, 0x24, 0x00, 0x00,
    ]);

    blob.extend_from_slice(&[b'R', b'S', b'A', b'1']);
    blob.extend_from_slice(&(mod_len as u32 * 8).to_le_bytes());

    let mut pubexp = [0u8; 4];
    pubexp[..3].copy_from_slice(exp_3bytes);
    blob.extend_from_slice(&pubexp);
    blob.extend_from_slice(&mod_bytes);

    blob
}

fn generate_keypair(key_size: usize, priv_key_name: &str, pub_key_name: &str) -> Result<(RsaPrivateKey, RsaPublicKey), Box<dyn std::error::Error>> {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, key_size)?;
    let priv_pem = private_key.to_pkcs1_pem(LineEnding::LF)?;
    File::create(priv_key_name)?.write_all(priv_pem.as_bytes())?;

    let public_key = RsaPublicKey::from(&private_key);
    let pub_pem = public_key.to_pkcs1_pem(LineEnding::LF)?;
    File::create(pub_key_name)?.write_all(pub_pem.as_bytes())?;

    Ok((private_key, public_key))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    if args.bits != 1024 && args.bits != 2048 {
        eprintln!("Only 1024 or 2048-bit keys are allowed.");
        std::process::exit(1);
    }

    let suffix = if args.bits == 1024 { "_1024" } else { "_2048" };

    let priv_out = if args.priv_out.ends_with(&format!("{}.pem", suffix)) {
        args.priv_out.clone()
    } else {
        let base = args.priv_out.trim_end_matches(".pem");
        format!("{}{}.pem", base, suffix)
    };
    let pub_out = if args.pub_out.ends_with(&format!("{}.pem", suffix)) {
        args.pub_out.clone()
    } else {
        let base = args.pub_out.trim_end_matches(".pem");
        format!("{}{}.pem", base, suffix)
    };
    let blob_out = if args.blob_out.ends_with(&format!("{}.txt", suffix)) {
        args.blob_out.clone()
    } else {
        let base = args.blob_out.trim_end_matches(".txt");
        format!("{}{}.txt", base, suffix)
    };

    let (_priv_key, pub_key) = generate_keypair(args.bits, &priv_out, &pub_out)?;
    let blob = export_csp_public_blob(&pub_key, args.bits / 8);
    let b64_blob = general_purpose::STANDARD.encode(&blob);
    File::create(&blob_out)?.write_all(b64_blob.as_bytes())?;

    Ok(())
}