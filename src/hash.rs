use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use base64ct::{Base64, Encoding};
use digest::generic_array::ArrayLength;
use digest::generic_array::GenericArray;
use digest::Digest;
use pbkdf2::{
    password_hash::{Ident as PbIdent, SaltString as PbSaltString},
    Pbkdf2,
};
use scrypt::{password_hash::SaltString as ScSaltString, Scrypt};
use std::ops::Add;
use std::{fs, io};

fn print_hash<D>(param: &str, hash: GenericArray<u8, D>, b64: bool)
where
    D: ArrayLength<u8> + std::ops::Add,
    <D as Add>::Output: ArrayLength<u8>,
{
    if b64 {
        let base64_hash = Base64::encode_string(&hash);
        println!("{} {}", base64_hash, param);
    } else {
        println!("{:x} {}", hash, param);
    }
}

pub fn hash_file<D>(file: String, mut hasher: D, b64: bool)
where
    D: Clone,
    D: Digest,
    D: io::Write,
    D::OutputSize: Add,
    <D::OutputSize as Add>::Output: ArrayLength<u8>,
    D: digest::FixedOutputReset,
{
    let md = std::fs::metadata(&file).unwrap();

    let mut hashdir = hasher.clone();

    if md.is_file() {
        let mut input = fs::File::open(&file).expect("Unable to open the provided file.");
        io::copy(&mut input, &mut hasher).expect("io error while reading from file.");
        let hash = hasher.finalize();
        print_hash(&file, hash, b64);
    }

    if md.is_dir() {
        for entry in fs::read_dir(&file).expect("Error while reading dir.") {
            let entry = entry.expect("Error while reading dir.");
            let path = entry.path();
            if path.is_file() {
                let mut input = fs::File::open(&path).expect("Unable to open the provided file.");
                io::copy(&mut input, &mut hashdir).expect("io error while reading from file.");
                let hash = hashdir.finalize_reset();
                print_hash(path.to_str().unwrap(), hash, b64);
            }
        }
    }
}

pub fn hash_scrypt(password: String) {
    let salt = ScSaltString::generate(&mut OsRng);
    let password_hash = Scrypt
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string();
    println!("{} {}", password_hash, password);
}

pub fn hash_argon2(password: String) {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string();
    println!("{} {}", password_hash, password);
}

pub fn hash_pbkdf2(password: String, pb_scheme: &str) {
    let algorithm = PbIdent::new(pb_scheme).unwrap();

    let salt = PbSaltString::generate(&mut OsRng);

    let params = pbkdf2::Params {
        output_length: 32,
        rounds: 100_000,
    };

    let password_hash = Pbkdf2::hash_password_customized(
        &Pbkdf2,
        password.as_bytes(),
        Some(algorithm),
        None,
        params,
        salt.as_salt(),
    )
    .unwrap()
    .to_string();

    println!("{} {}", password_hash, password);
}

pub fn hash_string<D>(password: String, mut hasher: D, b64: bool)
where
    D: Digest,
    D::OutputSize: Add,
    <D::OutputSize as Add>::Output: ArrayLength<u8>,
{
    hasher.update(&password.as_bytes());
    let hash = hasher.finalize();
    print_hash(&password, hash, b64);
}
