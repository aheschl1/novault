
use aes_gcm::{KeyInit, aead::Aead};
use argon2::{Argon2, Params};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hex::ToHex;
use zeroize::{ZeroizeOnDrop, Zeroizing};
use anyhow::{Result, anyhow};


#[derive(ZeroizeOnDrop, Clone)]
pub struct CachedPassword {
    password: String,
    cache: Option<CachedPasswordInner>,
    // tag: u32
}

impl PartialEq for CachedPassword {
    fn eq(&self, other: &Self) -> bool {
        self.password.eq(&other.password)
    }
}

impl CachedPassword {
    pub fn from_string(str: String) -> Self {
        Self {
            password: str,
            cache: None,
            // tag: rand::random()
        }
    }
    pub fn get_password(&mut self, test_salt: &[u8; 16]) -> Result<UserVaultKey> {
        Ok(match &mut self.cache {
            Some(CachedPasswordInner { salt, password }) => {
                if *salt == *test_salt {
                    UserVaultKey {
                        key: *password,
                        salt: *salt
                    }
                } else {
                    // println!("RESEEDING {}", self.tag);
                    let new_pass = get_password(&self.password, &*test_salt)?;
                    *salt = *test_salt;
                    *password = new_pass;
                    self.get_password(test_salt)?
                }
            }
            None => {
                // println!("RESEEDING (2) {}", self.tag);
                let new_pass = get_password(&self.password, &*test_salt)?;
                self.cache = Some(CachedPasswordInner {
                    password: new_pass,
                    salt: *test_salt
                });
                self.get_password(test_salt)?
            }
        })
    }
}

#[derive(ZeroizeOnDrop, Clone)]
struct CachedPasswordInner {
    salt: [u8; 16],
    password: [u8; 32]
}

#[derive(ZeroizeOnDrop)]
pub struct UserVaultKey {
    key: [u8; 32],
    salt: [u8; 16]
}

impl UserVaultKey {
    pub fn init_with_salt(password: &mut CachedPassword, salt: &[u8; 16]) -> Result<Self> {
        Ok(password.get_password(salt)?)
    }
    pub fn init_fresh(password: &mut CachedPassword) -> Result<Self> {
        let mut salt = [0u8; 16];
        rand::fill(&mut salt);
        Self::init_with_salt(password, &salt)
    }

    // pub fn init_raw(key: [u8; 16])
}

fn get_password(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let params = Params::new(64 * 1024, 2, 1, Some(32))
        .map_err(|e| anyhow::anyhow!("Failed to initialize Argon2id parameters: {e:?}"))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut out = [0u8; 32];
    argon2.hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| anyhow!("Failed to hash Argon2id password: {e:?}"))?;

    Ok(out)
}


#[derive(ZeroizeOnDrop)]
pub struct MasterVaultKey {
    key: [u8; 32]
}

impl MasterVaultKey {
    pub fn generate() -> Self {
        Self {
            key: rand::random()
        }
    }
    pub fn key_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

#[derive(ZeroizeOnDrop)]
pub struct WrappedKey {
    salt: [u8; 16],
    nonce: [u8; 24],
    payload: Vec<u8>
}

impl WrappedKey {
    pub fn init(user: &UserVaultKey, master: &MasterVaultKey) -> Result<Self> {
        generate_wrapped_mk(user, master)
    }
    pub fn get_master_key_with_no_rewrap(&self, passphrase: &mut CachedPassword) -> Result<MasterVaultKey> {
        
        let key_phrase = Zeroizing::new(passphrase.get_password(&self.salt)?.key);
        
        // let key_phrase = get_password(passphrase, &self.salt)?;
        
        let key = Key::from_slice(&*key_phrase);
        let cipher = XChaCha20Poly1305::new(&key);



        let result = cipher.decrypt(XNonce::from_slice(&self.nonce), &*self.payload)
            .map_err(|_| anyhow::anyhow!("Failed to decrypt master key with provided password."))?;


        let new_master = MasterVaultKey {
            key: result.try_into().unwrap()
        };

        Ok(new_master)
    }
    pub fn get_master_key(&self, passphrase: &mut CachedPassword) -> Result<(Self, MasterVaultKey)> {

        let new_master = self.get_master_key_with_no_rewrap(passphrase)?;
        Ok((WrappedKey::init(&UserVaultKey::init_fresh(passphrase)?, &new_master)?, new_master
    ))

    }
    pub fn from_hex(string: &str) -> Result<Self> {

        let mut nonce = hex::decode(string)?;

        if nonce.len() <= 16 + 24 + 32 {
            return Err(anyhow!("Wrapped key is of the incorrect size."));
        }

        let mut salt = nonce.split_off(24);
        let payload = salt.split_off(16);


        Ok(Self {
            salt: salt.try_into()
                .unwrap(),
            nonce: nonce.try_into()
                .unwrap(),
            payload
        })
        

        


    }
    pub fn to_hex(&self) -> String {
        let mut buffer = Vec::with_capacity(16 + 24 + 32);
        buffer.extend_from_slice(&self.nonce);
        
        buffer.extend_from_slice(&self.salt);
        buffer.extend_from_slice(&self.payload);
        return buffer.encode_hex();
    }
}


fn generate_wrapped_mk(
    rkey: &UserVaultKey,
    master: &MasterVaultKey
) -> Result<WrappedKey> {

    let key = Key::from_slice(&rkey.key);
    let cipher = XChaCha20Poly1305::new(&key);


    let mut nbytes = [0u8; 24];
    rand::fill(&mut nbytes);


    let result = cipher.encrypt(XNonce::from_slice(&nbytes), &master.key as &[u8])
        .map_err(|_| anyhow!("Failed to encrypt the new wrapped key."))?;

    Ok(WrappedKey {
        salt: rkey.salt,
        nonce: nbytes,
        payload: result
    })
}


#[cfg(test)]
mod tests {
    use crate::sys::mk::{CachedPassword, MasterVaultKey, UserVaultKey, WrappedKey};


    #[test]
    pub fn check_password_match() {
        let salt = [0u8; 16];
        let password = UserVaultKey::init_with_salt(&mut CachedPassword::from_string("hello".to_string()), &salt).unwrap();
        let pass2 = UserVaultKey::init_with_salt(&mut CachedPassword::from_string("hello".to_string()), &salt).unwrap();
        assert_eq!(pass2.key, password.key);
    }

    #[test]
    pub fn check_wrapped_key() {
        let salt = [0u8; 16];
        let password = UserVaultKey::init_with_salt(&mut CachedPassword::from_string("helo".to_string()), &salt)
            .unwrap();

        let master = MasterVaultKey::generate();


        let wrapped = WrappedKey::init(&password, &master).unwrap();


        let (new_wrap, master_dev) = wrapped.get_master_key(&mut CachedPassword::from_string("helo".to_string())).unwrap();
        assert_eq!(master_dev.key, master.key);

        let (_, master_dev) = new_wrap.get_master_key(&mut CachedPassword::from_string("helo".to_string())).unwrap();
        assert_eq!(master_dev.key, master.key);


    }
}