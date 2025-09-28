use hmac::Mac;
use sha2::Digest;

pub trait AlgoDigest {
    type Hasher: AlgoDigestHasher;
    type Hmac: AlgoDigestHmac;
}

pub trait AlgoDigestHasher {
    type Output: AsRef<[u8]>;
    const OUTPUT_SIZE: usize;

    fn new() -> Self;
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> Self::Output;
}

pub trait AlgoDigestHmac {
    type Output: AsRef<[u8]>;
    const OUTPUT_SIZE: usize;

    fn new(key: &[u8]) -> Self;
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> Self::Output;
}

pub struct AlgoSha256;

impl AlgoDigest for AlgoSha256 {
    type Hmac = AlgoSha256Hmac;
    type Hasher = AlgoSha256Hasher;
}

pub struct AlgoSha256Hasher(sha2::Sha256);

impl AlgoDigestHasher for AlgoSha256Hasher {
    type Output = [u8; 32];
    const OUTPUT_SIZE: usize = 32;

    fn new() -> Self {
        AlgoSha256Hasher(sha2::Sha256::new())
    }
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    fn finalize(self) -> Self::Output {
        self.0.finalize().into()
    }
}

pub struct AlgoSha256Hmac(hmac::Hmac<sha2::Sha256>);

impl AlgoDigestHmac for AlgoSha256Hmac {
    type Output = [u8; 32];
    const OUTPUT_SIZE: usize = 32;

    fn new(key: &[u8]) -> Self {
        // TODO: Unwrap
        AlgoSha256Hmac(hmac::Hmac::new_from_slice(key).unwrap())
    }
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    fn finalize(self) -> Self::Output {
        self.0.finalize().into_bytes().into()
    }
}
