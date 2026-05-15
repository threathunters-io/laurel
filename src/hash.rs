use sha2::{Digest, Sha256};

/// A simple adapter around `Sha256` that can be written to.
#[derive(Default)]
pub struct Sha256Writer(Sha256);

impl std::io::Write for Sha256Writer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Sha256Writer {
    pub fn finalize(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}
