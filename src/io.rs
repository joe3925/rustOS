use crate::error::IoError;

/// Provides IO error as an associated type.
///
/// Must be implemented for all types that also implement at least one of the following traits: `Read`, `Write`,
/// `Seek`.
pub trait IoBase {
    /// Type of errors returned by input/output operations.
    type Error: IoError;
}

/// The `Read` trait allows for reading bytes from a source.
///
/// It is based on the `std::io::Read` trait.
use kernel_types::async_ffi::{FfiFuture, FutureExt};

pub trait Read: IoBase {
    /// Pull some bytes from this source into the specified buffer, returning how many bytes were read.
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> FfiFuture<Result<usize, Self::Error>>;

    /// Read the exact number of bytes required to fill `buf`.
    fn read_exact<'a>(&'a mut self, buf: &'a mut [u8]) -> FfiFuture<Result<(), Self::Error>> {
        async move {
            let mut buf = buf;
            while !buf.is_empty() {
                match self.read(buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        let tmp = buf;
                        buf = &mut tmp[n..];
                    }
                    Err(ref e) if e.is_interrupted() => {}
                    Err(e) => return Err(e),
                }
            }
            if buf.is_empty() {
                Ok(())
            } else {
                Err(Self::Error::new_unexpected_eof_error())
            }
        }
        .into_ffi()
    }
}

/// The `Write` trait allows for writing bytes into the sink.
pub trait Write: IoBase {
    /// Write a buffer into this writer, returning how many bytes were written.
    fn write<'a>(&'a mut self, buf: &'a [u8]) -> FfiFuture<Result<usize, Self::Error>>;

    /// Attempts to write an entire buffer into this writer.
    fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> FfiFuture<Result<(), Self::Error>> {
        async move {
            let mut buf = buf;
            while !buf.is_empty() {
                match self.write(buf).await {
                    Ok(0) => {
                        return Err(Self::Error::new_write_zero_error());
                    }
                    Ok(n) => buf = &buf[n..],
                    Err(ref e) if e.is_interrupted() => {}
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        }
        .into_ffi()
    }

    /// Flush this output stream, ensuring that all intermediately buffered contents reach their destination.
    fn flush(&mut self) -> FfiFuture<Result<(), Self::Error>>;
}

/// Enumeration of possible methods to seek within an I/O object.
///
/// It is based on the `std::io::SeekFrom` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeekFrom {
    /// Sets the offset to the provided number of bytes.
    Start(u64),
    /// Sets the offset to the size of this object plus the specified number of bytes.
    End(i64),
    /// Sets the offset to the current position plus the specified number of bytes.
    Current(i64),
}

/// The `Seek` trait provides a cursor which can be moved within a stream of bytes.
///
/// It is based on the `std::io::Seek` trait.
pub trait Seek: IoBase {
    /// Seek to an offset, in bytes, in a stream.
    ///
    /// A seek beyond the end of a stream or to a negative position is not allowed.
    ///
    /// If the seek operation completed successfully, this method returns the new position from the start of the
    /// stream. That position can be used later with `SeekFrom::Start`.
    ///
    /// # Errors
    /// Seeking to a negative offset is considered an error.
    fn seek(&mut self, pos: SeekFrom) -> Result<u64, Self::Error>;
}

pub(crate) trait ReadLeExt {
    type Error;
    fn read_u8(&mut self) -> FfiFuture<Result<u8, Self::Error>>;
    fn read_u16_le(&mut self) -> FfiFuture<Result<u16, Self::Error>>;
    fn read_u32_le(&mut self) -> FfiFuture<Result<u32, Self::Error>>;
}

impl<T: Read> ReadLeExt for T {
    type Error = <Self as IoBase>::Error;

    fn read_u8(&mut self) -> FfiFuture<Result<u8, Self::Error>> {
        async move {
            let mut buf = [0_u8; 1];
            self.read_exact(&mut buf).await?;
            Ok(buf[0])
        }
        .into_ffi()
    }

    fn read_u16_le(&mut self) -> FfiFuture<Result<u16, Self::Error>> {
        async move {
            let mut buf = [0_u8; 2];
            self.read_exact(&mut buf).await?;
            Ok(u16::from_le_bytes(buf))
        }
        .into_ffi()
    }

    fn read_u32_le(&mut self) -> FfiFuture<Result<u32, Self::Error>> {
        async move {
            let mut buf = [0_u8; 4];
            self.read_exact(&mut buf).await?;
            Ok(u32::from_le_bytes(buf))
        }
        .into_ffi()
    }
}

pub(crate) trait WriteLeExt {
    type Error;
    fn write_u8(&mut self, n: u8) -> FfiFuture<Result<(), Self::Error>>;
    fn write_u16_le(&mut self, n: u16) -> FfiFuture<Result<(), Self::Error>>;
    fn write_u32_le(&mut self, n: u32) -> FfiFuture<Result<(), Self::Error>>;
}

impl<T: Write> WriteLeExt for T {
    type Error = <Self as IoBase>::Error;

    fn write_u8(&mut self, n: u8) -> FfiFuture<Result<(), Self::Error>> {
        async move {
            self.write_all(&[n]).await
        }
        .into_ffi()
    }

    fn write_u16_le(&mut self, n: u16) -> FfiFuture<Result<(), Self::Error>> {
        async move {
            self.write_all(&n.to_le_bytes()).await
        }
        .into_ffi()
    }

    fn write_u32_le(&mut self, n: u32) -> FfiFuture<Result<(), Self::Error>> {
        async move {
            self.write_all(&n.to_le_bytes()).await
        }
        .into_ffi()
    }
}
