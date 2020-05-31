use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::io;
use std::io::Seek;
use std::io::SeekFrom;

use memmap::MmapMut;

const MINDBSIZE: u64 = 4096;

#[derive(Debug)]
pub enum RmdbError {
    InvalidFileSize,
    UnrecoverableError,
    Io(io::Error),
}

impl fmt::Display for RmdbError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RmdbError::Io(ref err) => write!(f, "IO error: {}", err),
            RmdbError::UnrecoverableError => write!(f, "Unrecoverable Error"),
            RmdbError::InvalidFileSize => write!(f, "File of invalid size"),
        }
    }
}

impl Error for RmdbError {
    fn cause(&self) -> Option<&dyn Error> {
        match *self {
            RmdbError::Io(ref err) => Some(err),
            RmdbError::UnrecoverableError => None,
            RmdbError::InvalidFileSize => None,
        }
    }
}

#[derive(Debug)]
pub struct Rmdb {
    mmap: MmapMut
}

impl Rmdb {
    /// Opens an existing rmdb database for read/write operations
    pub fn open(path: &PathBuf, create: bool) -> Result<Rmdb, RmdbError> {
        let mut file = OpenOptions::new()
                                    .read(true)
                                    .write(true)
                                    .create(create)
                                    .open(&path).map_err(RmdbError::Io)?;

        let pos = file.seek(SeekFrom::End(0)).map_err(RmdbError::Io)?;

        if pos == 0 {
            // New file created, truncate it to min size

        } else if pos < MINDBSIZE {
            // corrupted or truncated file, abort
            return Err(RmdbError::InvalidFileSize)
        }

        Ok(Rmdb { mmap: unsafe { MmapMut::map_mut(&file).map_err(RmdbError::Io)? } })
    }

    pub fn close(&self) -> Result<(), RmdbError> {
        self.mmap.flush().map_err(RmdbError::Io)
    }
}
