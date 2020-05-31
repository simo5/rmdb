use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::io;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;

use memmap::MmapMut;

const RMDB_MINSIZE: u64 = 4096;
const RMDB_FILEVER: u32 = 1;
const RMDB_MAJOR: u16 = 0;
const RMDB_MINOR: u16 = 0;
const RMDB_RELEASE: u16 = 0;
const RMDB_RESERVED: u16 = 0;

#[derive(Debug)]
pub enum RmdbError {
    InvalidFileSize,
    InvalidDBFile,
    Io(io::Error),
}

impl fmt::Display for RmdbError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RmdbError::Io(ref err) => write!(f, "IO error: {}", err),
            RmdbError::InvalidDBFile => write!(f, "Invalid DB file contents"),
            RmdbError::InvalidFileSize => write!(f, "File of invalid size"),
        }
    }
}

impl Error for RmdbError {
    fn cause(&self) -> Option<&dyn Error> {
        match *self {
            RmdbError::Io(ref err) => Some(err),
            RmdbError::InvalidDBFile => None,
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
            initialize(&file).map_err(RmdbError::Io)?;
        } else if pos < RMDB_MINSIZE {
            // corrupted or truncated file, abort
            return Err(RmdbError::InvalidFileSize)
        } else {
            initcheck(&file)?;
        }

        Ok(Rmdb { mmap: unsafe { MmapMut::map_mut(&file).map_err(RmdbError::Io)? } })
    }

    pub fn close(&self) -> Result<(), RmdbError> {
        self.mmap.flush().map_err(RmdbError::Io)
    }

    pub fn version(&self) -> u64 {
        return (RMDB_MAJOR as u64) << 48 +
               (RMDB_MINOR as u64) << 32 +
               (RMDB_RELEASE as u64) << 16 +
               (RMDB_RESERVED as u64)
    }
}

fn initialize(mut f: &std::fs::File) -> std::io::Result<()> {
    f.set_len(RMDB_MINSIZE)?;
    f.seek(SeekFrom::Start(0))?;
    f.write("RMDB".as_bytes())?;
    f.write(&RMDB_FILEVER.to_le_bytes())?;
    Ok(())
}

fn initcheck(mut f: &std::fs::File) -> Result<(), RmdbError> {
    f.seek(SeekFrom::Start(0)).map_err(RmdbError::Io)?;

    let mut sig = [0; 8];
    let n = f.read(&mut sig).map_err(RmdbError::Io)?;
    if n != 8 {
        return Err(RmdbError::InvalidDBFile)
    }
    if b"RMDB" != &sig[0..4] {
        return Err(RmdbError::InvalidDBFile)
    }
    if &RMDB_FILEVER.to_le_bytes() != &sig[4..8] {
        return Err(RmdbError::InvalidDBFile)
    }
    Ok(())
}
