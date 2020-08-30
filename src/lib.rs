use std::convert::TryInto;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

use memmap::MmapMut;

const RMDB_PAGESIZE: u64 = 4096;
const RMDB_MINSIZE: u64 = RMDB_PAGESIZE * 3;
const RMDB_FILEVER: u32 = 1;
const RMDB_MAJOR: u16 = 0;
const RMDB_MINOR: u16 = 0;
const RMDB_RELEASE: u16 = 0;
const RMDB_RESERVED: u16 = 0;

#[derive(Debug)]
pub enum RmdbError {
    InvalidIndexSize,
    InvalidFileSize,
    InvalidDBFile,
    LockError,
    Io(io::Error),
}

impl fmt::Display for RmdbError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RmdbError::Io(ref err) => write!(f, "IO error: {}", err),
            RmdbError::LockError => write!(f, "Lock Poisoned Error"),
            RmdbError::InvalidDBFile => write!(f, "Invalid DB file contents"),
            RmdbError::InvalidFileSize => write!(f, "File of invalid size"),
            RmdbError::InvalidIndexSize => write!(f, "Index too large"),
        }
    }
}

impl Error for RmdbError {
    fn cause(&self) -> Option<&dyn Error> {
        match *self {
            RmdbError::Io(ref err) => Some(err),
            RmdbError::LockError => None,
            RmdbError::InvalidDBFile => None,
            RmdbError::InvalidFileSize => None,
            RmdbError::InvalidIndexSize => None,
        }
    }
}

impl From<std::io::Error> for RmdbError {
    fn from(error: io::Error) -> Self {
        RmdbError::Io(error)
    }
}

#[derive(Debug)]
pub struct RmdbMmap {
    mmap: MmapMut,
    num_pages: u64,
}

#[derive(Debug)]
pub struct Rmdb {
    path: PathBuf,
    file: File,
    mmap: RwLock<RmdbMmap>,
    pointer: Mutex<u64>
}

impl Rmdb {
    /// Opens an existing rmdb database for read/write operations
    pub fn open(path: PathBuf, create: bool) -> Result<Rmdb, RmdbError> {
        let mut file = OpenOptions::new()
                                    .read(true)
                                    .write(true)
                                    .create(create)
                                    .open(&path).map_err(RmdbError::Io)?;

        let pos = file.seek(SeekFrom::End(0)).map_err(RmdbError::Io)?;
        let mut pages = size_to_pages(RMDB_PAGESIZE, pos);

        if pos == 0 {
            // New file created, truncate it to min size
            initialize(&file).map_err(RmdbError::Io)?;
            pages = size_to_pages(RMDB_PAGESIZE, RMDB_MINSIZE);
        } else if pos < RMDB_MINSIZE {
            // corrupted or truncated file, abort
            return Err(RmdbError::InvalidFileSize)
        } else if pos != (pages * RMDB_PAGESIZE) {
            // corrupted, not a multiple of page size
            return Err(RmdbError::InvalidFileSize)
        } else {
            initcheck(&file)?;
        }



        Ok(
            Rmdb {
                mmap: unsafe {
                    RwLock::new(
                        RmdbMmap {
                            mmap: MmapMut::map_mut(&file).map_err(RmdbError::Io)?,
                            num_pages: pages,
                        }
                    )
                },
                path: path,
                file: file,
                pointer: Mutex::new(0),
            }
        )
    }

    pub fn resize(&self, size: u64) -> Result<(), RmdbError> {
        let mut mmap = self.mmap.write().unwrap();

        if size < RMDB_MINSIZE {
            return Err(RmdbError::InvalidFileSize)
        }
        let pages = size_to_pages(RMDB_PAGESIZE, size);
        if pages == mmap.num_pages {
            return Ok(())
        }
        self.file.set_len(pages * RMDB_PAGESIZE)?;
        unsafe {
            Ok(mmap.mmap = MmapMut::map_mut(&self.file).map_err(RmdbError::Io)?)
        }
    }

    pub fn version(&self) -> u64 {
        return (RMDB_MAJOR as u64) << 48 +
               (RMDB_MINOR as u64) << 32 +
               (RMDB_RELEASE as u64) << 16 +
               (RMDB_RESERVED as u64)
    }

    pub fn get_reader(&self) -> Result<RwLockReadGuard<'_, RmdbMmap>, RmdbError> {
        let res = self.mmap.read();
        match res {
            Ok(mmap) => Ok(mmap),
            Err(_er) => Err(RmdbError::LockError)
        }
    }

    pub fn get_writer(&self) -> Result<RwLockWriteGuard<'_, RmdbMmap>, RmdbError> {
        let res = self.mmap.write();
        match res {
            Ok(mmap) => Ok(mmap),
            Err(_er) => Err(RmdbError::LockError)
        }
    }
}

impl Drop for Rmdb {
    fn drop(&mut self) {
        let mmap = self.mmap.write().unwrap();
        let err = mmap.mmap.flush();
        let _err = match err {
            Ok(()) => (),
            Err(error) => eprintln!("Failed to fflush mmap: {:?}", error),
        };
    }
}

fn size_to_pages(page_size: u64, size: u64) -> u64 {
    return (size + page_size - 1) / page_size;
}

fn initialize(mut f: &std::fs::File) -> std::io::Result<()> {
    f.set_len(RMDB_MINSIZE)?;
    f.seek(SeekFrom::Start(0))?;
    f.write("RMDB".as_bytes())?;
    f.write(&RMDB_FILEVER.to_le_bytes())?;
    // set page numbers of first 2 pages
    f.seek(SeekFrom::Start(RMDB_PAGESIZE))?;
    f.write(&1u64.to_le_bytes())?;
    f.seek(SeekFrom::Start(RMDB_PAGESIZE * 2))?;
    f.write(&2u64.to_le_bytes())?;
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

#[derive(Debug)]
pub struct RmdbPage<'a> {
    mmap: RwLockReadGuard<'a, RmdbMmap>,
    index: u64
}

impl RmdbPage<'_> {
    pub fn new<'a>(mmap: RwLockReadGuard<'a, RmdbMmap>, index: u64) -> Result<RmdbPage<'a>, RmdbError> {
        if index >= mmap.num_pages {
            return Err(RmdbError::InvalidIndexSize)
        }

        Ok(RmdbPage { mmap: mmap, index: index })
    }

    fn get_u64(&self, pos: usize) -> Result<u64, RmdbError> {
        if pos % std::mem::size_of::<u64>() != 0 {
            return Err(RmdbError::InvalidIndexSize)
        }
        if pos > RMDB_PAGESIZE as usize - std::mem::size_of::<u64>() {
            return Err(RmdbError::InvalidIndexSize)
        }
        let start = (self.index * RMDB_PAGESIZE) as usize + pos;
        let end = start + std::mem::size_of::<u64>();
        let data = &self.mmap.mmap[start..end];
        Ok(u64::from_le_bytes(data.try_into().unwrap()))
    }

    pub fn get_page_num(&self) -> Result<u64, RmdbError> {
        self.get_u64(0)
    }
}

#[derive(Debug)]
pub struct RmdbWPage<'a> {
    mmap: RwLockWriteGuard<'a, RmdbMmap>,
    index: u64
}

impl RmdbWPage<'_> {
    pub fn new<'a>(mmap: RwLockWriteGuard<'a, RmdbMmap>, index: u64) -> Result<RmdbWPage<'a>, RmdbError> {
        if index >= mmap.num_pages {
            return Err(RmdbError::InvalidIndexSize)
        }

        Ok(RmdbWPage { mmap: mmap, index: index })
    }

    fn set_u64(&mut self, pos: usize, value: u64) -> Result<(), RmdbError> {
        if pos % std::mem::size_of::<u64>() != 0 {
            return Err(RmdbError::InvalidIndexSize)
        }
        if pos > RMDB_PAGESIZE as usize - std::mem::size_of::<u64>() {
            return Err(RmdbError::InvalidIndexSize)
        }
        let start = (self.index * RMDB_PAGESIZE) as usize + pos;
        let end = start + std::mem::size_of::<u64>();
        let data = self.mmap.mmap.get_mut(start..end).unwrap();
        data.copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    pub fn set_page_num(&mut self, num: u64) -> Result<(), RmdbError> {
        self.set_u64(0, num)
    }
}

impl Drop for RmdbWPage<'_> {
    fn drop(&mut self) {
        //TODO: Make flushing optional
        let (start, end) = page_range(self.index, 0, RMDB_PAGESIZE).unwrap();
        self.mmap.mmap.flush_async_range(start, end).unwrap();
    }
}

fn page_range(index: u64, offset: u64, size: u64) -> Result<(usize, usize),
                                                            RmdbError> {
    if offset + size > RMDB_PAGESIZE {
        return Err(RmdbError::InvalidIndexSize)
    }
    let base = index * RMDB_PAGESIZE;
    Ok((
        (base + offset) as usize,
        (base + offset + size) as usize
    ))
}
