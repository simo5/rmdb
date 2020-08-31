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
use openssl::sha;

#[macro_use]
extern crate bitflags;

const RMDB_PAGESIZE: usize = 4096;
const RMDB_MINSIZE: usize = RMDB_PAGESIZE * 3;
const RMDB_FILEVER: u32 = 1;
const RMDB_MAJOR: u16 = 0;
const RMDB_MINOR: u16 = 0;
const RMDB_RELEASE: u16 = 0;
const RMDB_RESERVED: u16 = 0;

#[derive(Debug)]
pub enum RmdbError {
    LockError,
    IntegrityCheck,
    InvalidIndexSize,
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
            RmdbError::InvalidIndexSize => write!(f, "Index too large"),
            RmdbError::IntegrityCheck => write!(f, "Integrity Check failed!"),
            RmdbError::LockError => write!(f, "Lock Poisoned Error"),
        }
    }
}

impl Error for RmdbError {
    fn cause(&self) -> Option<&dyn Error> {
        match *self {
            RmdbError::Io(ref err) => Some(err),
            RmdbError::InvalidDBFile => None,
            RmdbError::InvalidFileSize => None,
            RmdbError::InvalidIndexSize => None,
            RmdbError::IntegrityCheck => None,
            RmdbError::LockError => None,
        }
    }
}

impl From<std::io::Error> for RmdbError {
    fn from(error: io::Error) -> Self {
        RmdbError::Io(error)
    }
}

bitflags! {
    pub struct RmdbFlags: u32 {
        const PAGE_INTEGRITY = 1;
        const PAGE_ENCRYPTION = 2;
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
    flags: RmdbFlags,
    mmap: RwLock<RmdbMmap>,
    pointer: Mutex<u64>
}

impl Rmdb {
    /// Opens an existing rmdb database for read/write operations
    pub fn open(path: PathBuf, flags: RmdbFlags, create: bool) -> Result<Rmdb, RmdbError> {
        let mut file = OpenOptions::new()
                                    .read(true)
                                    .write(true)
                                    .create(create)
                                    .open(&path).map_err(RmdbError::Io)?;

        let pos = file.seek(SeekFrom::End(0)).map_err(RmdbError::Io)? as usize;
        let mut pages = size_to_pages(RMDB_PAGESIZE, pos);
        let mut initialize = false;

        if pos == 0 {
            /* New file created, truncate it to min size
             * This needs to be done here or the mmap open will fail */
            file.set_len(RMDB_MINSIZE as u64)?;
            initialize = true;
            pages = size_to_pages(RMDB_PAGESIZE, RMDB_MINSIZE);
        } else if pos < RMDB_MINSIZE {
            // corrupted or truncated file, abort
            return Err(RmdbError::InvalidFileSize)
        } else if pos != (pages as usize * RMDB_PAGESIZE) {
            // corrupted, not a multiple of page size
            return Err(RmdbError::InvalidFileSize)
        } else {
            initcheck(&file)?;
        }

        let mut rmdb = Rmdb {
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
            flags: flags,
            pointer: Mutex::new(0),
        };

        if initialize {
            rmdb.initialize().map_err(RmdbError::Io)?;
        }

        Ok(rmdb)
    }

    fn initialize(&mut self) -> std::io::Result<()> {
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write("RMDB".as_bytes())?;
        self.file.write(&RMDB_FILEVER.to_le_bytes())?;
        self.file.write(&self.flags.bits().to_le_bytes())?;
        for i in 1..3 {
            let mut page = RmdbWPage::new(self, self.get_writer().unwrap(), i).unwrap();
            page.set_page_num(i).unwrap();
            drop(page)
        }
        Ok(())
    }

    pub fn resize(&self, size: usize) -> Result<(), RmdbError> {
        let mut mmap = self.mmap.write().unwrap();

        if size < RMDB_MINSIZE {
            return Err(RmdbError::InvalidFileSize)
        }
        let pages = size_to_pages(RMDB_PAGESIZE, size);
        if pages == mmap.num_pages {
            return Ok(())
        }
        mmap.num_pages = pages;
        self.file.set_len(pages * RMDB_PAGESIZE as u64)?;
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

fn size_to_pages(page_size: usize, size: usize) -> u64 {
    return ((size + page_size - 1) / page_size) as u64;
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
    db: &'a Rmdb,
    mmap: RwLockReadGuard<'a, RmdbMmap>,
    index: u64
}

impl RmdbPage<'_> {
    pub fn new<'a>(db: &'a Rmdb, mmap: RwLockReadGuard<'a, RmdbMmap>, index: u64) -> Result<RmdbPage<'a>, RmdbError> {
        if index >= mmap.num_pages {
            return Err(RmdbError::InvalidIndexSize)
        }

        let page = RmdbPage {
            db: db,
            mmap: mmap,
            index: index
        };

        let err = page.integrity_check();
        match err {
            Ok(()) => Ok(page),
            Err(error) => Err(error)
        }
    }

    fn get_u64(&self, pos: usize) -> Result<u64, RmdbError> {
        if pos % std::mem::size_of::<u64>() != 0 {
            /* enforce alignment */
            return Err(RmdbError::InvalidIndexSize)
        }
        let (start, end) = page_range(self.index, pos,
                                      std::mem::size_of::<u64>()).unwrap();
        let data = &self.mmap.mmap[start..end];
        Ok(u64::from_le_bytes(data.try_into().unwrap()))
    }

    pub fn get_page_num(&self) -> Result<u64, RmdbError> {
        self.get_u64(0)
    }

    fn integrity_check(&self) -> Result<(), RmdbError> {
        if !self.db.flags.contains(RmdbFlags::PAGE_INTEGRITY) {
            return Ok(())
        }
        let (start, end) = page_range(self.index, 0,
                                      RMDB_PAGESIZE - 32).unwrap();
        let data = &self.mmap.mmap[start..end];
        let hash = compute_hash(data);
        let verify = &self.mmap.mmap[end..(end+32)];
        if verify != hash {
            return Err(RmdbError::IntegrityCheck)
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct RmdbWPage<'a> {
    db: &'a Rmdb,
    mmap: RwLockWriteGuard<'a, RmdbMmap>,
    index: u64
}

impl RmdbWPage<'_> {
    pub fn new<'a>(db: &'a Rmdb, mmap: RwLockWriteGuard<'a, RmdbMmap>, index: u64) -> Result<RmdbWPage<'a>, RmdbError> {
        if index >= mmap.num_pages {
            return Err(RmdbError::InvalidIndexSize)
        }

        Ok(RmdbWPage { db: db, mmap: mmap, index: index })
    }

    fn set_u64(&mut self, pos: usize, value: u64) -> Result<(), RmdbError> {
        if pos % std::mem::size_of::<u64>() != 0 {
            /* enforce alignment */
            return Err(RmdbError::InvalidIndexSize)
        }
        let (start, end) = page_range(self.index, pos,
                                      std::mem::size_of::<u64>()).unwrap();
        let data = self.mmap.mmap.get_mut(start..end).unwrap();
        data.copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn set_buf(&mut self, pos: usize, buf: &[u8]) -> Result<(), RmdbError> {
        let (start, end) = page_range(self.index, pos, buf.len()).unwrap();
        let data = self.mmap.mmap.get_mut(start..end).unwrap();
        data.copy_from_slice(buf);
        Ok(())
    }

    pub fn set_page_num(&mut self, num: u64) -> Result<(), RmdbError> {
        self.set_u64(0, num)
    }

    fn integrity_protect(&mut self) {
        if !self.db.flags.contains(RmdbFlags::PAGE_INTEGRITY) {
            return
        }
        let (start, end) = page_range(self.index, 0,
                                      RMDB_PAGESIZE - 32).unwrap();
        let data = &self.mmap.mmap[start..end];
        let hash = compute_hash(data);
        self.set_buf(RMDB_PAGESIZE - 32, &hash).unwrap();
    }
}

impl Drop for RmdbWPage<'_> {
    fn drop(&mut self) {
        self.integrity_protect();
        //TODO: Make flushing optional
        let (start, end) = page_range(self.index, 0, RMDB_PAGESIZE).unwrap();
        self.mmap.mmap.flush_async_range(start, end).unwrap();
    }
}

fn page_range(index: u64, offset: usize, size: usize)
                -> Result<(usize, usize), RmdbError> {
    if offset + size > RMDB_PAGESIZE {
        return Err(RmdbError::InvalidIndexSize)
    }
    let base = (index as usize) * RMDB_PAGESIZE;
    Ok((
        (base + offset),
        (base + offset + size)
    ))
}

fn compute_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha::Sha256::new();
    hasher.update(data);
    hasher.finish()
}
