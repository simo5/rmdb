use std::convert::TryInto;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::Seek;
use std::io::SeekFrom;
use std::path::PathBuf;
use std::sync::{RwLock, RwLockReadGuard};

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

const RMDB_P_SIG: usize = 0;
const RMDB_P_VER: usize = 4;
const RMDB_P_FLAGS: usize = 8;
//const RMDB_P_RES1: usize = 12;
const RMDB_P_ROOT: usize = 16;

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
        const PAGE_FLUSH = 4;
        const PAGE_SYNC_FLUSH = 8;
        const TRANSACTION_FLUSH = 16;
        const TRANSACTION_SYNC_FLUSH = 32;
    }
}

impl Default for RmdbFlags {
    fn default() -> RmdbFlags {
        RmdbFlags::PAGE_FLUSH | RmdbFlags::TRANSACTION_SYNC_FLUSH
    }
}

#[derive(Debug)]
pub struct RmdbRoot {
    mmap: MmapMut,
    num_pages: u64,
    rootpage: u64
}

#[derive(Debug)]
pub struct Rmdb {
    path: PathBuf,              // file name for db
    file: File,                 // file handle
    flags: RmdbFlags,           // db flags
    pub db: RwLock<RmdbRoot>,     // the global mmap and root info
}

impl Rmdb {
    /// Opens an existing rmdb database for read/write operations
    pub fn open(path: PathBuf, flags: RmdbFlags, create: bool)
            -> Result<Rmdb, RmdbError> {
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
        }

        let dflags = match flags.is_empty() {
            true => Default::default(),
            false => flags
        };

        let mut rmdb = Rmdb {
            path: path,
            flags: dflags,
            db: RwLock::new(
                RmdbRoot {
                    mmap: unsafe {
                        MmapMut::map_mut(&file).map_err(RmdbError::Io)?
                    },
                    num_pages: pages,
                    rootpage: 1
                }
            ),
            file: file,
        };

        if initialize {
            rmdb.initialize()?;
        } else {
            rmdb.integrity_check()?;
        }
        rmdb.setup()?;
        Ok(rmdb)
    }

    fn initialize(&self) -> Result<(), RmdbError> {
        let mut db = self.db.write().unwrap();
        let mut page = RmdbWPage::new(&mut *db, self.flags, 0).unwrap();
        page.set_buf(RMDB_P_SIG, "RMDB".as_bytes()).unwrap();
        page.set_buf(RMDB_P_VER, &RMDB_FILEVER.to_le_bytes()).unwrap();
        page.set_buf(RMDB_P_FLAGS, &self.flags.bits().to_le_bytes()).unwrap();
        /* always point to first page on initialization */
        page.set_u64(RMDB_P_FLAGS, 1).unwrap();
        drop(page);
        for i in 1..3 {
            let mut page = RmdbWPage::new(&mut *db, self.flags, i).unwrap();
            page.set_page_num(i).unwrap();
            drop(page)
        }
        drop(db);
        Ok(())
    }

    fn integrity_check(&self) -> Result<(), RmdbError> {
        let db = self.db.read().unwrap();
        let page = RmdbPage::new(&db, self.flags, 0).unwrap();
        if page.get_buf(RMDB_P_SIG, 4).unwrap() != "RMDB".as_bytes() {
            return Err(RmdbError::IntegrityCheck)
        }
        if page.get_buf(RMDB_P_VER, 4).unwrap() != &RMDB_FILEVER.to_le_bytes() {
            return Err(RmdbError::IntegrityCheck)
        }
        drop(db);
        Ok(())
    }

    fn setup(&mut self) -> Result<(), RmdbError> {
        let db = self.db.read().unwrap();
        let page = RmdbPage::new(&db, self.flags, 0).unwrap();
        let flags_buf = page.get_buf(RMDB_P_FLAGS, 4).unwrap().try_into().unwrap();
        let root_index = page.get_u64(RMDB_P_ROOT).unwrap();
        drop(page);
        drop(db);

        /* set flags compatibily with what's in the DB */
        let dbflags = RmdbFlags::from_bits(u32::from_le_bytes(flags_buf)).unwrap();

        if dbflags.contains(RmdbFlags::PAGE_INTEGRITY) {
            self.flags |= RmdbFlags::PAGE_INTEGRITY;
        } else {
            self.flags |= !RmdbFlags::PAGE_INTEGRITY;
        }

        /* Set current root page */
        let mut db = self.db.write().unwrap();
        db.rootpage = root_index;
        Ok(())
    }

    pub fn resize(&mut self, pages: u64) -> Result<(), RmdbError> {
        let size = pages as usize * RMDB_PAGESIZE;

        if size < RMDB_MINSIZE {
            return Err(RmdbError::InvalidFileSize)
        }

        let db = self.db.read().unwrap();
        if pages == db.num_pages {
            return Ok(())
        }
        if pages < db.num_pages {
            return Err(RmdbError::InvalidFileSize)
        }
        drop(db);
        let mut db = self.db.write().unwrap();
        self.file.set_len(pages * RMDB_PAGESIZE as u64)?;
        unsafe {
            db.mmap = MmapMut::map_mut(&self.file).map_err(RmdbError::Io)?;
        }
        db.num_pages = pages;
        drop(db);
        Ok(())
    }

    pub fn version(&self) -> u64 {
        return (RMDB_MAJOR as u64) << 48 +
               (RMDB_MINOR as u64) << 32 +
               (RMDB_RELEASE as u64) << 16 +
               (RMDB_RESERVED as u64)
    }

    pub fn flags(&self) -> RmdbFlags {
        return self.flags;
    }
}

impl Drop for Rmdb {
    fn drop(&mut self) {
        let db = self.db.read().unwrap();
        match db.mmap.flush() {
            Ok(()) => (),
            Err(error) => eprintln!("Failed to fflush mmap: {:?}", error),
        };
    }
}

fn size_to_pages(page_size: usize, size: usize) -> u64 {
    return ((size + page_size - 1) / page_size) as u64;
}

#[derive(Debug)]
pub struct RmdbPage<'a> {
    db: &'a RmdbRoot,
    flags: RmdbFlags,
    index: u64
}

impl RmdbPage<'_> {
    pub fn new<'a>(db: &RmdbRoot, flags: RmdbFlags, index: u64) -> Result<RmdbPage, RmdbError> {
        if index >= db.num_pages {
            return Err(RmdbError::InvalidIndexSize)
        }

        let page = RmdbPage {
            db: db,
            flags: flags,
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
        let data = self.db.mmap.get(start..end).unwrap();
        Ok(u64::from_le_bytes(data.try_into().unwrap()))
    }

    fn get_buf(&self, pos: usize, size: usize) -> Result<&[u8], RmdbError> {
        let (start, end) = page_range(self.index, pos, size).unwrap();
        Ok(self.db.mmap.get(start..end).unwrap())
    }

    pub fn get_page_num(&self) -> Result<u64, RmdbError> {
        self.get_u64(0)
    }

    fn integrity_check(&self) -> Result<(), RmdbError> {
        if !self.flags.contains(RmdbFlags::PAGE_INTEGRITY) {
            return Ok(())
        }
        let (start, end) = page_range(self.index, 0,
                                      RMDB_PAGESIZE - 32).unwrap();
        let data = self.db.mmap.get(start..end).unwrap();
        let hash = compute_hash(data);
        let verify = self.db.mmap.get(end..(end+32)).unwrap();
        if verify != hash {
            return Err(RmdbError::IntegrityCheck)
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct RmdbWPage<'a> {
    db: &'a mut RmdbRoot,
    flags: RmdbFlags,
    index: u64
}

impl RmdbWPage<'_> {
    pub fn new<'a>(db: & mut RmdbRoot, flags: RmdbFlags, index: u64) -> Result<RmdbWPage, RmdbError> {
        if index >= db.num_pages {
            return Err(RmdbError::InvalidIndexSize)
        }

        Ok(RmdbWPage { db: db, flags: flags, index: index })
    }

    fn set_u64(&mut self, pos: usize, value: u64) -> Result<(), RmdbError> {
        if pos % std::mem::size_of::<u64>() != 0 {
            /* enforce alignment */
            return Err(RmdbError::InvalidIndexSize)
        }
        let (start, end) = page_range(self.index, pos,
                                      std::mem::size_of::<u64>()).unwrap();
        let data = self.db.mmap.get_mut(start..end).unwrap();
        data.copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn set_buf(&mut self, pos: usize, buf: &[u8]) -> Result<(), RmdbError> {
        let (start, end) = page_range(self.index, pos, buf.len()).unwrap();
        let data = self.db.mmap.get_mut(start..end).unwrap();
        data.copy_from_slice(buf);
        Ok(())
    }

    pub fn set_page_num(&mut self, num: u64) -> Result<(), RmdbError> {
        self.set_u64(0, num)
    }

    fn integrity_protect(&mut self) {
        if !self.flags.contains(RmdbFlags::PAGE_INTEGRITY) {
            return
        }
        let (start, end) = page_range(self.index, 0,
                                      RMDB_PAGESIZE - 32).unwrap();
        let data = &self.db.mmap[start..end];
        let hash = compute_hash(data);
        self.set_buf(RMDB_PAGESIZE - 32, &hash).unwrap();
    }

    fn page_flush(&mut self) {
        let (start, end) = page_range(self.index, 0, RMDB_PAGESIZE).unwrap();
        if self.flags.contains(RmdbFlags::PAGE_SYNC_FLUSH) {
            self.db.mmap.flush_range(start, end).unwrap();
        } else if self.flags.contains(RmdbFlags::PAGE_FLUSH) {
            self.db.mmap.flush_async_range(start, end).unwrap();
        }
    }
}

impl Drop for RmdbWPage<'_> {
    fn drop(&mut self) {
        self.integrity_protect();
        self.page_flush();
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
