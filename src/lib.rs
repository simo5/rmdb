use std::convert::TryInto;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::Seek;
use std::io::SeekFrom;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

use memmap::{Mmap, MmapMut};
use openssl::sha;

#[macro_use]
extern crate bitflags;

const RMDB_PAGESIZE: usize = 4096;
const RMDB_MINSIZE: usize = RMDB_PAGESIZE * 64;
const RMDB_FILEVER: u32 = 1;
const RMDB_MAJOR: u16 = 0;
const RMDB_MINOR: u16 = 0;
const RMDB_RELEASE: u16 = 0;
const RMDB_RESERVED: u16 = 0;
const RMDB_INTGSIZE: usize = 32;

/* The Zeroth page contains the DB basic configuration and status
 *   0              32              64
 *   ---------------------------------
 * 0 |  RMDB        |  VERSION       |
 *   |-------------------------------|
 * 1 |  FLAGS       |  RESERVED      |
 *   |-------------------------------|
 * 2 |          MAIN PAGE            |
 *   |-------------------------------|
 *
 * Page number 1 and 2 are the two main pages,
 * The page pointed by the zeroth page index is the readers page,
 * The other is the main page used by the writer.
 *
 * The main pages have this structure:
 *   0              32              64
 *   ---------------------------------
 *   |   FREE PAGES: each bit is a   |
 *   |   free page (from page 0)     |
 *   .   ...                         .
 *   .                               .
 *   |--------------------------------
 *   |   PTR TO NEXT FREE PAGES      |
 *   |-------------------------------|
 *   |   PTR TO ROOT NODE PAGE       |
 *   |-------------------------------|
 *   . OPIONAL INTEGRITY/ENCRYPTION  .
 *   .................................
 */
const RMDB_P_SIG: usize = 0;
const RMDB_P_VER: usize = 4;
const RMDB_P_FLAGS: usize = 8;
//const RMDB_P_RES1: usize = 12;
const RMDB_P_RMAIN: usize = 16;
const RMDB_P_WMAIN: usize = 24;

#[derive(Debug)]
pub enum RmdbError {
    UnalignedAccess,
    LockError,
    IntegrityCheck,
    InvalidIndexSize,
    InvalidFileSize,
    InvalidDBFile,
    InvalidTransaction,
    Io(io::Error),
}

impl fmt::Display for RmdbError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RmdbError::Io(ref err) => write!(f, "IO error: {}", err),
            RmdbError::InvalidTransaction => write!(f, "Transaction already closed"),
            RmdbError::InvalidDBFile => write!(f, "Invalid DB file contents"),
            RmdbError::InvalidFileSize => write!(f, "File of invalid size"),
            RmdbError::InvalidIndexSize => write!(f, "Index too large"),
            RmdbError::IntegrityCheck => write!(f, "Integrity Check failed!"),
            RmdbError::LockError => write!(f, "Lock Poisoned Error"),
            RmdbError::UnalignedAccess => write!(f, "Unaligned Access Request"),
        }
    }
}

impl Error for RmdbError {
    fn cause(&self) -> Option<&dyn Error> {
        match *self {
            RmdbError::Io(ref err) => Some(err),
            RmdbError::InvalidTransaction => None,
            RmdbError::InvalidDBFile => None,
            RmdbError::InvalidFileSize => None,
            RmdbError::InvalidIndexSize => None,
            RmdbError::IntegrityCheck => None,
            RmdbError::LockError => None,
            RmdbError::UnalignedAccess => None,
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
struct RmdbRMap {
    mmap: Mmap,             // the global mmap for reading only
    mainpage: u64,          // the main read root page
    num_pages: u64,         // copy of Rmdb's num_pages
    flags: RmdbFlags,       // copy of Rmdb's flags
}

#[derive(Debug)]
struct RmdbWMap {
    mmap: MmapMut,          // the global mmap for writing
    mainpage: u64,          // the main write root page
    num_pages: u64,         // copy of Rmdb's num_pages
    flags: RmdbFlags,       // copy of Rmdb's flags
}

#[derive(Debug)]
pub struct Rmdb {
    path: PathBuf,              // file name for db
    file: File,                 // file handle
    num_pages: u64,             // max num pages allocated
    flags: RmdbFlags,           // db flags
    rmap: RwLock<RmdbRMap>,     // read root pointer
    wmap: Mutex<RmdbWMap>,      // the global mmap for writing
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
            num_pages: pages,
            flags: flags,
            rmap: RwLock::new(
                RmdbRMap {
                    mmap: unsafe {
                        Mmap::map(&file).map_err(RmdbError::Io)?
                    },
                    mainpage: 1,
                    num_pages: pages,
                    flags: flags,
                }
            ),
            wmap: Mutex::new(
                RmdbWMap {
                    mmap: unsafe {
                        MmapMut::map_mut(&file).map_err(RmdbError::Io)?
                    },
                    mainpage: 2,
                    num_pages: pages,
                    flags: flags,
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

    fn initialize(&mut self) -> Result<(), RmdbError> {
        let flags = self.flags;
        let mut page = self.get_write_page(0).unwrap();
        page.set_buf(RMDB_P_SIG, "RMDB".as_bytes())?;
        page.set_buf(RMDB_P_VER, &RMDB_FILEVER.to_le_bytes())?;
        page.set_buf(RMDB_P_FLAGS, &flags.bits().to_le_bytes())?;
        /* always point to first page on initialization */
        page.set_u64(RMDB_P_FLAGS, 1)?;
        drop(page);
        let pagesize = page_size(self.flags());
        for i in 1..3 {
            let mut page = self.get_write_page(i).unwrap();
            let freepagessize = pagesize - 8 - 8;
            let mut freepages = vec![u8::MAX; freepagessize];
            /* First three pages are always taken */
            freepages[0] = freepages[0] >> 3;
            page.set_buf(0, &freepages)?;
            /* Initial db has only one free page buf */
            page.set_u64(freepagessize, 0)?;
            /* and points to no root node page */
            page.set_u64(pagesize - 8, 0)?;
            drop(page)
        }
        Ok(())
    }

    fn integrity_check(&self) -> Result<(), RmdbError> {
        let page = self.get_read_page(0).unwrap();
        if page.get_buf(RMDB_P_SIG, 4).unwrap() != "RMDB".as_bytes() {
            return Err(RmdbError::IntegrityCheck)
        }
        if page.get_buf(RMDB_P_VER, 4).unwrap() != &RMDB_FILEVER.to_le_bytes() {
            return Err(RmdbError::IntegrityCheck)
        }
        Ok(())
    }

    fn setup(&mut self) -> Result<(), RmdbError> {
        let page = self.get_read_page(0).unwrap();
        let flags_buf = page.get_buf(RMDB_P_FLAGS, 4).unwrap().try_into().unwrap();
        let rmain = page.get_u64(RMDB_P_RMAIN).unwrap();
        let wmain = page.get_u64(RMDB_P_WMAIN).unwrap();
        drop(page);

        /* set flags compatibily with what's in the DB */
        let dbflags = RmdbFlags::from_bits(u32::from_le_bytes(flags_buf)).unwrap();

        if dbflags.contains(RmdbFlags::PAGE_INTEGRITY) {
            self.flags |= RmdbFlags::PAGE_INTEGRITY;
        } else {
            self.flags |= !RmdbFlags::PAGE_INTEGRITY;
        }

        /* Set current root page */
        let mut wmap = self.wmap.lock().unwrap();
        let mut rmap = self.rmap.write().unwrap();
        wmap.mainpage = wmain;
        rmap.mainpage = rmain;
        Ok(())
    }

    pub fn resize(&mut self, pages: u64) -> Result<(), RmdbError> {
        let size = pages as usize * RMDB_PAGESIZE;

        if size < RMDB_MINSIZE {
            return Err(RmdbError::InvalidFileSize)
        }

        let mut wmap = self.wmap.lock().unwrap();
        let mut rmap = self.rmap.write().unwrap();
        if pages == self.num_pages {
            return Ok(())
        }
        if pages < self.num_pages {
            return Err(RmdbError::InvalidFileSize)
        }
        self.file.set_len(pages * RMDB_PAGESIZE as u64)?;
        self.num_pages = pages;
        wmap.mmap = unsafe {
            MmapMut::map_mut(&self.file).map_err(RmdbError::Io)?
        };
        rmap.mmap = unsafe {
            Mmap::map(&self.file).map_err(RmdbError::Io)?
        };
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

    pub fn get_read_page<'a>(&'a self, page: u64) -> Result<RmdbPage<'a>, RmdbError> {
        let rmap = self.rmap.read().unwrap();
        if page >= rmap.num_pages {
            return Err(RmdbError::InvalidIndexSize)
        }
        page_integrity_check(&*rmap, page)?;

        Ok(RmdbPage {
            page: page,
            rmap: rmap,
        })
    }

    pub fn get_write_page<'a>(&'a self, page: u64) -> Result<RmdbWPage<'a>, RmdbError> {
        let wmap = self.wmap.lock().unwrap();
        if page >= wmap.num_pages {
            return Err(RmdbError::InvalidIndexSize)
        }
        Ok(RmdbWPage { wmap: wmap, page: page })
    }

    pub fn get_read_transaction<'a>(&'a self) -> Result<RmdbTxn<'a>, RmdbError> {
        let rmap = self.rmap.read().unwrap();
        let mainpage = self.get_read_page(rmap.mainpage).unwrap();
        let rootpage = mainpage.get_u64(page_size(self.flags) - 8)?;

        Ok(RmdbTxn {
            rmap: rmap,
            status: RmdbTxnState::Open,
            rootpage: rootpage,
        })
    }

    pub fn get_write_transaction<'a>(&'a self) -> Result<RmdbWTxn<'a>, RmdbError> {
        let rmap = self.rmap.read().unwrap();
        let trylock = self.wmap.try_lock();
        if let Ok(wmap) = trylock {
            let mut txn = RmdbWTxn {
                wmap: wmap,
                status: RmdbTxnState::Open,
                mainpage: [0; RMDB_PAGESIZE]
            };

            let page = self.get_read_page(rmap.mainpage)?;
            let pagesize = page_size(self.flags);
            let data = page.get_buf(0, pagesize)?;
            txn.mainpage[0..pagesize].clone_from_slice(data);

            Ok(txn)
        } else {
            Err(RmdbError::LockError)
        }
    }
}

impl Drop for Rmdb {
    fn drop(&mut self) {
        let wmap = self.wmap.lock().unwrap();
        match wmap.mmap.flush() {
            Ok(()) => (),
            Err(error) => eprintln!("Failed to fflush mmap: {:?}", error),
        };
    }
}

fn size_to_pages(page_size: usize, size: usize) -> u64 {
    return ((size + page_size - 1) / page_size) as u64;
}

pub fn page_size(flags: RmdbFlags) -> usize {
    let mut size = RMDB_PAGESIZE;
    if flags.contains(RmdbFlags::PAGE_INTEGRITY) {
        size -= RMDB_INTGSIZE;
    }
    return size;
}

fn page_integrity_check(rmap: &RmdbRMap, page: u64) -> Result<(), RmdbError> {
    if !rmap.flags.contains(RmdbFlags::PAGE_INTEGRITY) {
        return Ok(())
    }
    let (start, end) = page_range(page, 0, RMDB_PAGESIZE - 32).unwrap();
    let data = rmap.mmap.get(start..end).unwrap();
    let hash = compute_hash(data);
    let verify = rmap.mmap.get(end..(end+32)).unwrap();
    if verify != hash {
        return Err(RmdbError::IntegrityCheck)
    }
    Ok(())
}

fn get_u64(rmap: &RmdbRMap, page: u64, pos: usize) -> Result<u64, RmdbError> {
    if page >= rmap.num_pages {
        return Err(RmdbError::InvalidIndexSize)
    }
    if pos % std::mem::size_of::<u64>() != 0 {
        /* enforce alignment */
        return Err(RmdbError::UnalignedAccess)
    }
    let (start, end) = page_range(page, pos, std::mem::size_of::<u64>())?;
    let data = rmap.mmap.get(start..end).unwrap();
    Ok(u64::from_le_bytes(data.try_into().unwrap()))
}

fn get_buf<'a>(rmap: &'a RmdbRMap, page: u64, pos: usize, size: usize)
                                                -> Result<&'a [u8], RmdbError> {
    if page >= rmap.num_pages {
        return Err(RmdbError::InvalidIndexSize)
    }
    let (start, end) = page_range(page, pos, size)?;
    Ok(&rmap.mmap[start..end])
}

fn set_u64(wmap: &mut RmdbWMap, page: u64, pos: usize, value: u64)
                                                -> Result<(), RmdbError> {
    if page >= wmap.num_pages {
        return Err(RmdbError::InvalidIndexSize)
    }
    if pos % std::mem::size_of::<u64>() != 0 {
        /* enforce alignment */
        return Err(RmdbError::UnalignedAccess)
    }
    let (start, end) = page_range(page, pos, std::mem::size_of::<u64>())?;
    let data = wmap.mmap.get_mut(start..end).unwrap();
    data.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn set_buf(wmap: &mut RmdbWMap, page: u64, pos: usize, buf: &[u8])
                                                -> Result<(), RmdbError> {
    let (start, end) = page_range(page, pos, buf.len())?;
    let data = wmap.mmap.get_mut(start..end).unwrap();
    data.copy_from_slice(buf);
    Ok(())
}

fn integrity_protect(wmap: &mut RmdbWMap, page: u64)
                                                -> Result<(), RmdbError> {
    if !wmap.flags.contains(RmdbFlags::PAGE_INTEGRITY) {
        return Ok(())
    }
    let (start, end) = page_range(page, 0, RMDB_PAGESIZE - 32)?;
    let data = wmap.mmap.get_mut(start..end).unwrap();
    let hash = compute_hash(data);
    set_buf(wmap, page, RMDB_PAGESIZE - 32, &hash)
}

fn page_flush(wmap: &mut RmdbWMap, page: u64) -> Result<(), RmdbError> {
    let (start, end) = page_range(page, 0, RMDB_PAGESIZE)?;
    if wmap.flags.contains(RmdbFlags::PAGE_SYNC_FLUSH) {
        wmap.mmap.flush_range(start, end).unwrap();
    } else if wmap.flags.contains(RmdbFlags::PAGE_FLUSH) {
        wmap.mmap.flush_async_range(start, end).unwrap();
    }
    Ok(())
}

pub struct RmdbPage<'a> {
    rmap: RwLockReadGuard<'a, RmdbRMap>,
    page: u64,
}

impl RmdbPage<'_> {
    pub fn get_u64(&self, pos: usize) -> Result<u64, RmdbError> {
        get_u64(&*self.rmap, self.page, pos)
    }

    pub fn get_buf<'a>(&'a self, pos: usize, size: usize)
                                            -> Result<&'a [u8], RmdbError> {
        get_buf(&*self.rmap, self.page, pos, size)
    }
}

pub struct RmdbWPage<'a> {
    wmap: MutexGuard<'a, RmdbWMap>,
    page: u64,
}

impl RmdbWPage<'_> {
    pub fn set_u64(&mut self, pos: usize, value: u64)
                                                -> Result<(), RmdbError> {
        set_u64(&mut *self.wmap, self.page, pos, value)
    }

    pub fn set_buf(&mut self, pos: usize, buf: &[u8])
                                                -> Result<(), RmdbError> {
        set_buf(&mut *self.wmap, self.page, pos, buf)
    }
}

impl Drop for RmdbWPage<'_> {
    fn drop(&mut self) {
        integrity_protect(&mut *self.wmap, self.page).unwrap();
        page_flush(&mut *self.wmap, self.page).unwrap();
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

pub enum RmdbTxnState {
    Open,
    Committed,
    Scrubbed
}

pub struct RmdbTxn<'a> {
    rmap: RwLockReadGuard<'a, RmdbRMap>,
    status: RmdbTxnState,
    rootpage: u64,
}

impl RmdbTxn<'_> {
    pub fn get_entry(&self, key: &[u8]) -> Result<Vec<&[u8]>, RmdbError> {
        Err(RmdbError::InvalidTransaction)
    }

    fn _scrub(&mut self) {
        // TODO: something
        self.status = RmdbTxnState::Scrubbed
    }

    pub fn scrub(&mut self) -> Result<(), RmdbError> {
        match self.status {
            RmdbTxnState::Open => self._scrub(),
            _ => return Err(RmdbError::InvalidTransaction),
        };
        Ok(())
    }
}

impl Drop for RmdbTxn<'_> {
    fn drop(&mut self) {
        match self.status {
            RmdbTxnState::Open => self.scrub().unwrap(),
            _ => {}
        }
    }
}

pub struct RmdbWTxn<'a> {
    wmap: MutexGuard<'a, RmdbWMap>,
    status: RmdbTxnState,
    mainpage: [u8; RMDB_PAGESIZE],
}

impl RmdbWTxn<'_> {
    pub fn get_entry(&self, key: &[u8]) -> Result<Vec<&[u8]>, RmdbError> {
        Err(RmdbError::InvalidTransaction)
    }

    pub fn add_entry(&mut self, key: &[u8], value: &[u8]) -> Result<(), RmdbError> {
        write_entry(&mut *self.wmap, &mut self.mainpage, key, value)
    }

    fn _scrub(&mut self) {
        self.status = RmdbTxnState::Scrubbed
    }

    pub fn scrub(&mut self) -> Result<(), RmdbError> {
        match self.status {
            RmdbTxnState::Open => self._scrub(),
            _ => return Err(RmdbError::InvalidTransaction),
        };
        Ok(())
    }

    pub fn commit(&mut self) -> Result<(), RmdbError> {
        let pagesize = page_size(self.wmap.flags);
        let mainpage = self.wmap.mainpage;
        set_buf(&mut *self.wmap, mainpage, 0, &self.mainpage[0..pagesize])?;
        integrity_protect(&mut *self.wmap, mainpage)?;
        page_flush(&mut *self.wmap, mainpage)?;
        self.status = RmdbTxnState::Committed;
        Ok(())
    }
}

impl Drop for RmdbWTxn<'_> {
    fn drop(&mut self) {
        match self.status {
            RmdbTxnState::Open => self.scrub().unwrap(),
            _ => {}
        }
    }
}

// TODO: need to add support for multiple free page buffers
fn get_free_page(freepages: &mut [u8]) -> Result<u64, RmdbError> {
    for i in 0..freepages.len() {
        if freepages[i] != 0xff {
            for j in 0..7 {
                let x = 0b10000000u8 >> j;
                let val = freepages[i] | x;
                if val != freepages[i] {
                    freepages[i] = val;
                    return Ok((i * 8 + j) as u64);
                }
            }
        }
    }
    Err(RmdbError::InvalidIndexSize)
}

fn write_entry(wmap: &mut RmdbWMap, mainpage: &mut [u8],
               key: &[u8], value: &[u8]) -> Result<(), RmdbError> {
    let pagesize = page_size(wmap.flags);

    let mut rootpage = u64::from_le_bytes(
                        mainpage[(pagesize - 8)..pagesize].try_into().unwrap());
    if rootpage == 0 {
        rootpage = get_free_page(&mut mainpage[0..(pagesize - 16)])?;
    }

    Ok(())
}
