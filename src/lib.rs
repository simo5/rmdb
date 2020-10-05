use std::convert::TryInto;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::Seek;
use std::io::SeekFrom;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard};

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
 * 2 |          READ PAGE            |
 *   |-------------------------------|
 * 3 |         WRITE PAGE            |
 *   |-------------------------------|
 *   .   ...                         .
 *   .                               .
 *   |--------------------------------
 *   . OPIONAL INTEGRITY/ENCRYPTION  .
 *   .................................
 */
const RMDB_P_SIG: usize = 0;
const RMDB_P_VER: usize = 4;
const RMDB_P_FLAGS: usize = 8;
//const RMDB_P_RESERVED: usize = 12;
const RMDB_P_RMAIN: usize = 16;
const RMDB_P_WMAIN: usize = 24;

/* Page number 1 and 2 (at initialization) are the two main pages,
 * The page pointed by the zeroth page index is the readers page,
 * The other is the main page used by the writer.
 *
 * The main pages have this structure:
 *   0              32              64
 *   ---------------------------------
 * 0 |   PAGETYPE   |   RESERVED     |
 *   |-------------------------------|
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

const POS_PAGETYPE: usize = 0;
const MAIN_FREEPAGES: usize = 8;

const PAGE_MAIN: u32 = 1u32 << 0;
const PAGE_NODE: u32 = 1u32 << 1;
const PAGE_LEAF: u32 = 1u32 << 2;
const PAGE_DIRTY: u32 = 1u32 << 31;

/* Pages are of two types: node or leaf.
 * Node page structure:
 *   0              32              64
 *   ---------------------------------
 * 0 |   PAGETYPE   | # OF PAGE PTRs |
 *   |-------------------------------|
 *   | PAGE PTR for K#1              |
 *   |-------------------------------|
 *   | PAGE PTR for K#2              |
 *   |-------------------------------|
 *   .   ...                         .
 *   |-------------------------------|
 *   . OPIONAL INTEGRITY/ENCRYPTION  .
 *   .................................
 *
 * Key data is at the start of the page.
 * The key index is at the bottom of
 * the page and grows up. The keys data
 * (len, contents and page pointer start
 * at the top and grow down.
 */
const NODE_PAGETYPE: usize = POS_PAGETYPE; //u32
const NODE_NUMPTRS: usize = 4;   // u32
const NODE_FIRSTPTR: usize = 8;  // u64

const PAGEPTR_SIZE: usize = 8;   // u64

/* Leaf page structure:
 *   0              32              64
 *   ---------------------------------
 * 0 |   PAGETYPE    |  DATASIZE     |
 *   |-------------------------------|
 *   |  dLen | dPtr  | pgPtr | kLen  |
 *   |-------------------------------|
 *   | KEY ...                       |
 *   .   ...                         .
 *   |-------------------------------|
 *   . DATA ...                      .
 *   |-------------------------------|
 *   |   FIRST DATA PAGE PTR         |
 *   |--------------------------------
 *   .   ...                         .
 *   |-------------------------------|
 *   |   LAST DATA PAGE PTR          |
 *   |-------------------------------|
 *   . OPIONAL DATA INTEG/ENCR TAG   .
 *   |-------------------------------|
 *   . OPIONAL INTEGRITY/ENCRYPTION  .
 *   .................................
 *
 * The number of aditional pages is
 * dependent on DATALEN.
 * DATALEN/RAWPAGESIZE = #PAGES
 * Part or all of the content may also
 * be contained directly in the Leaf
 * page in the DATA section.
 */
const LEAF_PAGETYPE: usize = POS_PAGETYPE; //u32
const LEAF_DATASIZE: usize = 4;  // u32
const LEAF_DATALEN:  usize = 8;  // u16
const LEAF_DATAPTR:  usize = 10; // u16
const LEAF_PAGEPTR:  usize = 12; // u16
const LEAF_KEYLEN:   usize = 14; // u16
const LEAF_KEY:      usize = 16; // [u8]


#[derive(Debug)]
pub enum RmdbError {
    InvalidDataSize,
    KeyNotFound,
    InvalidMetadata,
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
            RmdbError::InvalidMetadata => write!(f, "Invalid metadata"),
            RmdbError::KeyNotFound => write!(f, "Key not found"),
            RmdbError::InvalidDataSize => write!(f, "Invalid data size"),
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
            RmdbError::InvalidMetadata => None,
            RmdbError::KeyNotFound => None,
            RmdbError::InvalidDataSize => None,
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

macro_rules! page_get_whole {
    ($mmap:expr, $page:expr) => {
        {
            let start = ($page as usize) * RMDB_PAGESIZE;
            let end = start + RMDB_PAGESIZE;
            &$mmap[start..end]
        }
    };
    (mut, $mmap:expr, $page:expr) => {
        {
            let start = ($page as usize) * RMDB_PAGESIZE;
            let end = start + RMDB_PAGESIZE;
            &mut $mmap[start..end]
        }
    };
}

macro_rules! page_get_payload {
    ($mmap:expr, $pagesize:expr, $page:expr) => {
        {
            let (start, end) = page_range($page, 0, $pagesize).unwrap();
            &$mmap[start..end]
        }
    };
    (mut, $mmap:expr, $pagesize:expr, $page:expr) => {
        {
            let (start, end) = page_range($page, 0, $pagesize).unwrap();
            &mut $mmap[start..end]
        }
    };
}

macro_rules! page_get_buf {
    ($mmap:expr, $page:expr, $pos:expr, $size:expr) => {
        {
            let (start, end) = page_range($page, $pos, $size).unwrap();
            &$mmap[start..end]
        }
    };
    (mut, $mmap:expr, $page:expr, $pos:expr, $size:expr) => {
        {
            let (start, end) = page_range($page, $pos, $size).unwrap();
            &mut $mmap[start..end]
        }
    };
}

macro_rules! pagebuf_get_int {
    ($t:ident, $pagebuf:expr, $pos:expr) => {
        {
            let tsz = std::mem::size_of::<$t>();
            if $pos % tsz != 0 {
                /* enforce alignment */
                panic!();
            }
            let data = &$pagebuf[$pos..($pos + tsz)];
            $t::from_le_bytes(data.try_into().unwrap())
        }
    };
}

macro_rules! pagebuf_get_buf {
    ($pagebuf:expr, $pos:expr, $len: expr) => {
        {
            &$pagebuf[$pos..($pos + $len)]
        }
    };
}

macro_rules! page_get_int {
    ($t:ident, $mmap:expr, $page:expr, $pos:expr) => {
        {
            let tsz = std::mem::size_of::<$t>();
            let (start, end) = page_range($page, $pos, tsz).unwrap();
            pagebuf_get_int!($t, &$mmap[start..end], 0)
        }
    };
}

macro_rules! pagebuf_set_int {
    ($t:ident, $pagebuf:expr, $pos:expr, $val:expr) => {
        {
            let tsz = std::mem::size_of::<$t>();
            if $pos % tsz != 0 {
                /* enforce alignment */
                panic!();
            }
            $pagebuf[$pos..($pos + tsz)].copy_from_slice(&$val.to_le_bytes());
        }
    };
}

macro_rules! pagebuf_set_buf {
    ($pagebuf:expr, $pos:expr, $buf:expr) => {
        {
            $pagebuf[$pos..($pos + $buf.len())].copy_from_slice($buf);
        }
    };
}

macro_rules! align {
    ($t:ident, $value:expr) => {
        {
            let tsz = std::mem::size_of::<$t>();
            ((($value + tsz - 1) / tsz) * tsz)
        }
    }
}

#[derive(Debug)]
struct RmdbSel {
    readpage: u64,          // the read root page
    writepage: u64,         // the write root page
}

#[derive(Debug)]
pub struct Rmdb {
    path: PathBuf,          // file name for db
    file: File,             // file handle
    pagesize: usize,        // size of pages
    num_pages: u64,         // max num pages allocated
    flags: RmdbFlags,       // db flags
    select: Mutex<RmdbSel>, // the global read/write selector
    rmap: RwLock<Mmap>,     // the global mmap for reading
    wmap: Mutex<MmapMut>,   // the global mmap for writing
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
            pagesize: page_size(dflags),
            num_pages: pages,
            flags: dflags,
            select: Mutex::new(
                RmdbSel {
                    readpage: 1,
                    writepage: 2
                }
            ),
            rmap: RwLock::new(
                unsafe {
                    Mmap::map(&file).map_err(RmdbError::Io)?
                }
            ),
            wmap: Mutex::new(
                unsafe {
                    MmapMut::map_mut(&file).map_err(RmdbError::Io)?
                }
            ),
            file: file,
        };

        if initialize {
            rmdb.initialize()?;
        }
        rmdb.setup()?;
        rmdb.integrity_check()?;
        Ok(rmdb)
    }

    fn initialize(&mut self) -> Result<(), RmdbError> {
        let mut wmap = self.wmap.lock().unwrap();
        let page = page_get_payload!(mut, wmap, self.pagesize, 0);
        pagebuf_set_buf!(page, RMDB_P_SIG, "RMDB".as_bytes());
        pagebuf_set_buf!(page, RMDB_P_VER, &RMDB_FILEVER.to_le_bytes());
        pagebuf_set_buf!(page, RMDB_P_FLAGS, &self.flags.bits().to_le_bytes());
        pagebuf_set_int!(u64, page, RMDB_P_RMAIN, 1u64);
        pagebuf_set_int!(u64, page, RMDB_P_WMAIN, 2u64);
        integrity_protect(&mut wmap, self.flags, 0)?;
        let pagesize = page_size(self.flags());
        for i in 1..3 {
            let page = page_get_payload!(mut, wmap, self.pagesize, i);
            let freepagessize = pagesize - (PAGEPTR_SIZE * 2) - MAIN_FREEPAGES;
            let mut freepages = vec![u8::MAX; freepagessize];
            /* First three pages are always taken */
            freepages[0] = freepages[0] >> 3;
            pagebuf_set_buf!(page, MAIN_FREEPAGES, &freepages);
            /* Initial db has only one free page buf */
            pagebuf_set_int!(u64, page, MAIN_FREEPAGES + freepagessize, 0u64);
            /* and points to no root node page */
            pagebuf_set_int!(u64, page, pagesize - 8, 0u64);
            /* mark page type */
            pagebuf_set_int!(u32, page, POS_PAGETYPE, PAGE_MAIN | PAGE_DIRTY);
            integrity_protect(&mut wmap, self.flags, 1)?;
        }
        Ok(())
    }

    fn integrity_check(&self) -> Result<(), RmdbError> {

        /* block writers */
        let _wmap = self.wmap.lock().unwrap();
        let select = self.select.lock().unwrap();
        let rmap = self.rmap.read().unwrap();

        /* check page 0 */
        let sig = page_get_buf!(rmap, 0, RMDB_P_SIG, 4);
        if sig != "RMDB".as_bytes() {
            return Err(RmdbError::IntegrityCheck)
        }
        let ver = page_get_buf!(rmap, 0, RMDB_P_VER, 4);
        if ver != &RMDB_FILEVER.to_le_bytes() {
            return Err(RmdbError::IntegrityCheck)
        }

        /* check read and write main pages */
        let page = page_get_payload!(rmap, self.pagesize, select.readpage);
        let ptype = pagebuf_get_int!(u32, page, POS_PAGETYPE);
        if ptype & PAGE_MAIN == 0 {
            return Err(RmdbError::IntegrityCheck)
        }

        let page = page_get_payload!(rmap, self.pagesize, select.writepage);
        let ptype = pagebuf_get_int!(u32, page, POS_PAGETYPE);
        if ptype & PAGE_MAIN == 0 {
            return Err(RmdbError::IntegrityCheck)
        }

        Ok(())
    }

    fn setup(&mut self) -> Result<(), RmdbError> {
        /* Set current root pages */

        /* block writers */
        let wmap = self.wmap.lock().unwrap();

        /* block any access to root page selection */
        let mut select = self.select.lock().unwrap();

        /* wait until all readers are done */
        let rmap = self.rmap.write().unwrap();

        let flags_buf = page_get_buf!(rmap, 0, RMDB_P_FLAGS, 4);
        let rmain = page_get_int!(u64, rmap, 0, RMDB_P_RMAIN);
        let wmain = page_get_int!(u64, rmap, 0, RMDB_P_WMAIN);

        /* set flags compatibily with what's in the DB */
        let dbflags = RmdbFlags::from_bits(
                u32::from_le_bytes(flags_buf.try_into().unwrap())).unwrap();

        if dbflags.contains(RmdbFlags::PAGE_INTEGRITY) {
            self.flags |= RmdbFlags::PAGE_INTEGRITY;
        } else {
            self.flags |= !RmdbFlags::PAGE_INTEGRITY;
        }
        self.pagesize = page_size(self.flags);

        select.writepage = wmain;
        select.readpage = rmain;
        drop(rmap);
        drop(select);
        drop(wmap);
        Ok(())
    }

    pub fn resize(&mut self, pages: u64) -> Result<(), RmdbError> {
        let size = pages as usize * RMDB_PAGESIZE;

        if size < RMDB_MINSIZE {
            return Err(RmdbError::InvalidFileSize)
        }

        /* block writers */
        let mut wmap = self.wmap.lock().unwrap();

        /* block any access to root page selection */
        let select = self.select.lock().unwrap();

        /* wait until all readers are done */
        let mut rmap = self.rmap.write().unwrap();

        if pages == self.num_pages {
            return Ok(())
        }
        if pages < self.num_pages {
            return Err(RmdbError::InvalidFileSize)
        }
        self.file.set_len(pages * RMDB_PAGESIZE as u64)?;
        self.num_pages = pages;
        *wmap = unsafe {
            MmapMut::map_mut(&self.file).map_err(RmdbError::Io)?
        };
        *rmap = unsafe {
            Mmap::map(&self.file).map_err(RmdbError::Io)?
        };
        drop(rmap);
        drop(wmap);
        drop(select);
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

    pub fn get_read_transaction<'a>(&'a self) -> Result<RmdbTxn<'a>, RmdbError> {
        let select = self.select.lock().unwrap();
        let readpage = select.readpage;
        let rmap = self.rmap.read().unwrap();
        drop(select);

        Ok(RmdbTxn {
            rmap: rmap,
            flags: self.flags,
            status: RmdbTxnState::Open,
            readpage: readpage,
            pagesize: self.pagesize,
        })
    }

    pub fn get_write_transaction<'a>(&'a self)
            -> Result<RmdbWTxn<'a>, RmdbError> {
        let wmap = self.wmap.lock().unwrap();
        let select = self.select.lock().unwrap();
        let writepage = select.writepage;
        let readpage = select.readpage;
        drop(select);
        let txn = RmdbWTxn {
            wmap: wmap,
            flags: self.flags,
            status: RmdbTxnState::Open,
            writepage: writepage,
            readpage: readpage,
            pagesize: self.pagesize,
            dirtypages: Vec::new(),
        };

        Ok(txn)
    }
}

impl Drop for Rmdb {
    fn drop(&mut self) {
        let mmap = self.wmap.lock().unwrap();
        match mmap.flush() {
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

fn integrity_protect(mmap: &mut MmapMut, flags: RmdbFlags, page: u64)
                                                -> Result<(), RmdbError> {
    if flags.contains(RmdbFlags::PAGE_INTEGRITY) {
        let page = page_get_whole!(mut, mmap, page);
        let hash = compute_hash(&page[0..(RMDB_PAGESIZE - 32)]);
        page[(RMDB_PAGESIZE - 32)..RMDB_PAGESIZE].copy_from_slice(&hash);
    }
    Ok(())
}

fn integrity_check(mmap: &Mmap, flags: RmdbFlags, page: u64)
        -> Result<(), RmdbError> {
    if !flags.contains(RmdbFlags::PAGE_INTEGRITY) {
        return Ok(())
    }
    let (start, end) = page_range(page, 0, RMDB_PAGESIZE - 32).unwrap();
    let data = mmap.get(start..end).unwrap();
    let hash = compute_hash(data);
    let verify = mmap.get(end..(end+32)).unwrap();
    if verify != hash {
        return Err(RmdbError::IntegrityCheck)
    }
    Ok(())
}

fn page_flush(mmap: &mut MmapMut, flags: RmdbFlags, page: u64)
                                                -> Result<(), RmdbError> {
    let (start, end) = page_range(page, 0, RMDB_PAGESIZE)?;
    if flags.contains(RmdbFlags::PAGE_SYNC_FLUSH) {
        mmap.flush_range(start, end).unwrap();
    } else if flags.contains(RmdbFlags::PAGE_FLUSH) {
        mmap.flush_async_range(start, end).unwrap();
    }
    Ok(())
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
    rmap: RwLockReadGuard<'a, Mmap>,
    flags: RmdbFlags,
    status: RmdbTxnState,
    pagesize: usize,        // size of pages
    readpage: u64,
}

macro_rules! get_root {
    ($self:ident, $mmap:expr, $mainpage:expr) => {
        {
            let page = page_get_payload!($mmap, $self.pagesize, $mainpage);
            pagebuf_get_int!(u64, page, $self.pagesize - 8)
        }
    };
}

// returns root when key not found
fn get_data<'a>(rmap: &'a [u8], pagesize: usize, leafnum: u64)
        -> Result<Vec<&'a [u8]>, RmdbError> {
    let page = page_get_payload!(rmap, pagesize, leafnum);
    let ptype = pagebuf_get_int!(u32, page, LEAF_PAGETYPE);
    if ptype & PAGE_LEAF != PAGE_LEAF {
        return Err(RmdbError::InvalidMetadata);
    }

    /* then fetch data */
    let dsize = pagebuf_get_int!(u32, page, LEAF_DATASIZE) as usize;
    let dlen = pagebuf_get_int!(u16, page, LEAF_DATALEN) as usize;
    let pages = (dsize - dlen + RMDB_PAGESIZE - 1) / RMDB_PAGESIZE;
    let pageptr = pagebuf_get_int!(u16, page, LEAF_PAGEPTR) as usize;
    let mut res = Vec::with_capacity(pages + 1);
    if dlen > 0 {
        let dptr = pagebuf_get_int!(u16, page, LEAF_DATAPTR) as usize;
        res.push(&page[dptr..(dptr + dlen)]);
    }
    let mut dptr = dlen;
    for i in 0..pages {
        let mut size = dsize - dptr;
        if size > RMDB_PAGESIZE {
            size = RMDB_PAGESIZE;
        }
        let dpage = pagebuf_get_int!(u64, page, pageptr + i * 8);
        res.push(page_get_buf!(rmap, dpage, 0, size));
        dptr += size;
    }
    Ok(res)
}

fn get_leaf_key(mmap: &[u8], leaf: u64) -> Result<&[u8], RmdbError> {
    let page = page_get_payload!(mmap, RMDB_PAGESIZE, leaf);
    let ptype = pagebuf_get_int!(u32, page, POS_PAGETYPE);
    if ptype & PAGE_LEAF == PAGE_LEAF {
        let klen = pagebuf_get_int!(u16, page, LEAF_KEYLEN) as usize;
        Ok(pagebuf_get_buf!(page, LEAF_KEY, klen))
    } else {
        Err(RmdbError::InvalidMetadata)
    }
}

/* page here must be only the payload, not the raw page,
   page.len() MUST be == self.pagesize */
fn get_leaf(mmap: &[u8], pagesize: usize, pagenum: u64, key: &[u8])
        -> Result<u64, RmdbError> {
    let page = page_get_payload!(mmap, pagesize, pagenum);
    let ptype = pagebuf_get_int!(u32, page, POS_PAGETYPE);
    if ptype & PAGE_LEAF == PAGE_LEAF {
        /* check we got the right leaf */
        let klen = pagebuf_get_int!(u16, page, LEAF_KEYLEN) as usize;
        if key.len() != klen {
            return Err(RmdbError::KeyNotFound);
        }
        if key != &page[LEAF_KEY..(LEAF_KEY + klen)] {
            return Err(RmdbError::KeyNotFound);
        }
        return Ok(pagenum);
    }
    if ptype & PAGE_NODE != PAGE_NODE {
        return Err(RmdbError::InvalidMetadata);
    }
    let nptrs = pagebuf_get_int!(u32, page, NODE_NUMPTRS) as usize;
    if nptrs == 0 {
        return Err(RmdbError::KeyNotFound);
    }
    /* TODO: change to a bisect */
    let mut node = 0u64;
    for n in (0..nptrs).rev() {
        node = pagebuf_get_int!(u64, page, NODE_FIRSTPTR + n * 8);
        let pkey = get_leaf_key(mmap, node)?;
        if key >= pkey {
            return get_leaf(mmap, pagesize, node, key);
        }
    }
    /* not found, return lowmost index node,
     * the last in the loop */
    return get_leaf(mmap, pagesize, node, key);
}


impl RmdbTxn<'_> {

    pub fn get_entry(&self, key: &[u8]) -> Result<Vec<&[u8]>, RmdbError> {
        let rootpage = get_root!(self, self.rmap, self.readpage);
        if rootpage == 0 {
            return Err(RmdbError::KeyNotFound);
        }
        let leaf = get_leaf(&self.rmap, self.pagesize, rootpage, key)?;
        integrity_check(&self.rmap, self.flags, leaf)?;
        get_data(&self.rmap, self.pagesize, leaf)
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
    wmap: MutexGuard<'a, MmapMut>,
    flags: RmdbFlags,
    status: RmdbTxnState,
    writepage: u64,
    readpage: u64,
    pagesize: usize,        // size of pages
    dirtypages: Vec<u64>,
}

impl RmdbWTxn<'_> {

    fn get_free_pages(&mut self, n:usize) -> Result<Vec<u64>, RmdbError> {
        // TODO: need to add support for multiple free page buffers
        let mut res = Vec::with_capacity(n);

        let wpage = page_get_payload!(mut, self.wmap, self.pagesize,
                                      self.writepage);
        let base = MAIN_FREEPAGES;
        let fsize = self.pagesize - 16 - MAIN_FREEPAGES;

        //TODO: try to allocate consecutive blocks
        for _ in 0..n {
            'page:for i in 0..fsize {
                if wpage[base + i] != 0 {
                    for j in 0..8 {
                        let x = 0b10000000u8 >> j;
                        if wpage[base + i] & x == x {
                            wpage[base + i] &= !x;
                            res.push((i * 8 + j) as u64);
                            break 'page;
                        }
                    }
                }
            }
        }
        if res.len() != n {
            Err(RmdbError::InvalidIndexSize)
        } else {
            //TODO: clear pages before returing them?
            Ok(res)
        }
    }

    fn put_free_pages(&mut self, pvec: Vec<u64>) -> Result<(), RmdbError> {
        let wpage = page_get_payload!(mut, self.wmap, self.pagesize,
                                      self.writepage);
        let base = MAIN_FREEPAGES;
        for p in pvec {
            let u = (p / 8) as usize;
            let v = (p % 8) as u8;
            let x = 0b10000000u8 >> v;
            wpage[base + u] |= x;
        }
        Ok(())
    }

    fn get_root(&mut self, allocate: bool) -> Result<u64, RmdbError> {
        let mut rootpage = get_root!(self, self.wmap, self.writepage);
        if rootpage == 0 {
            if !allocate {
                return Err(RmdbError::KeyNotFound)
            }
            rootpage = self.get_free_pages(1)?[0];
            let mut wpage = page_get_payload!(mut, self.wmap, self.pagesize,
                                              self.writepage);
            pagebuf_set_int!(u64, &mut wpage, self.pagesize - 8, rootpage);
            pagebuf_set_int!(u32, &mut wpage, POS_PAGETYPE,
                             PAGE_MAIN | PAGE_DIRTY);
            let mut page = page_get_payload!(mut, self.wmap, self.pagesize,
                                             rootpage);
            pagebuf_set_int!(u32, &mut page,
                             NODE_PAGETYPE, PAGE_NODE | PAGE_DIRTY);
            pagebuf_set_int!(u32, &mut page,
                             NODE_NUMPTRS, 0u32);
            self.dirtypages.push(rootpage);
        }
        Ok(rootpage)
    }

    pub fn get_entry(&mut self, key: &[u8]) -> Result<Vec<&[u8]>, RmdbError> {
        let rootpage = self.get_root(false)?;
        let leaf = get_leaf(&self.wmap, self.pagesize, rootpage, key)?;
        get_data(&self.wmap, self.pagesize, leaf)
    }

    pub fn add_entry(&mut self, key: &[u8], value: &[u8])
                                                -> Result<(), RmdbError> {

        let mut leaf_pagesize = self.pagesize;
        if self.flags.contains(RmdbFlags::PAGE_INTEGRITY) {
            leaf_pagesize -= 32;
        }

        /* create new pages */
        let datasize = value.len();
        let mut dataptr = 0usize;
        let mut datalen = 0usize;
        let mut pages = datasize / RMDB_PAGESIZE;
        let overflow = datasize % RMDB_PAGESIZE;
        let overhead = std::mem::size_of::<u64>() * pages +
                        LEAF_KEY + align!(u64, key.len()) as usize;
        if leaf_pagesize < overhead {
            return Err(RmdbError::InvalidDataSize);
        }
        let avail_space = leaf_pagesize - overhead;
        if avail_space < overflow {
            if avail_space < 8 {
                return Err(RmdbError::InvalidDataSize);
            }
            pages += 1;
        } else {
            datalen = overflow;
        }
        if datalen > 0 {
            dataptr = LEAF_KEY + align!(u64, key.len());
        }

        let pagevec = self.get_free_pages(pages + 1)?;

        /* write leaf page */
        let leaf = pagevec[0];
        let mut leafpage = page_get_payload!(mut, self.wmap, self.pagesize,
                                             leaf);

        pagebuf_set_int!(u32, &mut leafpage, LEAF_PAGETYPE, PAGE_LEAF);
        pagebuf_set_int!(u32, &mut leafpage, LEAF_DATASIZE, datasize as u32);
        pagebuf_set_int!(u16, &mut leafpage, LEAF_DATALEN, datalen as u16);
        pagebuf_set_int!(u16, &mut leafpage, LEAF_DATAPTR, dataptr as u16);

        /* add page pointers to leaf pages */
        let mut pageptr = 0usize;
        if pages > 0 {
            pageptr = leaf_pagesize - (8 * pages);
        }
        pagebuf_set_int!(u16, &mut leafpage, LEAF_PAGEPTR, pageptr as u16);

        for i in 0..pages {
            pagebuf_set_int!(u64, &mut leafpage,
                             (pageptr + i * 8), pagevec[i + 1]);
        }

        /* copy key */
        pagebuf_set_int!(u16, &mut leafpage, LEAF_KEYLEN, key.len() as u16);
        pagebuf_set_buf!(&mut leafpage, LEAF_KEY, key);

        /* copy data */
        //TODO: compute hash as we store data
        if self.flags.contains(RmdbFlags::PAGE_INTEGRITY) {
            let hash = compute_hash(value);
            pagebuf_set_buf!(&mut leafpage, leaf_pagesize, &hash);
        }

        /* write overflow data if any */
        if datalen > 0 {
            pagebuf_set_buf!(&mut leafpage, dataptr, &value[0..datalen]);
        }

        /* drop here to allow following code to manipulate other pages */
        drop(leafpage);

        /* then write the data */
        let mut start = datalen;
        for i in 0..pages {
            let mut data = page_get_whole!(mut, self.wmap, pagevec[i + 1]);
            let mut end = value.len() - start;
            if end > RMDB_PAGESIZE {
                end = RMDB_PAGESIZE;
            }
            pagebuf_set_buf!(&mut data, 0, &value[start..end]);
            start += end;
        }

        self.mark_dirty(leaf);

        /* then add them to the tree */
        let rootpage = self.get_root(true)?;
        let cur_leaf = get_leaf(&self.wmap, self.pagesize, rootpage, key);
        let cur_leaf = match cur_leaf {
            Ok(cur_leaf) => cur_leaf,
            Err(error) => {
                match error {
                    RmdbError::KeyNotFound => 0u64,
                    _ => return Err(error),
                }
            },
        };

        if cur_leaf == 0 {
            // adding a new key/value
            self.add_page(rootpage, leaf, key)?;
        } else {
            // we are replacing a leaf
            self.replace_page(rootpage, cur_leaf, leaf)?;
        }

        Ok(())
    }

    fn delete_page(&mut self, pagenum: u64) -> Result<(), RmdbError> {
        let mut pvec = Vec::new();
        pvec.push(pagenum);
        let page = page_get_payload!(self.wmap, self.pagesize, pagenum);
        let ptype = pagebuf_get_int!(u32, page, POS_PAGETYPE);
        if ptype & PAGE_LEAF != 0 {
            let dsize = pagebuf_get_int!(u32, page, LEAF_DATASIZE) as usize;
            let dlen = pagebuf_get_int!(u16, page, LEAF_DATALEN) as usize;
            let pages = (dsize - dlen + RMDB_PAGESIZE - 1) / RMDB_PAGESIZE;
            let pageptr = pagebuf_get_int!(u16, page, LEAF_PAGEPTR) as usize;

            for i in 0..pages {
                pvec.push(pagebuf_get_int!(u64, page, pageptr + i * 8));
            }
        }
        /* remove it from dirty-pages if there */
        self.dirtypages.retain(|&x| x != pagenum);

        self.put_free_pages(pvec)
    }

    fn replace_childptr(&mut self, parent: u64, curptr: u64, newptr: u64)
            -> Result<(), RmdbError> {
        let mut page = page_get_payload!(mut, self.wmap, self.pagesize,
                                         parent);
        let nptrs = pagebuf_get_int!(u32, page, NODE_NUMPTRS) as usize;
        if nptrs == 0 {
            return Err(RmdbError::KeyNotFound);
        }
        for n in 0..nptrs {
            let idx = NODE_FIRSTPTR + n * 8;
            let pageptr = pagebuf_get_int!(u64, page, idx);
            if pageptr == curptr {
                pagebuf_set_int!(u64, &mut page, idx, newptr);
                return Ok(());
            }
        }
        Err(RmdbError::KeyNotFound)
    }

    fn page_copy(&mut self, src: u64, dst: u64) -> Result<(), RmdbError> {
        let (sh, st) = page_range(src, 0, RMDB_PAGESIZE)?;
        let (dh, dt) = page_range(dst, 0, RMDB_PAGESIZE)?;
        if src > dst {
            let (dbuf, sbuf) = self.wmap.split_at_mut(sh);
            dbuf[dh..dt].copy_from_slice(&sbuf[0..RMDB_PAGESIZE]);
        } else {
            let (sbuf, dbuf) = self.wmap.split_at_mut(dh);
            dbuf[0..RMDB_PAGESIZE].copy_from_slice(&sbuf[sh..st]);
        }
        Ok(())
    }

    fn get_new_page_copy(&mut self, source: u64) -> Result<u64, RmdbError> {
        let copy = self.get_free_pages(1)?[0];
        self.page_copy(source, copy)?;

        Ok(copy)
    }

    fn mark_dirty(&mut self, pagenum: u64) {
        let mut page = page_get_payload!(mut, self.wmap, self.pagesize,
                                         pagenum);
        let mut ptype = pagebuf_get_int!(u32, page, POS_PAGETYPE);
        ptype |= PAGE_DIRTY;
        pagebuf_set_int!(u32, &mut page, POS_PAGETYPE, ptype);
        self.dirtypages.push(pagenum);
    }

    /* FIXME: this replaces only one leaf directly to the parent, no layering */
    fn replace_page(&mut self, oldparent: u64, curchild: u64, newchild: u64)
            -> Result<(), RmdbError> {
        let mut parent = oldparent;
        let ptype = page_get_int!(u32, self.wmap, parent, POS_PAGETYPE);
        if ptype & PAGE_DIRTY == 0 {
            /* page not dirty, we mut Copy on Write */
            parent = self.get_new_page_copy(oldparent)?;
            self.mark_dirty(parent);
            self.delete_page(oldparent)?;
        }
        self.replace_childptr(parent, curchild, newchild)?;
        self.delete_page(curchild)?;

        /* Finally, replace rootpage on writepage, to rebind the new tree */
        let mut writepage = page_get_payload!(mut, self.wmap, self.pagesize,
                                              self.writepage);
        pagebuf_set_int!(u64, &mut writepage, self.pagesize - 8, parent);
        Ok(())
    }

    /* FIXME: this adds only one leaf directly to the parent, no layering */
    /* FIXME: remove key parameter, get from leaf */
    fn add_page(&mut self, rootpage: u64, leaf: u64, key: &[u8])
            -> Result<(), RmdbError> {
        let mut parent = rootpage;
        let ptype = page_get_int!(u32, self.wmap, rootpage, POS_PAGETYPE);
        if ptype & PAGE_DIRTY == 0 {
            parent = self.get_new_page_copy(rootpage)?;
            self.mark_dirty(parent);
            self.delete_page(rootpage)?;
        }

        /* get page as immutable until we need to make changes */
        let page = page_get_payload!(self.wmap, self.pagesize, parent);

        /* check if enough space in page to add key */
        let nptrs = pagebuf_get_int!(u32, page, NODE_NUMPTRS) as usize;
        let topptr = NODE_FIRSTPTR + nptrs * PAGEPTR_SIZE;
        if topptr + PAGEPTR_SIZE > self.pagesize {
            //TODO: split tree and add nodes
            return Err(RmdbError::InvalidDataSize);
        }

        /* add leaf to index */
        let mut idx = NODE_FIRSTPTR + nptrs * PAGEPTR_SIZE;
        for n in (0..nptrs).rev() {
            idx = NODE_FIRSTPTR + n * 8;
            let node = pagebuf_get_int!(u64, page, idx);
            let pkey = get_leaf_key(&self.wmap, node)?;
            if key == pkey {
                return Err(RmdbError::InvalidMetadata);
            }
            if key > pkey {
                idx += 8;
                break;
            }
        }

        /* we found the insertion point, add key index here, and move,
         * all other upwards */

        /* get again page as mutuable now to make changes */
        let page = page_get_payload!(mut, self.wmap, self.pagesize, parent);

        let mptrs = (topptr - idx) / 8;

        /* ignored if we are operating on the highest slot */
        let mut savedptr = pagebuf_get_int!(u64, page, idx);

        /* set new in slot */
        pagebuf_set_int!(u64, page, idx, leaf);

        /* move all others up if any */
        idx += 8;
        for _ in 0..mptrs {
            let curptr = pagebuf_get_int!(u64, page, idx);
            pagebuf_set_int!(u64, page, idx, savedptr);
            savedptr = curptr;
            idx += 8;
        }

        pagebuf_set_int!(u32, page, NODE_NUMPTRS, nptrs as u32 + 1);

        /* Finally, replace rootpage on writepage, to rebind the new tree */
        let mut wpage = page_get_payload!(mut, self.wmap, self.pagesize,
                                          self.writepage);
        pagebuf_set_int!(u64, &mut wpage, self.pagesize - 8, parent);

        Ok(())
    }

    fn _scrub(&mut self) {
        /* make sure to copy readpage over writepage, to wipe out any changes
         * that my ahve happened there */
        self.page_copy(self.readpage, self.writepage).unwrap();

        self.status = RmdbTxnState::Scrubbed
    }

    pub fn scrub(&mut self) -> Result<(), RmdbError> {
        match self.status {
            RmdbTxnState::Open => self._scrub(),
            _ => return Err(RmdbError::InvalidTransaction),
        };
        Ok(())
    }

    fn finalize_page(&mut self, page: u64)
            -> Result<(), RmdbError> {
        if page != 0 {
            let mut pagebuf = page_get_whole!(mut, self.wmap, page);
            let mut ptype = pagebuf_get_int!(u32, pagebuf, POS_PAGETYPE);
            if ptype & PAGE_DIRTY != 0 {
                ptype &= !PAGE_DIRTY;
                pagebuf_set_int!(u32, &mut pagebuf, POS_PAGETYPE, ptype);
            }
        }
        integrity_protect(&mut *self.wmap, self.flags, page)?;
        page_flush(&mut *self.wmap, self.flags, page)
    }

    pub fn commit(&mut self, rmdb: &Rmdb) -> Result<(), RmdbError> {

        /* integrity check all dirty pages */
        let pages = self.dirtypages.to_vec();
        for dirty in pages {
            self.finalize_page(dirty)?;
        }
        /* and finally the writepage too */
        self.finalize_page(self.writepage)?;

        /* block any access to root page selection */
        let select = rmdb.select.lock().unwrap();

        /* wait until all readers are done */
        let rmap = rmdb.rmap.write().unwrap();

        /* copy write page over read page now */
        self.page_copy(self.writepage, self.readpage)?;

        self.status = RmdbTxnState::Committed;

        drop(rmap);
        drop(select);
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
