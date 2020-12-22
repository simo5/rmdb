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

/* default page size */
const RMDB_PAGESIZE: usize = 4096;
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
 * 1 |  FLAGS       |  PAGESIZE      |
 *   |-------------------------------|
 * 2 |          READ PAGE            |
 *   |-------------------------------|
 * 3 |         WRITE PAGE            |
 *   |-------------------------------|
 *   |   POINTERS TO FREE PAGES      |
 *   |-------------------------------|
 *   .   ...                         .
 *   .                               .
 *   |--------------------------------
 *   . OPIONAL INTEGRITY/ENCRYPTION  .
 *   .................................
 *    */
const RMDB_P_SIG: usize = 0;        // [u8]
const RMDB_P_VER: usize = 4;        // [u8]
const RMDB_P_FLAGS: usize = 8;      // u32
const RMDB_P_PAGESIZE: usize = 12;  // u32
const RMDB_P_ROOT: usize = 16;      // u64
const RMDB_P_FREEPAGES: usize = 24; // [u64]

const POS_PAGETYPE: usize = 0;

//const PAGE_NONE: u32 = 1u32 << 0;
const PAGE_FREE: u32 = 1u32 << 1;
const PAGE_NODE: u32 = 1u32 << 2;
const PAGE_LEAF: u32 = 1u32 << 3;
const PAGE_ROOT: u32 = 1u32 << 30;
const PAGE_DIRTY: u32 = 1u32 << 31;

/*
 * The free pages page has this structure:
 *   0              32              64
 *   ---------------------------------
 * 0 |   PAGETYPE   |   RESERVED     |
 *   |-------------------------------|
 *   |   FREE PAGES: each bit is a   |
 *   |   free page (from page 0)     |
 *   .   ...                         .
 *   .                               .
 *   |-------------------------------|
 *   . OPIONAL INTEGRITY/ENCRYPTION  .
 *   .................................
 */
const FREE_PAGETYPE: usize = POS_PAGETYPE; //u32
const FREE_BITMAP: usize = 8; //u32

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
 * Just an ordered list of pointers to leaves.
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
 * dependent on DATASIZE.
 * DATASIZE/RAWPAGESIZE = #PAGES
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
    KeyNotHere,
    PageNotLeaf,
    InvalidMetadata,
    UnalignedAccess,
    LockError,
    IntegrityCheck,
    InvalidIndexSize,
    InvalidFileSize,
    InvalidDBFile,
    InvalidTransaction,
    NotImplemented,
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
            RmdbError::KeyNotHere => write!(f, "Key not in this (sub)tree"),
            RmdbError::PageNotLeaf => write!(f, "Page is not a leaf"),
            RmdbError::InvalidDataSize => write!(f, "Invalid data size"),
            RmdbError::NotImplemented => write!(f, "Oooh!! Where's my code?"),
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
            RmdbError::KeyNotHere => None,
            RmdbError::PageNotLeaf => None,
            RmdbError::InvalidDataSize => None,
            RmdbError::NotImplemented => None,
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
        RmdbFlags::PAGE_INTEGRITY | RmdbFlags::TRANSACTION_SYNC_FLUSH
    }
}

#[derive(Copy, Clone, Debug)]
pub struct RmdbOptions {
    init_size: usize,
    pagesize: usize,
    flags: RmdbFlags,
    readonly: bool,
}

impl RmdbOptions {
    pub fn new() -> Self {
        RmdbOptions {
            init_size: rmdb_minsize(RMDB_PAGESIZE),
            pagesize: RMDB_PAGESIZE,
            flags: <RmdbFlags as Default>::default(),
            readonly: false,
        }
    }

    pub fn pagesize(&mut self, s: usize) -> &mut Self {
        let is = rmdb_minsize(s);
        if self.init_size < is {
            self.init_size = is
        }
        self.pagesize = s;
        self
    }

    pub fn initial_size(&mut self, s: usize) -> &mut Self {
        self.init_size = s;
        self
    }

    pub fn flags(&mut self, f: RmdbFlags) -> &mut Self {
        self.flags = f;
        self
    }

    pub fn readonly(&mut self) -> &mut Self {
        self.readonly = true;
        self
    }
}

macro_rules! page_get_whole {
    ($rmdb:expr, $mmap:expr, $page:expr) => {
        {
            page_get_buf!($rmdb, $mmap, $page, 0, $rmdb.pagesize)
        }
    };
    (mut, $rmdb:expr, $mmap:expr, $page:expr) => {
        {
            page_get_buf!(mut, $rmdb, $mmap, $page, 0, $rmdb.pagesize)
        }
    };
}

macro_rules! page_get_payload {
    ($rmdb:expr, $mmap:expr, $page:expr) => {
        {
            page_get_buf!($rmdb, $mmap, $page, 0, $rmdb.payload)
        }
    };
    (mut, $rmdb:expr, $mmap:expr, $page:expr) => {
        {
            page_get_buf!(mut, $rmdb, $mmap, $page, 0, $rmdb.payload)
        }
    };
}

macro_rules! page_get_buf {
    ($rmdb:expr, $mmap:expr, $page:expr, $pos:expr, $size:expr) => {
        {
            let (start, end) = page_range($rmdb.pagesize,
                                          $page, $pos, $size).unwrap();
            &$mmap[start..end]
        }
    };
    (mut, $rmdb:expr, $mmap:expr, $page:expr, $pos:expr, $size:expr) => {
        {
            let (start, end) = page_range($rmdb.pagesize,
                                          $page, $pos, $size).unwrap();
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

fn rmdb_minsize(pagesize: usize) -> usize {
    pagesize * 64
}

#[derive(Debug)]
struct RmdbRd {
    rootpage: u64,          // the root page
    mmap: Mmap,             // the global mmap for reading
}

#[derive(Debug)]
struct RmdbWr {
    num_pages: u64,         // num of pages currently allocated
    mmap: MmapMut,          // the global mmap for writing
}

#[derive(Debug)]
pub struct Rmdb {
    path: PathBuf,          // file name for db
    file: File,             // file handle
    pagesize: usize,        // actual size of pages
    payload: usize,         // usable size of pages
    flags: RmdbFlags,       // db flags
    rlock: RwLock<RmdbRd>, // the readers struct
    wlock: Mutex<RmdbWr>,    // the writers struct
}

impl Rmdb {

    pub fn create(path: PathBuf, options: Option<RmdbOptions>)
            -> Result<Rmdb, RmdbError> {

        let opt: RmdbOptions;

        match options {
            Some(o) => opt = o,
            None    => opt = RmdbOptions::new(),
        }

        let file = OpenOptions::new()
                                .read(true)
                                .write(!opt.readonly)
                                .create_new(true)
                                .open(&path).map_err(RmdbError::Io)?;
        file.set_len(opt.init_size as u64).map_err(RmdbError::Io)?;

        let mut rmdb = Rmdb {
            path: path,
            pagesize: opt.pagesize,
            payload: payload_size(opt.pagesize, opt.flags),
            flags: opt.flags,
            rlock: RwLock::new(RmdbRd {
                rootpage: 2,
                mmap: unsafe {
                    Mmap::map(&file).map_err(RmdbError::Io)?
                }
            }),
            wlock: Mutex::new(RmdbWr {
                num_pages: size_to_pages(opt.pagesize, opt.init_size),
                mmap: unsafe {
                    MmapMut::map_mut(&file).map_err(RmdbError::Io)?
                }
            }),
            file: file,
        };

        // initialize
        rmdb.initialize()?;
        Ok(rmdb)
    }

    fn initialize(&mut self) -> Result<(), RmdbError> {
        let mut wlock = self.wlock.lock().unwrap();
        let page = page_get_payload!(mut, self, wlock.mmap, 0);
        pagebuf_set_buf!(page, RMDB_P_SIG, "RMDB".as_bytes());
        pagebuf_set_buf!(page, RMDB_P_VER, &RMDB_FILEVER.to_le_bytes());
        pagebuf_set_buf!(page, RMDB_P_FLAGS, &self.flags.bits().to_le_bytes());
        pagebuf_set_int!(u32, page, RMDB_P_PAGESIZE, self.pagesize as u32);
        /* first allocated page is the first freepages bitmap */
        pagebuf_set_int!(u64, page, RMDB_P_FREEPAGES, 1u64);
        /* second allocated page is the rootpage */
        pagebuf_set_int!(u64, page, RMDB_P_ROOT, 2u64);
        self.integrity_protect(&mut wlock.mmap, 0)?;

        /* init first free pages page */
        let page = page_get_payload!(mut, self, wlock.mmap, 1);
        let fsize = self.payload - FREE_BITMAP;
        let mut freepages = vec![u8::MAX; fsize];
        /* At init we have: main page, free page, root page */
        freepages[0] = freepages[0] >> 3;
        pagebuf_set_buf!(page, FREE_BITMAP, &freepages);
        /* mark page type */
        pagebuf_set_int!(u32, page, FREE_PAGETYPE, PAGE_FREE);
        self.integrity_protect(&mut wlock.mmap, 1)?;

        /* init empty root node */
        let page = page_get_payload!(mut, self, wlock.mmap, 2);
        pagebuf_set_int!(u32, page, NODE_PAGETYPE, PAGE_NODE | PAGE_ROOT);
        pagebuf_set_int!(u32, page, NODE_NUMPTRS, 0u32);
        self.integrity_protect(&mut wlock.mmap, 2)?;

        Ok(())
    }

    /// Opens an existing rmdb database for read/write operations
    pub fn open(path: PathBuf) -> Result<Rmdb, RmdbError> {
        let mut file = OpenOptions::new()
                                    .read(true)
                                    .write(true)
                                    .open(&path).map_err(RmdbError::Io)?;

        let flen = file.seek(SeekFrom::End(0)).map_err(RmdbError::Io)?;

        let mut rmdb = Rmdb {
            path: path,
            pagesize: 0,
            payload: 0,
            flags: Default::default(),
            rlock: RwLock::new(RmdbRd {
                rootpage: 0,
                mmap: unsafe {
                    Mmap::map(&file).map_err(RmdbError::Io)?
                }
            }),
            wlock: Mutex::new(RmdbWr {
                num_pages: 0,
                mmap: unsafe {
                    MmapMut::map_mut(&file).map_err(RmdbError::Io)?
                }
            }),
            file: file,
        };

        rmdb.setup(flen as usize)?;
        Ok(rmdb)
    }

    fn setup(&mut self, flen: usize) -> Result<(), RmdbError> {

        /* Exclusive Access */
        let wlock = self.wlock.lock().unwrap();
        let mut rlock = self.rlock.write().unwrap();

        /* check page 0 */
        let sig = pagebuf_get_buf!(rlock.mmap, RMDB_P_SIG, 4);
        if sig != "RMDB".as_bytes() {
            return Err(RmdbError::IntegrityCheck)
        }
        let ver = pagebuf_get_buf!(rlock.mmap, RMDB_P_VER, 4);
        if ver != &RMDB_FILEVER.to_le_bytes() {
            return Err(RmdbError::IntegrityCheck)
        }

        /* get DB settings */
        self.flags = RmdbFlags::from_bits(
                        u32::from_le_bytes(
                            pagebuf_get_buf!(rlock.mmap, RMDB_P_FLAGS, 4)
                                .try_into().unwrap())).unwrap();
        self.pagesize = pagebuf_get_int!(u32, rlock.mmap, RMDB_P_PAGESIZE) as usize;
        self.payload = payload_size(self.pagesize, self.flags);

        if flen % self.pagesize != 0 {
            // corrupted, not a multiple of page size
            return Err(RmdbError::InvalidFileSize)
        }

        /* Set current root pages */
        rlock.rootpage = pagebuf_get_int!(u64, rlock.mmap, RMDB_P_ROOT);
        if rlock.rootpage == 0 {
            return Err(RmdbError::IntegrityCheck)
        }

        let fetch = RmdbFetch::new(self, &rlock.mmap);
        /* now check integrity of the three fundamental pages */
        fetch.integrity_check(0)?;
        fetch.integrity_check(1)?;
        fetch.integrity_check(rlock.rootpage)?;

        /* check root page */
        let page = page_get_payload!(self, rlock.mmap, rlock.rootpage);
        let ptype = pagebuf_get_int!(u32, page, POS_PAGETYPE);
        if ptype & PAGE_ROOT == 0 {
            return Err(RmdbError::IntegrityCheck)
        }

        drop(rlock);
        drop(wlock);
        Ok(())
    }

    pub fn growdb(&mut self, pages: u64) -> Result<(), RmdbError> {

        let size = pages as usize * self.pagesize;
        let meta = self.file.metadata()?;
        let filelen = meta.len() as usize;

        if size == filelen {
            return Ok(())
        }
        if size < filelen {
            return Err(RmdbError::InvalidFileSize)
        }

        if size < rmdb_minsize(self.pagesize) {
            return Err(RmdbError::InvalidFileSize)
        }

        /* Exclusive Access */
        let mut wlock = self.wlock.lock().unwrap();
        let mut rlock = self.rlock.write().unwrap();

        self.file.set_len(size as u64)?;
        wlock.num_pages= pages;
        wlock.mmap = unsafe {
            MmapMut::map_mut(&self.file).map_err(RmdbError::Io)?
        };
        rlock.mmap = unsafe {
            Mmap::map(&self.file).map_err(RmdbError::Io)?
        };
        drop(rlock);
        drop(wlock);
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
        let rlock = self.rlock.read().unwrap();
        Ok(RmdbTxn {
            rlock: rlock,
            status: RmdbTxnState::Open,
            rmdb: self,
        })
    }

    pub fn get_write_transaction<'a>(&'a self)
            -> Result<RmdbWTxn<'a>, RmdbError> {
        let wlock = self.wlock.lock().unwrap();
        let rlock = self.rlock.read().unwrap();
        let rootpage = rlock.rootpage;
        drop(rlock);
        let txn = RmdbWTxn {
            wlock: wlock,
            status: RmdbTxnState::Open,
            rmdb: self,
            rootpage: rootpage,
            dirtypages: Vec::new(),
            deletepages: Vec::new(),
        };

        Ok(txn)
    }

    fn integrity_protect(&self, mmap: &mut MmapMut, page: u64)
            -> Result<(), RmdbError> {
        if self.flags.contains(RmdbFlags::PAGE_INTEGRITY) {
            let page = page_get_whole!(mut, self, mmap, page);
            let hash = compute_hash(&page[0..(self.pagesize - 32)]);
            page[(self.pagesize - 32)..self.pagesize].copy_from_slice(&hash);
        }
        Ok(())
    }

    fn page_flush(&self, mmap: &mut MmapMut, page: u64)
            -> Result<(), RmdbError> {
        let (start, end) = page_range(self.pagesize, page, 0, self.pagesize)?;
        if self.flags.contains(RmdbFlags::PAGE_SYNC_FLUSH) {
            mmap.flush_range(start, end).unwrap();
        } else if self.flags.contains(RmdbFlags::PAGE_FLUSH) {
            mmap.flush_async_range(start, end).unwrap();
        }
        Ok(())
    }
}

impl Drop for Rmdb {
    fn drop(&mut self) {
        let wlock = self.wlock.lock().unwrap();
        match wlock.mmap.flush() {
            Ok(()) => (),
            Err(error) => eprintln!("Failed to fflush mmap: {:?}", error),
        };
    }
}

fn size_to_pages(pagesize: usize, size: usize) -> u64 {
    return ((size + pagesize - 1) / pagesize) as u64;
}

pub fn payload_size(pagesize: usize, flags: RmdbFlags) -> usize {
    let mut size = pagesize;
    if flags.contains(RmdbFlags::PAGE_INTEGRITY) {
        size -= RMDB_INTGSIZE;
    }
    return size;
}

fn page_range(pagesize: usize, index: u64, offset: usize, size: usize)
                -> Result<(usize, usize), RmdbError> {
    if offset + size > pagesize {
        return Err(RmdbError::InvalidIndexSize)
    }
    let base = (index as usize) * pagesize;
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
    rlock: RwLockReadGuard<'a, RmdbRd>,
    status: RmdbTxnState,
    rmdb: &'a Rmdb,
}

struct RmdbFetch<'a> {
    rmdb: &'a Rmdb,
    mmap: &'a [u8],
}

impl<'a> RmdbFetch<'a> {

    fn new(rmdb: &'a Rmdb,
           mmap: &'a [u8]) -> RmdbFetch<'a> {
        RmdbFetch {
            rmdb: rmdb,
            mmap: mmap,
        }
    }

    fn integrity_check(&self, page: u64) -> Result<(), RmdbError> {
        if !self.rmdb.flags.contains(RmdbFlags::PAGE_INTEGRITY) {
            return Ok(())
        }
        let page = page_get_whole!(self.rmdb, self.mmap, page);
        let (data, verify) = page.split_at(self.rmdb.payload);
        let hash = compute_hash(data);
        if verify != hash {
            return Err(RmdbError::IntegrityCheck)
        }
        Ok(())
    }

    // returns root when key not found
    fn get_data(&self, leafnum: u64) -> Result<Vec<&'a [u8]>, RmdbError> {
        let page = page_get_payload!(self.rmdb, self.mmap, leafnum);
        let ptype = pagebuf_get_int!(u32, page, LEAF_PAGETYPE);
        if ptype & PAGE_LEAF != PAGE_LEAF {
            return Err(RmdbError::InvalidMetadata);
        }

        /* then fetch data */
        let dsize = pagebuf_get_int!(u32, page, LEAF_DATASIZE) as usize;
        let dlen = pagebuf_get_int!(u16, page, LEAF_DATALEN) as usize;
        let pagesize = self.rmdb.pagesize;
        let pages = (dsize - dlen + pagesize - 1) / pagesize;
        let pageptr = pagebuf_get_int!(u16, page, LEAF_PAGEPTR) as usize;
        let mut res = Vec::with_capacity(pages + 1);
        if dlen > 0 {
            let dptr = pagebuf_get_int!(u16, page, LEAF_DATAPTR) as usize;
            res.push(&page[dptr..(dptr + dlen)]);
        }
        let mut dptr = dlen;
        for i in 0..pages {
            let mut size = dsize - dptr;
            if size > pagesize {
                size = pagesize;
            }
            let dpage = pagebuf_get_int!(u64, page, pageptr + i * 8);
            res.push(page_get_buf!(self.rmdb, self.mmap, dpage, 0, size));
            dptr += size;
        }
        Ok(res)
    }

    fn get_leaf_key(&self, leaf: u64) -> Result<&[u8], RmdbError> {
        let page = page_get_payload!(self.rmdb, self.mmap, leaf);
        let ptype = pagebuf_get_int!(u32, page, POS_PAGETYPE);
        if ptype & PAGE_LEAF == PAGE_LEAF {
            let klen = pagebuf_get_int!(u16, page, LEAF_KEYLEN) as usize;
            Ok(pagebuf_get_buf!(page, LEAF_KEY, klen))
        } else {
            Err(RmdbError::PageNotLeaf)
        }
    }

    /* pagenum must be a node page */
    fn get_parents_leaf(&self, pagenum: u64, key: &[u8])
                       -> Result<(Vec<u64>, u64), RmdbError> {
        let mut parents = Vec::new();
        let page = page_get_payload!(self.rmdb, self.mmap, pagenum);
        let ptype = pagebuf_get_int!(u32, page, POS_PAGETYPE);
        if ptype & PAGE_NODE != PAGE_NODE {
            return Err(RmdbError::InvalidMetadata);
        }
        let nptrs = pagebuf_get_int!(u32, page, NODE_NUMPTRS) as usize;
        if nptrs == 0 {
            return Err(RmdbError::KeyNotHere);
        }

        parents.push(pagenum);

        /* TODO: change to a bisect */
        for n in 0..nptrs {
            let pageptr = pagebuf_get_int!(u64, page, NODE_FIRSTPTR + n * 8);
            match self.get_leaf_key(pageptr) {
                Ok(pkey) => {
                    if key == pkey {
                        return Ok((parents, pageptr));
                    }
                    if key < pkey {
                        /* key not found, and found pkey is larger, so this
                         * node would be the likely parent, of a child with
                         * the requested key */
                        return Ok((parents, 0));
                    }
                },
                Err(error) => {
                    /* PageNotLeaf means this is a node of nodes */
                    match error {
                        RmdbError::PageNotLeaf => (),
                        _ => return Err(error),
                    };
                    match self.get_parents_leaf(pageptr, key) {
                        Ok((mut par, leaf)) => {
                            parents.append(&mut par);
                            return Ok((parents, leaf));
                        },
                        Err(error) => {
                            /* KeyNotHere means continue with loop */
                            match error {
                                RmdbError::KeyNotHere => (),
                                _ => return Err(error),
                            };
                        },
                    };
                },
            };
        }
        /* if we get here it means we scanned all keys in this (sub)tree and
         * found the key is bigger than biggest stored key.
         * return KeyNotHere which indicates that key could be found in the
         * next parent's subtree */
        return Err(RmdbError::KeyNotHere);
    }

    fn get_parents(&self, pagenum: u64, key: &[u8])
                   -> Result<Vec<u64>, RmdbError> {
        match self.get_parents_leaf(pagenum, key) {
            Ok((parents, _leaf)) => Ok(parents),
            Err(error) => match error {
                RmdbError::KeyNotHere => Ok(vec![pagenum]),
                _ => Err(error),
            },
        }
    }

    fn get_leaf(&self, pagenum: u64, key: &[u8]) -> Result<u64, RmdbError> {
        match self.get_parents_leaf(pagenum, key) {
            Ok((_parents, leaf)) => {
                if leaf != 0 {
                    Ok(leaf)
                } else {
                    Err(RmdbError::KeyNotFound)
                }
            },
            Err(error) => match error {
                RmdbError::KeyNotHere => Err(RmdbError::KeyNotFound),
                _ => Err(error),
            },
        }
    }
}

impl RmdbTxn<'_> {

    pub fn get_entry(&self, key: &[u8]) -> Result<Vec<&[u8]>, RmdbError> {
        if self.rlock.rootpage == 0 {
            return Err(RmdbError::KeyNotFound);
        }
        let fetch = RmdbFetch::new(self.rmdb, &self.rlock.mmap);
        let leaf = fetch.get_leaf(self.rlock.rootpage, key)?;
        fetch.integrity_check(leaf)?;
        fetch.get_data(leaf)
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
    wlock: MutexGuard<'a, RmdbWr>,
    status: RmdbTxnState,
    rootpage: u64,
    rmdb: &'a Rmdb,
    dirtypages: Vec<u64>,
    deletepages: Vec<u64>,
}

impl RmdbWTxn<'_> {

    fn get_free_pages(&mut self, n:usize) -> Result<Vec<u64>, RmdbError> {
        // TODO: need to add support for multiple free page buffers
        let mut res = Vec::with_capacity(n);

        let freepage = pagebuf_get_int!(u64, self.wlock.mmap, RMDB_P_FREEPAGES);
        let page = page_get_payload!(mut, self.rmdb, self.wlock.mmap, freepage);
        let base = FREE_BITMAP;
        let fsize = self.rmdb.payload - 16 - FREE_BITMAP;

        //TODO: try to allocate consecutive blocks
        for _ in 0..n {
            'bpage:for i in 0..fsize {
                if page[base + i] != 0 {
                    for j in 0..8 {
                        let x = 0b10000000u8 >> j;
                        if page[base + i] & x == x {
                            page[base + i] &= !x;
                            res.push((i * 8 + j) as u64);
                            break 'bpage;
                        }
                    }
                }
            }
        }
        if res.len() != n {
            Err(RmdbError::InvalidIndexSize)
        } else {
            //TODO: clear pages before returing them?
            self.mark_dirty(freepage);
            Ok(res)
        }
    }

    fn put_free_pages(&mut self, pvec: Vec<u64>) -> Result<(), RmdbError> {
        let freepage = pagebuf_get_int!(u64, self.wlock.mmap, RMDB_P_FREEPAGES);
        let page = page_get_payload!(mut, self.rmdb, self.wlock.mmap, freepage);
        let base = FREE_BITMAP;
        for p in pvec {
            let u = (p / 8) as usize;
            let v = (p % 8) as u8;
            let x = 0b10000000u8 >> v;
            page[base + u] |= x;
        }
        Ok(())
    }

    pub fn get_entry(&mut self, key: &[u8]) -> Result<Vec<&[u8]>, RmdbError> {
        if self.rootpage == 0 {
            return Err(RmdbError::KeyNotFound);
        }
        let fetch = RmdbFetch::new(self.rmdb, &self.wlock.mmap);
        let leaf = fetch.get_leaf(self.rootpage, key)?;
        fetch.get_data(leaf)
    }

    pub fn add_entry(&mut self, key: &[u8], value: &[u8])
                                                -> Result<(), RmdbError> {

        let mut leaf_payload = self.rmdb.payload;
        if self.rmdb.flags.contains(RmdbFlags::PAGE_INTEGRITY) {
            leaf_payload -= 32;
        }

        /* create new pages */
        let datasize = value.len();
        let mut dataptr = 0usize;
        let mut datalen = 0usize;
        let mut pages = datasize / self.rmdb.pagesize;
        let overflow = datasize % self.rmdb.pagesize;
        let overhead = std::mem::size_of::<u64>() * pages +
                        LEAF_KEY + align!(u64, key.len()) as usize;
        if leaf_payload < overhead {
            return Err(RmdbError::InvalidDataSize);
        }
        let avail_space = leaf_payload - overhead;
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
        let mut leafpage = page_get_payload!(mut, self.rmdb, self.wlock.mmap, leaf);

        pagebuf_set_int!(u32, &mut leafpage, LEAF_PAGETYPE, PAGE_LEAF);
        pagebuf_set_int!(u32, &mut leafpage, LEAF_DATASIZE, datasize as u32);
        pagebuf_set_int!(u16, &mut leafpage, LEAF_DATALEN, datalen as u16);
        pagebuf_set_int!(u16, &mut leafpage, LEAF_DATAPTR, dataptr as u16);

        /* add page pointers to leaf pages */
        let mut pageptr = 0usize;
        if pages > 0 {
            pageptr = leaf_payload - (8 * pages);
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
        if self.rmdb.flags.contains(RmdbFlags::PAGE_INTEGRITY) {
            let hash = compute_hash(value);
            pagebuf_set_buf!(&mut leafpage, leaf_payload, &hash);
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
            let mut data = page_get_whole!(mut, self.rmdb, self.wlock.mmap,
                                           pagevec[i + 1]);
            let mut end = value.len() - start;
            if end > self.rmdb.pagesize {
                end = self.rmdb.pagesize;
            }
            pagebuf_set_buf!(&mut data, 0, &value[start..(start + end)]);
            start += end;
        }

        self.mark_dirty(leaf);

        /* then add them to the tree */
        let fetch = RmdbFetch::new(self.rmdb, &self.wlock.mmap);
        let cur_leaf = fetch.get_leaf(self.rootpage, key);
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
            self.add_leaf(leaf, key)?;
        } else {
            // we are replacing a leaf
            self.replace_leaf(cur_leaf, leaf)?;
        }

        Ok(())
    }

    pub fn del_entry(&mut self, key: &[u8]) -> Result<(), RmdbError> {
        if self.rootpage == 0 {
            return Err(RmdbError::KeyNotFound);
        }
        let fetch = RmdbFetch::new(self.rmdb, &self.wlock.mmap);
        let result = fetch.get_parents_leaf(self.rootpage, key);
        let (mut parents, leaf) = match result {
            Ok((parents, leaf)) => {
                if leaf != 0 {
                    (parents, leaf)
                } else {
                    return Err(RmdbError::KeyNotFound)
                }
            },
            Err(error) => match error {
                RmdbError::KeyNotHere => return Err(RmdbError::KeyNotFound),
                _ => return Err(error),
            },
        };
        self.del_leaf(&mut parents, leaf)
    }

    fn delete_page(&mut self, pagenum: u64) {
        /* remove it from dirty-pages if there */
        self.dirtypages.retain(|&x| x != pagenum);

        let page = page_get_payload!(self.rmdb, self.wlock.mmap, pagenum);
        let ptype = pagebuf_get_int!(u32, page, POS_PAGETYPE);
        if (ptype & PAGE_DIRTY) == PAGE_DIRTY {
            /* if dirty return immediately to free pages */
            self.put_free_pages([pagenum].to_vec()).unwrap();
        } else {
            /* otherwise mark for deletion on commit */
            self.deletepages.push(pagenum);
        }
    }

    fn replace_childptr(&mut self, parent: u64, curptr: u64, newptr: u64)
            -> Result<(), RmdbError> {
        let mut page = page_get_payload!(mut, self.rmdb, self.wlock.mmap, parent);
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
        let pagesize = self.rmdb.pagesize;
        let (sh, st) = page_range(pagesize, src, 0, pagesize)?;
        let (dh, dt) = page_range(pagesize, dst, 0, pagesize)?;
        if src > dst {
            let (dbuf, sbuf) = self.wlock.mmap.split_at_mut(sh);
            dbuf[dh..dt].copy_from_slice(&sbuf[0..pagesize]);
        } else {
            let (sbuf, dbuf) = self.wlock.mmap.split_at_mut(dh);
            dbuf[0..pagesize].copy_from_slice(&sbuf[sh..st]);
        }
        Ok(())
    }

    fn get_new_page_copy(&mut self, source: u64) -> Result<u64, RmdbError> {
        let copy = self.get_free_pages(1)?[0];
        self.page_copy(source, copy)?;

        Ok(copy)
    }

    fn mark_dirty(&mut self, pagenum: u64) {
        let mut page = page_get_payload!(mut, self.rmdb, self.wlock.mmap, pagenum);
        let mut ptype = pagebuf_get_int!(u32, page, POS_PAGETYPE);
        ptype |= PAGE_DIRTY;
        pagebuf_set_int!(u32, &mut page, POS_PAGETYPE, ptype);
        if ! self.dirtypages.contains(&pagenum) {
            self.dirtypages.push(pagenum);
        }
    }

    fn replace_node(&mut self, parents: &mut Vec<u64>, current: u64)
            -> Result<u64, RmdbError> {
        let newpage = self.get_new_page_copy(current)?;
        self.mark_dirty(newpage);
        self.delete_page(current);
        if current == self.rootpage {
            self.rootpage = newpage;
        } else {
            let mut parent = match parents.pop() {
                Some(parent) => parent,
                None => return Err(RmdbError::InvalidMetadata),
            };
            let page = page_get_payload!(self.rmdb, self.wlock.mmap, parent);
            let ptype = pagebuf_get_int!(u32, page, POS_PAGETYPE);
            if ptype & PAGE_DIRTY != PAGE_DIRTY {
                parent = self.replace_node(parents, parent)?;
            }
            /* reload, may have changed */
            let page = page_get_payload!(mut, self.rmdb, self.wlock.mmap, parent);
            let nptrs = pagebuf_get_int!(u32, page, NODE_NUMPTRS) as usize;
            /* TODO: use bisection */
            let mut idx = NODE_FIRSTPTR;
            for _ in 0..nptrs {
                let node = pagebuf_get_int!(u64, page, idx);
                if node == current {
                    pagebuf_set_int!(u64, page, idx, newpage);
                    break;
                }
                idx += PAGEPTR_SIZE;
            }
            if idx == NODE_FIRSTPTR + nptrs * PAGEPTR_SIZE {
                return Err(RmdbError::InvalidMetadata);
            }
        }
        Ok(newpage)
    }

    fn replace_leaf(&mut self, curchild: u64, newchild: u64)
            -> Result<(), RmdbError> {
        let fetch = RmdbFetch::new(self.rmdb, &self.wlock.mmap);
        let key = fetch.get_leaf_key(curchild)?;
        let mut parents = fetch.get_parents(self.rootpage, key)?;
        let mut parent = match parents.pop() {
            Some(parent) => parent,
            None => return Err(RmdbError::InvalidMetadata),
        };
        let page = page_get_payload!(self.rmdb, self.wlock.mmap, parent);
        let ptype = pagebuf_get_int!(u32, page, POS_PAGETYPE);
        if ptype & PAGE_DIRTY == 0 {
            /* page not dirty, we must Copy on Write */
            parent = self.replace_node(&mut parents, parent)?;
        }
        self.replace_childptr(parent, curchild, newchild)?;
        self.delete_page(curchild);

        Ok(())
    }

    fn split_node(&mut self, parents: &mut Vec<u64>, current: u64)
            -> Result<(u64, u64), RmdbError> {
        let mut parent = match parents.pop() {
            Some(parent) => parent,
            None => {
                /* splitting root node */
                let rootpage = self.get_free_pages(1)?[0];
                let mut page = page_get_payload!(mut, self.rmdb, self.wlock.mmap,
                                                 rootpage);
                pagebuf_set_int!(u32, &mut page, NODE_PAGETYPE,
                                 PAGE_NODE | PAGE_ROOT);
                pagebuf_set_int!(u32, &mut page, NODE_NUMPTRS, 0u32);
                self.mark_dirty(rootpage);
                self.rootpage = rootpage;
                rootpage
            },
        };
        let page = page_get_payload!(self.rmdb, self.wlock.mmap, parent);
        let ptype = pagebuf_get_int!(u32, page, POS_PAGETYPE);
        let nptrs = pagebuf_get_int!(u32, page, NODE_NUMPTRS) as usize;
        let topptr = NODE_FIRSTPTR + nptrs * PAGEPTR_SIZE;
        if topptr + PAGEPTR_SIZE <= self.rmdb.payload {
            /* there is space here */
            if ptype & PAGE_DIRTY != PAGE_DIRTY {
                /* page not dirty, we must Copy on Write */
                parent = self.replace_node(parents, parent)?;
            }
        } else {
            /* page split */
            let (left, right) = self.split_node(parents, parent)?;
            /* find which of the left or right node should be the new parent */
            let page = page_get_payload!(self.rmdb, self.wlock.mmap, left);
            let nptrs = pagebuf_get_int!(u32, page, NODE_NUMPTRS) as usize;
            let mut idx = NODE_FIRSTPTR;
            for _ in 0..nptrs {
                let node = pagebuf_get_int!(u64, page, idx);
                if node == current {
                    idx = 1;
                    break;
                }
                idx += 8;
            }
            if idx == 1 {
                /* set to 1 when found */
                parent = left;
            } else {
                parent = right;
            }
        }

        /* make two copies of current, then delete half child ptrs
         * from each side */
        let left = self.get_new_page_copy(current)?;
        let right = self.get_new_page_copy(current)?;

        /* update left */
        let page = page_get_payload!(mut, self.rmdb, self.wlock.mmap, left);
        /* mark as dirty node (removes PAGE_ROOT on split of rootpage) */
        pagebuf_set_int!(u32, page, POS_PAGETYPE, PAGE_NODE | PAGE_DIRTY);
        let nptrs = pagebuf_get_int!(u32, page, NODE_NUMPTRS) as usize;
        let lptrs = nptrs / 2;
        pagebuf_set_int!(u32, page, NODE_NUMPTRS, lptrs as u32);

        /* update right */
        let page = page_get_payload!(mut, self.rmdb, self.wlock.mmap, right);
        /* mark as dirty node (removes PAGE_ROOT on split of rootpage) */
        pagebuf_set_int!(u32, page, POS_PAGETYPE, PAGE_NODE | PAGE_DIRTY);
        let rptrs = nptrs - lptrs;
        let mut sidx = NODE_FIRSTPTR + lptrs * PAGEPTR_SIZE;
        let mut didx = NODE_FIRSTPTR;
        for _ in 0..rptrs {
            let node = pagebuf_get_int!(u64, page, sidx);
            pagebuf_set_int!(u64, page, didx, node);
            sidx += 8;
            didx += 8;
        }
        pagebuf_set_int!(u32, page, NODE_NUMPTRS, rptrs as u32);

        /* finally update the parent to insert two pages where
         * the current is */
        let page = page_get_payload!(mut, self.rmdb, self.wlock.mmap, parent);
        let nptrs = pagebuf_get_int!(u32, page, NODE_NUMPTRS) as usize;

        let mut idx = NODE_FIRSTPTR;
        let mut ins = 0usize;
        /* TODO: use bisection */
        for n in 0..nptrs {
            let node = pagebuf_get_int!(u64, page, idx);
            if node == current {
                ins = n;
                break;
            }
            idx += 8;
        }

        /* found insertion point, copy the rest one over */
        for n in (ins..nptrs).rev() {
            idx = NODE_FIRSTPTR + n * 8;
            let node = pagebuf_get_int!(u64, page, idx);
            pagebuf_set_int!(u64, page, idx + 8, node);
        }
        /* finally set left and right nodes */
        idx = NODE_FIRSTPTR + ins * PAGEPTR_SIZE;
        pagebuf_set_int!(u64, page, idx, left);
        pagebuf_set_int!(u64, page, idx + 8, right);

        if nptrs > 0 {
            pagebuf_set_int!(u32, page, NODE_NUMPTRS, (nptrs + 1) as u32);
        } else {
            /* if we split the root we get a new empty top node */
            pagebuf_set_int!(u32, page, NODE_NUMPTRS, 2u32);
        }

        /* remove old splitted page */
        self.delete_page(current);
        Ok((left, right))
    }

    fn add_leaf(&mut self, leaf: u64, key: &[u8])
            -> Result<(), RmdbError> {
        let fetch = RmdbFetch::new(self.rmdb, &self.wlock.mmap);
        let mut parents = fetch.get_parents(self.rootpage, key)?;
        drop(fetch);
        let mut parent = match parents.pop() {
            Some(parent) => parent,
            None => return Err(RmdbError::InvalidMetadata),
        };
        let page = page_get_payload!(self.rmdb, self.wlock.mmap, parent);
        let ptype = pagebuf_get_int!(u32, page, POS_PAGETYPE);
        let nptrs = pagebuf_get_int!(u32, page, NODE_NUMPTRS) as usize;
        let topptr = NODE_FIRSTPTR + nptrs * PAGEPTR_SIZE;
        if topptr + PAGEPTR_SIZE <= self.rmdb.payload {
            /* there is space here */
            if ptype & PAGE_DIRTY != PAGE_DIRTY {
                /* page not dirty, we must Copy on Write */
                parent = self.replace_node(&mut parents, parent)?;
            }
        } else {
            /* page split */
            self.split_node(&mut parents, parent)?;

            /* after split find again which node to be added to */
            let fetch = RmdbFetch::new(self.rmdb, &self.wlock.mmap);
            parents = fetch.get_parents(self.rootpage, key)?;
            parent = match parents.pop() {
                Some(parent) => parent,
                None => return Err(RmdbError::InvalidMetadata),
            };
        }

        /* map page again as it may have changed */
        let page = page_get_payload!(self.rmdb, self.wlock.mmap, parent);

        let nptrs = pagebuf_get_int!(u32, page, NODE_NUMPTRS) as usize;
        let topptr = NODE_FIRSTPTR + nptrs * PAGEPTR_SIZE;
        if topptr + PAGEPTR_SIZE > self.rmdb.payload {
            return Err(RmdbError::InvalidMetadata)
        }

        /* add leaf to index */
        let fetch = RmdbFetch::new(self.rmdb, &self.wlock.mmap);
        let mut idx = NODE_FIRSTPTR;
        for n in (0..nptrs).rev() {
            idx = NODE_FIRSTPTR + n * 8;
            let node = pagebuf_get_int!(u64, page, idx);
            let pkey = fetch.get_leaf_key(node)?;
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
        let page = page_get_payload!(mut, self.rmdb, self.wlock.mmap, parent);

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

        Ok(())
    }

    fn del_leaf(&mut self, parents: &mut Vec<u64>, leaf: u64)
            -> Result<(), RmdbError> {

        let mut parent = match parents.pop() {
            Some(parent) => parent,
            None => return Err(RmdbError::InvalidMetadata),
        };
        let page = page_get_payload!(self.rmdb, self.wlock.mmap, parent);
        let ptype = pagebuf_get_int!(u32, page, POS_PAGETYPE);
        let nptrs = pagebuf_get_int!(u32, page, NODE_NUMPTRS) as usize;
        if nptrs == 1 && parent != self.rootpage {
            /* last leaf of node, remove parent as well */
            self.del_leaf(parents, parent)?;
            self.delete_page(leaf);
            return Ok(());
        } else {
            if ptype & PAGE_DIRTY != PAGE_DIRTY {
                /* page not dirty, we must Copy on Write */
                parent = self.replace_node(parents, parent)?;
            }
        }

        /* re-read parent, may have changed */
        let page = page_get_payload!(mut, self.rmdb, self.wlock.mmap, parent);

        /* remove leaf from index */
        let mut loc = 0usize;
        /* TODO: use bisection */
        for n in 0..nptrs {
            let idx = NODE_FIRSTPTR + n * PAGEPTR_SIZE;
            let node = pagebuf_get_int!(u64, page, idx);
            if node == leaf {
                loc = n;
                break;
            }
        }
        /* found insertion point, copy the rest one over */
        loc += 1;
        for n in loc..nptrs {
            let idx = NODE_FIRSTPTR + n * PAGEPTR_SIZE;
            let node = pagebuf_get_int!(u64, page, idx);
            pagebuf_set_int!(u64, page, idx - 8, node);
        }
        /* update size */
        pagebuf_set_int!(u32, page, NODE_NUMPTRS, (nptrs - 1) as u32);
        self.delete_page(leaf);
        Ok(())
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

    fn finalize_page(&mut self, page: u64)
            -> Result<(), RmdbError> {
        if page != 0 {
            let mut pagebuf = page_get_buf!(mut, self.rmdb, self.wlock.mmap,
                                            page, 0, self.rmdb.payload);
            let mut ptype = pagebuf_get_int!(u32, pagebuf, POS_PAGETYPE);
            if ptype & PAGE_DIRTY != 0 {
                ptype &= !PAGE_DIRTY;
                pagebuf_set_int!(u32, &mut pagebuf, POS_PAGETYPE, ptype);
            }
        }
        self.rmdb.integrity_protect(&mut self.wlock.mmap, page)?;
        self.rmdb.page_flush(&mut self.wlock.mmap, page)
    }

    pub fn commit(&mut self) -> Result<(), RmdbError> {

        /* free deleted pages */
        self.put_free_pages(self.deletepages.to_vec())?;

        /* integrity check all dirty pages */
        let pages = self.dirtypages.to_vec();
        for dirty in pages {
            self.finalize_page(dirty)?;
        }

        /* wait until all readers are done */
        let mut rlock = self.rmdb.rlock.write().unwrap();

        /* set readers root page */
        rlock.rootpage = self.rootpage;

        /* now update root page in Main page */
        let page = page_get_payload!(mut, self.rmdb, self.wlock.mmap, 0);
        pagebuf_set_int!(u64, page, RMDB_P_ROOT, rlock.rootpage);
        self.rmdb.integrity_protect(&mut self.wlock.mmap, 0)?;

        /* flush whole file if requested */
        if self.rmdb.flags.contains(RmdbFlags::TRANSACTION_FLUSH) {
            self.wlock.mmap.flush_async()?;
        } else if self.rmdb.flags.contains(RmdbFlags::TRANSACTION_SYNC_FLUSH) {
            self.wlock.mmap.flush()?;
        }

        self.status = RmdbTxnState::Committed;

        drop(rlock);
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
