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
 *   .   ...                         .
 *   .                               .
 *   |--------------------------------
 *   . OPIONAL INTEGRITY/ENCRYPTION  .
 *   .................................
 */
const RMDB_P_SIG: usize = 0;        // [u8]
const RMDB_P_VER: usize = 4;        // [u8]
const RMDB_P_FLAGS: usize = 8;      // u32
const RMDB_P_PAGESIZE: usize = 12;  // u32
const RMDB_P_RMAIN: usize = 16;     // u64
const RMDB_P_WMAIN: usize = 24;     // u64

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
    ($self:ident, $mmap:expr, $page:expr) => {
        {
            page_get_buf!($self, $mmap, $page, 0, $self.pagesize)
        }
    };
    (mut, $self:ident, $mmap:expr, $page:expr) => {
        {
            page_get_buf!(mut, $self, $mmap, $page, 0, $self.pagesize)
        }
    };
}

macro_rules! page_get_payload {
    ($self:ident, $mmap:expr, $page:expr) => {
        {
            page_get_buf!($self, $mmap, $page, 0, $self.payload)
        }
    };
    (mut, $self:ident, $mmap:expr, $page:expr) => {
        {
            page_get_buf!(mut, $self, $mmap, $page, 0, $self.payload)
        }
    };
}

macro_rules! page_get_buf {
    ($self:ident, $mmap:expr, $page:expr, $pos:expr, $size:expr) => {
        {
            let (start, end) = page_range($self.pagesize,
                                          $page, $pos, $size).unwrap();
            &$mmap[start..end]
        }
    };
    (mut, $self:ident, $mmap:expr, $page:expr, $pos:expr, $size:expr) => {
        {
            let (start, end) = page_range($self.pagesize,
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
#[derive(Default)]
struct RmdbSel {
    readpage: u64,          // the read root page
    writepage: u64,         // the write root page
}

#[derive(Debug)]
pub struct Rmdb {
    path: PathBuf,          // file name for db
    file: File,             // file handle
    pagesize: usize,        // actual size of pages
    payload: usize,          // usable size of pages
    num_pages: u64,         // max num pages allocated
    flags: RmdbFlags,       // db flags
    select: Mutex<RmdbSel>, // the global read/write selector
    rmap: RwLock<Mmap>,     // the global mmap for reading
    wmap: Mutex<MmapMut>,   // the global mmap for writing
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
            num_pages: size_to_pages(opt.pagesize, opt.init_size),
            flags: opt.flags,
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

        // initialize
        rmdb.initialize()?;
        Ok(rmdb)
    }

    fn initialize(&mut self) -> Result<(), RmdbError> {
        let mut wmap = self.wmap.lock().unwrap();
        let page = page_get_payload!(mut, self, wmap, 0);
        pagebuf_set_buf!(page, RMDB_P_SIG, "RMDB".as_bytes());
        pagebuf_set_buf!(page, RMDB_P_VER, &RMDB_FILEVER.to_le_bytes());
        pagebuf_set_buf!(page, RMDB_P_FLAGS, &self.flags.bits().to_le_bytes());
        pagebuf_set_int!(u32, page, RMDB_P_PAGESIZE, self.pagesize as u32);
        pagebuf_set_int!(u64, page, RMDB_P_RMAIN, 1u64);
        pagebuf_set_int!(u64, page, RMDB_P_WMAIN, 2u64);
        integrity_protect(&mut wmap, self.flags, self.pagesize, 0)?;
        for i in 1..3 {
            let page = page_get_payload!(mut, self, wmap, i);
            let fsize = self.payload - (PAGEPTR_SIZE * 2) - MAIN_FREEPAGES;
            let mut freepages = vec![u8::MAX; fsize];
            /* First three pages are always taken */
            freepages[0] = freepages[0] >> 3;
            pagebuf_set_buf!(page, MAIN_FREEPAGES, &freepages);
            /* Initial db has only one free page buf */
            pagebuf_set_int!(u64, page, MAIN_FREEPAGES + fsize, 0u64);
            /* and points to no root node page */
            pagebuf_set_int!(u64, page, self.payload - 8, 0u64);
            /* mark page type */
            pagebuf_set_int!(u32, page, POS_PAGETYPE, PAGE_MAIN);
            integrity_protect(&mut wmap, self.flags, self.pagesize, 1)?;
        }
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
            num_pages: 0,
            flags: Default::default(),
            select: Mutex::new(Default::default()),
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

        rmdb.setup(flen as usize)?;
        Ok(rmdb)
    }

    fn setup(&mut self, flen: usize) -> Result<(), RmdbError> {

        /* Exclusive Access */
        let wmap = self.wmap.lock().unwrap();
        let mut select = self.select.lock().unwrap();
        let rmap = self.rmap.write().unwrap();

        /* check page 0 */
        let sig = pagebuf_get_buf!(rmap, RMDB_P_SIG, 4);
        if sig != "RMDB".as_bytes() {
            return Err(RmdbError::IntegrityCheck)
        }
        let ver = pagebuf_get_buf!(rmap, RMDB_P_VER, 4);
        if ver != &RMDB_FILEVER.to_le_bytes() {
            return Err(RmdbError::IntegrityCheck)
        }

        /* get DB settings */
        self.flags = RmdbFlags::from_bits(
                        u32::from_le_bytes(
                            pagebuf_get_buf!(rmap, RMDB_P_FLAGS, 4)
                                .try_into().unwrap())).unwrap();
        self.pagesize = pagebuf_get_int!(u32, rmap, RMDB_P_PAGESIZE) as usize;
        self.payload = payload_size(self.pagesize, self.flags);

        if flen % self.pagesize != 0 {
            // corrupted, not a multiple of page size
            return Err(RmdbError::InvalidFileSize)
        }

        /* Set current main pages */
        select.readpage = pagebuf_get_int!(u64, rmap, RMDB_P_RMAIN);
        select.writepage = pagebuf_get_int!(u64, rmap, RMDB_P_WMAIN);

        let fetch = RmdbFetch::new(self.flags, self.pagesize, self.payload,
                                   &rmap);
        /* now check integrity of the three fundamental pages */
        fetch.integrity_check(0)?;
        fetch.integrity_check(select.readpage)?;
        fetch.integrity_check(select.writepage)?;

        /* check read and write main pages */
        let page = page_get_payload!(self, rmap, select.readpage);
        let ptype = pagebuf_get_int!(u32, page, POS_PAGETYPE);
        if ptype & PAGE_MAIN == 0 {
            return Err(RmdbError::IntegrityCheck)
        }

        let page = page_get_payload!(self, rmap, select.writepage);
        let ptype = pagebuf_get_int!(u32, page, POS_PAGETYPE);
        if ptype & PAGE_MAIN == 0 {
            return Err(RmdbError::IntegrityCheck)
        }

        drop(rmap);
        drop(select);
        drop(wmap);
        Ok(())
    }

    pub fn growdb(&mut self, pages: u64) -> Result<(), RmdbError> {

        if pages == self.num_pages {
            return Ok(())
        }

        if pages < self.num_pages {
            return Err(RmdbError::InvalidFileSize)
        }

        let size = pages as usize * self.pagesize;

        if size < rmdb_minsize(self.pagesize) {
            return Err(RmdbError::InvalidFileSize)
        }

        /* Exclusive Access */
        let mut wmap = self.wmap.lock().unwrap();
        let select = self.select.lock().unwrap();
        let mut rmap = self.rmap.write().unwrap();

        self.file.set_len(size as u64)?;
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
            payload: self.payload,
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
            payload: self.payload,
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

fn integrity_protect(mmap: &mut MmapMut,
                     flags: RmdbFlags,
                     pagesize: usize,
                     page: u64) -> Result<(), RmdbError> {
    if flags.contains(RmdbFlags::PAGE_INTEGRITY) {
        struct Page {
            pagesize: usize
        }
        let w = Page { pagesize: pagesize };
        let page = page_get_whole!(mut, w, mmap, page);
        let hash = compute_hash(&page[0..(pagesize - 32)]);
        page[(pagesize - 32)..pagesize].copy_from_slice(&hash);
    }
    Ok(())
}

fn page_flush(mmap: &mut MmapMut,
              flags: RmdbFlags,
              pagesize: usize,
              page: u64) -> Result<(), RmdbError> {
    let (start, end) = page_range(pagesize, page, 0, pagesize)?;
    if flags.contains(RmdbFlags::PAGE_SYNC_FLUSH) {
        mmap.flush_range(start, end).unwrap();
    } else if flags.contains(RmdbFlags::PAGE_FLUSH) {
        mmap.flush_async_range(start, end).unwrap();
    }
    Ok(())
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
    rmap: RwLockReadGuard<'a, Mmap>,
    flags: RmdbFlags,
    status: RmdbTxnState,
    pagesize: usize,    // size of pages
    payload: usize,     // useful payload
    readpage: u64,      // main read page
}

macro_rules! get_root {
    ($self:ident, $mmap:expr, $mainpage:expr) => {
        {
            let page = page_get_payload!($self, $mmap, $mainpage);
            pagebuf_get_int!(u64, page, $self.payload - 8)
        }
    };
}

struct RmdbFetch<'a> {
    flags: RmdbFlags,
    pagesize: usize,
    payload: usize,
    mmap: &'a [u8],
}

impl<'a> RmdbFetch<'a> {

    fn new(flags: RmdbFlags,
           pagesize: usize,
           payload: usize,
           mmap: &'a [u8]) -> RmdbFetch {
        RmdbFetch {
            flags: flags,
            pagesize: pagesize,
            payload: payload,
            mmap: mmap,
        }
    }

    fn integrity_check(&self, page: u64) -> Result<(), RmdbError> {
        if !self.flags.contains(RmdbFlags::PAGE_INTEGRITY) {
            return Ok(())
        }
        let page = page_get_whole!(self, self.mmap, page);
        let (data, verify) = page.split_at(self.payload);
        let hash = compute_hash(data);
        if verify != hash {
            return Err(RmdbError::IntegrityCheck)
        }
        Ok(())
    }

    // returns root when key not found
    fn get_data(&self, leafnum: u64) -> Result<Vec<&'a [u8]>, RmdbError> {
        let page = page_get_payload!(self, self.mmap, leafnum);
        let ptype = pagebuf_get_int!(u32, page, LEAF_PAGETYPE);
        if ptype & PAGE_LEAF != PAGE_LEAF {
            return Err(RmdbError::InvalidMetadata);
        }

        /* then fetch data */
        let dsize = pagebuf_get_int!(u32, page, LEAF_DATASIZE) as usize;
        let dlen = pagebuf_get_int!(u16, page, LEAF_DATALEN) as usize;
        let pages = (dsize - dlen + self.pagesize - 1) / self.pagesize;
        let pageptr = pagebuf_get_int!(u16, page, LEAF_PAGEPTR) as usize;
        let mut res = Vec::with_capacity(pages + 1);
        if dlen > 0 {
            let dptr = pagebuf_get_int!(u16, page, LEAF_DATAPTR) as usize;
            res.push(&page[dptr..(dptr + dlen)]);
        }
        let mut dptr = dlen;
        for i in 0..pages {
            let mut size = dsize - dptr;
            if size > self.pagesize {
                size = self.pagesize;
            }
            let dpage = pagebuf_get_int!(u64, page, pageptr + i * 8);
            res.push(page_get_buf!(self, self.mmap, dpage, 0, size));
            dptr += size;
        }
        Ok(res)
    }

    fn get_leaf_key(&self, leaf: u64) -> Result<&[u8], RmdbError> {
        let page = page_get_payload!(self, self.mmap, leaf);
        let ptype = pagebuf_get_int!(u32, page, POS_PAGETYPE);
        if ptype & PAGE_LEAF == PAGE_LEAF {
            let klen = pagebuf_get_int!(u16, page, LEAF_KEYLEN) as usize;
            Ok(pagebuf_get_buf!(page, LEAF_KEY, klen))
        } else {
            Err(RmdbError::InvalidMetadata)
        }
    }

    /* page here must be only the payload, not the raw page,
       page.len() MUST be == self.payload */
    fn get_leaf(&self, pagenum: u64, key: &[u8]) -> Result<u64, RmdbError> {
        let page = page_get_payload!(self, self.mmap, pagenum);
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
            let pkey = self.get_leaf_key(node)?;
            if key >= pkey {
                return self.get_leaf(node, key);
            }
        }
        /* not found, return lowmost index node,
         * the last in the loop */
        return self.get_leaf(node, key);
    }
}

impl RmdbTxn<'_> {

    pub fn get_entry(&self, key: &[u8]) -> Result<Vec<&[u8]>, RmdbError> {
        let rootpage = get_root!(self, self.rmap, self.readpage);
        if rootpage == 0 {
            return Err(RmdbError::KeyNotFound);
        }
        let fetch = RmdbFetch::new(self.flags, self.pagesize, self.payload,
                                   &self.rmap);
        let leaf = fetch.get_leaf(rootpage, key)?;
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
    wmap: MutexGuard<'a, MmapMut>,
    flags: RmdbFlags,
    status: RmdbTxnState,
    writepage: u64,
    readpage: u64,
    pagesize: usize,    // size of page
    payload: usize,     // size of useful payload
    dirtypages: Vec<u64>,
}

impl RmdbWTxn<'_> {

    fn get_free_pages(&mut self, n:usize) -> Result<Vec<u64>, RmdbError> {
        // TODO: need to add support for multiple free page buffers
        let mut res = Vec::with_capacity(n);

        let wpage = page_get_payload!(mut, self, self.wmap, self.writepage);
        let base = MAIN_FREEPAGES;
        let fsize = self.payload - 16 - MAIN_FREEPAGES;

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
        let wpage = page_get_payload!(mut, self, self.wmap, self.writepage);
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
            let mut wpage = page_get_payload!(mut, self, self.wmap,
                                              self.writepage);
            pagebuf_set_int!(u64, &mut wpage, self.payload - 8, rootpage);
            pagebuf_set_int!(u32, &mut wpage, POS_PAGETYPE,
                             PAGE_MAIN | PAGE_DIRTY);
            let mut page = page_get_payload!(mut, self, self.wmap, rootpage);
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
        let fetch = RmdbFetch::new(self.flags, self.pagesize, self.payload,
                                   &self.wmap);
        let leaf = fetch.get_leaf(rootpage, key)?;
        fetch.get_data(leaf)
    }

    pub fn add_entry(&mut self, key: &[u8], value: &[u8])
                                                -> Result<(), RmdbError> {

        let mut leaf_payload = self.payload;
        if self.flags.contains(RmdbFlags::PAGE_INTEGRITY) {
            leaf_payload -= 32;
        }

        /* create new pages */
        let datasize = value.len();
        let mut dataptr = 0usize;
        let mut datalen = 0usize;
        let mut pages = datasize / self.pagesize;
        let overflow = datasize % self.pagesize;
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
        let mut leafpage = page_get_payload!(mut, self, self.wmap, leaf);

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
        if self.flags.contains(RmdbFlags::PAGE_INTEGRITY) {
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
            let mut data = page_get_whole!(mut, self, self.wmap,
                                           pagevec[i + 1]);
            let mut end = value.len() - start;
            if end > self.pagesize {
                end = self.pagesize;
            }
            pagebuf_set_buf!(&mut data, 0, &value[start..(start + end)]);
            start += end;
        }

        self.mark_dirty(leaf);

        /* then add them to the tree */
        let rootpage = self.get_root(true)?;
        let fetch = RmdbFetch::new(self.flags, self.pagesize, self.payload,
                                   &self.wmap);
        let cur_leaf = fetch.get_leaf(rootpage, key);
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
        let page = page_get_payload!(self, self.wmap, pagenum);
        let ptype = pagebuf_get_int!(u32, page, POS_PAGETYPE);
        if ptype & PAGE_LEAF != 0 {
            let dsize = pagebuf_get_int!(u32, page, LEAF_DATASIZE) as usize;
            let dlen = pagebuf_get_int!(u16, page, LEAF_DATALEN) as usize;
            let pages = (dsize - dlen + self.pagesize - 1) / self.pagesize;
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
        let mut page = page_get_payload!(mut, self, self.wmap, parent);
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
        let (sh, st) = page_range(self.pagesize, src, 0, self.pagesize)?;
        let (dh, dt) = page_range(self.pagesize, dst, 0, self.pagesize)?;
        if src > dst {
            let (dbuf, sbuf) = self.wmap.split_at_mut(sh);
            dbuf[dh..dt].copy_from_slice(&sbuf[0..self.pagesize]);
        } else {
            let (sbuf, dbuf) = self.wmap.split_at_mut(dh);
            dbuf[0..self.pagesize].copy_from_slice(&sbuf[sh..st]);
        }
        Ok(())
    }

    fn get_new_page_copy(&mut self, source: u64) -> Result<u64, RmdbError> {
        let copy = self.get_free_pages(1)?[0];
        self.page_copy(source, copy)?;

        Ok(copy)
    }

    fn mark_dirty(&mut self, pagenum: u64) {
        let mut page = page_get_payload!(mut, self, self.wmap, pagenum);
        let mut ptype = pagebuf_get_int!(u32, page, POS_PAGETYPE);
        ptype |= PAGE_DIRTY;
        pagebuf_set_int!(u32, &mut page, POS_PAGETYPE, ptype);
        self.dirtypages.push(pagenum);
    }

    /* FIXME: this replaces only one leaf directly to the parent, no layering */
    fn replace_page(&mut self, oldparent: u64, curchild: u64, newchild: u64)
            -> Result<(), RmdbError> {
        let mut parent = oldparent;
        let page = page_get_payload!(self, self.wmap, parent);
        let ptype = pagebuf_get_int!(u32, page, POS_PAGETYPE);
        if ptype & PAGE_DIRTY == 0 {
            /* page not dirty, we mut Copy on Write */
            parent = self.get_new_page_copy(oldparent)?;
            self.mark_dirty(parent);
            self.delete_page(oldparent)?;
        }
        self.replace_childptr(parent, curchild, newchild)?;
        self.delete_page(curchild)?;

        /* Finally, replace rootpage on writepage, to rebind the new tree */
        let mut writepage = page_get_payload!(mut, self, self.wmap,
                                              self.writepage);
        pagebuf_set_int!(u64, &mut writepage, self.payload - 8, parent);
        Ok(())
    }

    /* FIXME: this adds only one leaf directly to the parent, no layering */
    /* FIXME: remove key parameter, get from leaf */
    fn add_page(&mut self, rootpage: u64, leaf: u64, key: &[u8])
            -> Result<(), RmdbError> {
        let mut parent = rootpage;

        /* get page as immutable until we need to make changes */
        let page = page_get_payload!(self, self.wmap, parent);
        let ptype = pagebuf_get_int!(u32, page, POS_PAGETYPE);
        if ptype & PAGE_DIRTY == 0 {
            parent = self.get_new_page_copy(rootpage)?;
            self.mark_dirty(parent);
            self.delete_page(rootpage)?;
        }

        /* fetch page again as it may have changed */
        let page = page_get_payload!(self, self.wmap, parent);

        /* check if enough space in page to add key */
        let nptrs = pagebuf_get_int!(u32, page, NODE_NUMPTRS) as usize;
        let topptr = NODE_FIRSTPTR + nptrs * PAGEPTR_SIZE;
        if topptr + PAGEPTR_SIZE > self.payload {
            //TODO: split tree and add nodes
            return Err(RmdbError::InvalidDataSize);
        }

        /* add leaf to index */
        let fetch = RmdbFetch::new(self.flags, self.pagesize, self.payload,
                                   &self.wmap);
        let mut idx = NODE_FIRSTPTR + nptrs * PAGEPTR_SIZE;
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
        let page = page_get_payload!(mut, self, self.wmap, parent);

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
        let mut wpage = page_get_payload!(mut, self, self.wmap, self.writepage);
        pagebuf_set_int!(u64, &mut wpage, self.payload - 8, parent);

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
            let mut pagebuf = page_get_buf!(mut, self, self.wmap,
                                            page, 0, self.payload);
            let mut ptype = pagebuf_get_int!(u32, pagebuf, POS_PAGETYPE);
            if ptype & PAGE_DIRTY != 0 {
                ptype &= !PAGE_DIRTY;
                pagebuf_set_int!(u32, &mut pagebuf, POS_PAGETYPE, ptype);
            }
        }
        integrity_protect(&mut *self.wmap, self.flags, self.pagesize, page)?;
        page_flush(&mut *self.wmap, self.flags, self.pagesize, page)
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

        /* flush whole file if requested */
        if self.flags.contains(RmdbFlags::TRANSACTION_FLUSH) {
            self.wmap.flush_async()?;
        } else if self.flags.contains(RmdbFlags::TRANSACTION_SYNC_FLUSH) {
            self.wmap.flush()?;
        }

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
