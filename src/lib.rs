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
const RMDB_MINPAGESIZE: usize = 128;
const RMDB_FILEVER: u32 = 3;
const RMDB_MAJOR: u16 = 0;
const RMDB_MINOR: u16 = 0;
const RMDB_RELEASE: u16 = 0;
const RMDB_RESERVED: u16 = 0;
const RMDB_INTGSIZE: usize = 32;
const RMDB_MAXORDER: usize = 31;

/* The Zeroth page contains the DB basic configuration and status
 *   0              32
 *   ----------------|
 * 0 |  RMDB         |
 *   |---------------|
 * 1 |  VERSION      |
 *   |---------------|
 * 2 |  FLAGS        |
 *   |---------------|
 * 3 |  PAGESIZE     |
 *   |---------------|
 * 4 |  TOTAL PAGES  |
 *   |---------------|
 * 5 |  ROOT PAGE    |
 *   |---------------|
 * 6 | FREEPAGES PTR |
 *   |---------------|
 * 7 | FREEPAGES SIZ |
 * . |---------------|
 * . .   ...         .
 * . .               .
 *   |----------------
 *   . OPIONAL       .
 *   . INTEGRITY /   .
 *   . ENCRYPTION    .
 *   .................
 */
const PTRSZ: usize = 4;      // u32

const RMDB_P_SIG: usize =       0 * PTRSZ; // [u8]
const RMDB_P_VER: usize =       1 * PTRSZ; // [u8]
const RMDB_P_FLAGS: usize =     2 * PTRSZ; //u32
const RMDB_P_PAGESIZE: usize =  3 * PTRSZ; // u32
const RMDB_P_DBPAGES: usize =   4 * PTRSZ; // u32
const RMDB_P_ROOT: usize =      5 * PTRSZ; // u32
const RMDB_P_FREEPAGES: usize = 6 * PTRSZ; // u32
const RMDB_P_FREESIZE: usize =  7 * PTRSZ; // u32

const POS_PAGETYPE: usize = 0;
const POS_PAGEDATA: usize = 4;

//const PAGE_NONE: u16 = 1u16 << 0;
const PAGE_FREE: u16 =  1u16 << 1;
const PAGE_NODE: u16 =  1u16 << 2;
const PAGE_LEAF: u16 =  1u16 << 3;
const PAGE_ROOT: u16 =  1u16 << 14;
const PAGE_DIRTY: u16 = 1u16 << 15;

/*
 * Free pages are always allocated according to an algorithm dependent
 * on the size of pages.
 * The number of bits we can store in a freepage map is:
 *  B = (payload - 8) * PTRSZ, where payload is pagesize - integrity (if any)
 * So teh database is spliat in slices of size B * pagesize, and the free
 * page for the area is always located at index * B * pagesize + 1.
 *
 * so for a 4k pagesize DB, B = 32576, and the second freepage is located
 * at page 32576+1 (the first is always at page 1).
 *
 * the number of currently available freepages is always determined by the
 * size of the DB, for the eample above if the DB is bigger than 132MiB then
 * we have a second page allocated (32576 × 4096 = 133431296).
 *
 * The free pages page has this structure:
 *   0      16      32
 *   -----------------
 * 0 | TYPE  | RSRVD |
 *   |---------------|
 * 1 |   MAP SIZE    |
 *   |---------------|
 * 2 | Serialized    |
 *   | list of blocks|
 *   | of  free pages|
 *   | in by # order.|
 *   .   ...         .
 *   .               .
 *   |----------------
 *   . OPIONAL       .
 *   . INTEGRITY /   .
 *   . ENCRYPTION    .
 *   .................
 */
const FREE_MAP_SIZE: usize = 1 * PTRSZ; //u32
const FREE_MAP: usize =      2 * PTRSZ; //[u32]

/* Pages are of two types: node or leaf.
 * Node page structure:
 *   0      16      32
 *   -----------------
 * 0 | TYPE | # PTRs |
 *   |---------------|
 * 1 | PAGE PTR K#1  |
 *   |---------------|
 * 2 | PAGE PTR K#2  |
 *   |---------------|
 * . .   ...         .
 * . |----------------
 *   . OPIONAL       .
 *   . INTEGRITY /   .
 *   . ENCRYPTION    .
 *   .................
 *
 * Just an ordered list of pointers to leaves.
 */
const NODE_NUMPTRS: usize = 2;   // u16
const NODE_FIRSTPTR: usize = 1 * PTRSZ;  // u32

/* Leaf page structure:
 *   0      16      32
 *   -----------------
 * 0 | TYPE  | #Keys |
 *   |---------------|
 * 1 | #Kptr1| ...   |
 *   |---------------|
 *   . ...           .
 *   |----------------
 *   . OPIONAL       .
 *   . INTEGRITY /   .
 *   . ENCRYPTION    .
 *   .................
 */
const LEAF_KEYNUM:  usize = 2; // u16
const LEAF_KEYPTRS: usize = 4; // [u16]

/*
 * Individual key/data structures.
 * There are two cases.
 * Klen is marked specially, if the high bit is 0 it means
 * we are in case 1. If the high bit is 1 we are in case 2.
 *
 *
 * 1. all data fits into the remaining of the leaf page:
 *   0      16      32
 *   -----------------
 * 0 |[0]kLen| Key...|
 *   |---------------|
 *   .   ...         .
 *   |---------------|
 * X | dLen  | data..| //u32 aligned
 *   |---------------|
 * . .   ...         .
 * . |---------------|
 *
 * 2. data is bigger than available space:
 * NOTE: we assume contiguous data pages, no fragmentation
 * is allowed for a single data element at this time.
 *   0      16      32
 * 0 |[1]kLen| Key...|
 *   |---------------|
 *   .   ...         .
 *   -----------------
 * X | Datasize      | //u32 aligned
 *   |---------------|
 * X | 1ST PAGE PTR  |
 *   |---------------|
 *   . OPIONAL DATA  .
 *   . INTEG/ENCR TAG.
 *   .................
 *
 * The number of aditional pages is
 * dependent on DATASIZE.
 * DATASIZE/RAWPAGESIZE = #PAGES
 * Part or all of the content may also
 * be contained directly in the Leaf
 * page in the DATA section.
 */
const LEAF_PL_KLEN: usize = 0; // u15!! (high bit is type)
const LEAF_PL_KEY: usize = 2;  // [u8]


#[derive(Debug)]
pub enum RmdbError {
    InvalidDataSize,
    KeyNotFound,
    KeyTooSmall,
    KeyTooBig,
    PageNotLeaf,
    InvalidMetadata,
    UnalignedAccess,
    LockError,
    IntegrityCheck,
    InvalidCursor,
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
            RmdbError::KeyTooSmall => write!(f, "Key not in this (sub)tree (too small)"),
            RmdbError::KeyTooBig => write!(f, "Key not in this (sub)tree (too big)"),
            RmdbError::PageNotLeaf => write!(f, "Page is not a leaf"),
            RmdbError::InvalidDataSize => write!(f, "Invalid data size"),
            RmdbError::InvalidCursor => write!(f, "Invalid Cursor"),
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
            RmdbError::KeyTooSmall => None,
            RmdbError::KeyTooBig => None,
            RmdbError::PageNotLeaf => None,
            RmdbError::InvalidDataSize => None,
            RmdbError::InvalidCursor => None,
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
        const ZERO_PAGES = 64;
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
        let mut size = s;
        if size < RMDB_MINPAGESIZE {
            size = RMDB_MINPAGESIZE;
        }
        let is = rmdb_minsize(size);
        if self.init_size < is {
            self.init_size = is
        }
        self.pagesize = size;
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

macro_rules! page_get_many {
    ($rmdb:expr, $mmap:expr, $page:expr, $num:expr) => {
        {
            let start = $page as usize * $rmdb.pagesize;
            let end = start + $num as usize * $rmdb.pagesize;
            &$mmap[start..end]
        }
    };
    (mut, $rmdb:expr, $mmap:expr, $page:expr, $num:expr) => {
        {
            let start = $page as usize * $rmdb.pagesize;
            let end = start + $num as usize * $rmdb.pagesize;
            &mut $mmap[start..end]
        }
    };
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
    rootpage: u32,          // the root page
    mmap: Mmap,             // the global mmap for reading
}

#[derive(Debug)]
struct RmdbFreePages {
    lists: Vec<Vec<u32>>,  // the lists of free page blocks
    free: u32,             // total number of free pages
}

#[derive(Debug)]
struct RmdbWr {
    num_pages: u32,         // num of pages total
    mmap: MmapMut,          // the global mmap for writing
    freepages: RmdbFreePages,
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
                rootpage: 0,
                mmap: unsafe {
                    Mmap::map(&file).map_err(RmdbError::Io)?
                }
            }),
            wlock: Mutex::new(RmdbWr {
                num_pages: size_to_pages(opt.pagesize, opt.init_size),
                mmap: unsafe {
                    MmapMut::map_mut(&file).map_err(RmdbError::Io)?
                },
                freepages: RmdbFreePages {
                    lists: Vec::new(),
                    free: 0,
                },
            }),
            file: file,
        };

        // initialize
        rmdb.initialize()?;
        Ok(rmdb)
    }

    fn initialize(&mut self) -> Result<(), RmdbError> {
        let mut wlock = self.wlock.lock().unwrap();
        let mut rlock = self.rlock.write().unwrap();
        let num_pages = wlock.num_pages;

        /* so the first four pages are taken! */
        self.init_free_pages_map(&mut wlock)?;

        let alloc = self.get_free_pages(1usize, &mut wlock, true)?;
        rlock.rootpage = alloc[0];

        /* init empty root node */
        let root = page_get_payload!(mut, self, wlock.mmap, alloc[0]);
        pagebuf_set_int!(u16, root, POS_PAGETYPE, PAGE_NODE | PAGE_ROOT);
        pagebuf_set_int!(u16, root, NODE_NUMPTRS, 0u16);
        self.integrity_protect(&mut wlock.mmap, alloc[0])?;

        let (fp, fs) = self.set_free_pages_map(0, 0, &mut wlock)?;

        let main = page_get_payload!(mut, self, wlock.mmap, 0);
        pagebuf_set_buf!(main, RMDB_P_SIG, "RMDB".as_bytes());
        pagebuf_set_buf!(main, RMDB_P_VER, &RMDB_FILEVER.to_le_bytes());
        pagebuf_set_buf!(main, RMDB_P_FLAGS, &self.flags.bits().to_le_bytes());
        pagebuf_set_int!(u32, main, RMDB_P_PAGESIZE, self.pagesize as u32);
        pagebuf_set_int!(u32, main, RMDB_P_DBPAGES, num_pages);
        /* always reserve 2 pages for freepages, so we can fragment a bit,
         * without, immediately requiring freepages expansion */
        pagebuf_set_int!(u32, main, RMDB_P_FREEPAGES, fp);
        pagebuf_set_int!(u32, main, RMDB_P_FREESIZE, fs);
        pagebuf_set_int!(u32, main, RMDB_P_ROOT, alloc[0]);
        /* finally integrity protect main */
        self.integrity_protect(&mut wlock.mmap, 0)?;

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
                },
                freepages: RmdbFreePages {
                    lists: Vec::new(),
                    free: 0,
                },
            }),
            file: file,
        };

        rmdb.setup(flen as usize)?;
        Ok(rmdb)
    }

    fn setup(&mut self, flen: usize) -> Result<(), RmdbError> {

        /* Exclusive Access */
        let mut wlock = self.wlock.lock().unwrap();
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

        wlock.num_pages = pagebuf_get_int!(u32, rlock.mmap, RMDB_P_DBPAGES);
        if size_to_pages(self.pagesize, flen) < wlock.num_pages {
            return Err(RmdbError::InvalidFileSize)
        }
        /* FIXME:
         * if size_to_pages(self.pagesize, flen) > wlock.num_pages {
         *   File size is larger than stored num_pages,
         *   previous transaction abort or crash ?
         *   Should we truncate? Or simply increase the number
         *   of pages ?
         * } */

        if flen % self.pagesize != 0 {
            // corrupted, not a multiple of page size
            return Err(RmdbError::InvalidFileSize)
        }

        /* Set current root pages */
        rlock.rootpage = pagebuf_get_int!(u32, rlock.mmap, RMDB_P_ROOT);
        if rlock.rootpage == 0 {
            return Err(RmdbError::IntegrityCheck)
        }

        /* now check integrity of the fundamental pages */
        self.integrity_check(&rlock.mmap, 0)?;
        self.integrity_check(&rlock.mmap, rlock.rootpage)?;

        /* check root page */
        let page = page_get_payload!(self, rlock.mmap, rlock.rootpage);
        let ptype = pagebuf_get_int!(u16, page, POS_PAGETYPE);
        if ptype & PAGE_ROOT == 0 {
            return Err(RmdbError::IntegrityCheck)
        }

        self.get_free_pages_map(&mut *wlock)?;

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

    pub fn size(&self) -> Result<u64, RmdbError> {
        let meta = self.file.metadata()?;
        Ok(meta.len())
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

    fn integrity_protect(&self, mmap: &mut MmapMut, pagenum: u32)
            -> Result<(), RmdbError> {
        if self.flags.contains(RmdbFlags::PAGE_INTEGRITY) {
            let page = page_get_whole!(mut, self, mmap, pagenum);
            let datavec = vec![&page[0..(self.pagesize - RMDB_INTGSIZE)]];
            let hash = compute_hash(&datavec);
            page[(self.pagesize - RMDB_INTGSIZE)..self.pagesize].copy_from_slice(&hash);
        }
        Ok(())
    }

    fn integrity_check(&self, mmap: &[u8], pagenum: u32)
            -> Result<(), RmdbError> {
        if !self.flags.contains(RmdbFlags::PAGE_INTEGRITY) {
            return Ok(())
        }
        let page = page_get_whole!(self, mmap, pagenum);
        let (data, verify) = page.split_at(self.payload);
        let hash = compute_hash(&vec![data]);
        if verify != hash {
            return Err(RmdbError::IntegrityCheck)
        }
        Ok(())
    }

    fn data_integrity_check(&self, data: &Vec<&[u8]>, verify: &[u8])
            -> Result<(), RmdbError> {
        if !self.flags.contains(RmdbFlags::PAGE_INTEGRITY) {
            return Ok(())
        }
        let hash = compute_hash(data);
        if verify != hash {
            return Err(RmdbError::IntegrityCheck)
        }
        Ok(())
    }

    fn page_flush(&self, mmap: &mut MmapMut, page: u32)
            -> Result<(), RmdbError> {
        let (start, end) = page_range(self.pagesize, page, 0, self.pagesize)?;
        if self.flags.contains(RmdbFlags::PAGE_SYNC_FLUSH) {
            mmap.flush_range(start, end).unwrap();
        } else if self.flags.contains(RmdbFlags::PAGE_FLUSH) {
            mmap.flush_async_range(start, end).unwrap();
        }
        Ok(())
    }

    fn growdb(&self, to_page: u32, wlock: &mut RmdbWr)
            -> Result<(), RmdbError> {
        let oldpages = wlock.num_pages;

        /* always grow by no less than 4 pages to avoid constant churn as
         * pages are allocated piecemeal, also grow in multiple of 4 pages. */
        let numpages = ((to_page + 7) / 4) * 4;
        let size = (numpages + 1) as u64 * self.pagesize as u64;
        let meta = self.file.metadata()?;
        let filelen = meta.len();
        if size > filelen {
            self.file.set_len(size)?;
            wlock.num_pages = numpages;
            wlock.mmap = unsafe {
                MmapMut::map_mut(&self.file).map_err(RmdbError::Io)?
            };
        }

        let mut pnum = oldpages;
        let pluspages = numpages - oldpages;
        let mut s = pluspages as usize;
        let mut o = size_to_order(s);
        while s > 0 {
            let t = order_to_size(o);
            if t <= s {
                self.put_page_consolidate(pnum, o, wlock)?;
                pnum = pnum + t as u32;
                s = s - t;
            }
            o = o - 1;
        }
        wlock.freepages.free = wlock.freepages.free + pluspages;

        Ok(())
    }

    fn get_pages_from_block(&self, block: u32, size: usize, n: &mut usize,
                            wlock: &mut RmdbWr, res: &mut Vec<u32>)
            -> Result<(), RmdbError> {
        let mut t = size;
        if *n < t {
            t = *n;
        }
        for i in 0..t {
            res.push(block + i as u32);
        }
        *n = *n - t;
        if t < size {
            /* return unused pages to free lists */
            let mut rest = block + t as u32;
            let mut s = size - t;
            let mut o = 0usize;
            while s > 0 {
                if s & 1 == 1 {
                    /* insert while keeping lists sorted */
                    let v = &mut wlock.freepages.lists[o];
                    match v.binary_search(&rest) {
                        Ok(_pos) => {
                            /* we never have duplicates!! */
                            return Err(RmdbError::InvalidIndexSize)
                        }
                        Err(pos) => v.insert(pos, rest),
                    };
                    /* mark as entered al pages within this order block */
                    rest = rest + order_to_size(o) as u32;
                }
                s = s >> 1;
                o = o + 1;
                if o > RMDB_MAXORDER {
                    return Err(RmdbError::InvalidIndexSize)
                }
            }
        }

        wlock.freepages.free -= t as u32;

        Ok(())
    }

    fn get_free_pages(&self, n: usize, wlock: &mut RmdbWr, contiguous: bool)
            -> Result<Vec<u32>, RmdbError> {
        let mut res = Vec::with_capacity(n);
        let mut left = n;

        let order = size_to_order(n);
        if order > RMDB_MAXORDER {
            return Err(RmdbError::InvalidIndexSize)
        }
        let size = order_to_size(order);

        if left as u32 > wlock.freepages.free {
            self.growdb(wlock.num_pages + size as u32, wlock)?;
        }

        /* see if we can find a free page slot of the right order */
        let mut retries = 0;
        let mut o = order;
        while o <= RMDB_MAXORDER {
            /* try a whole block, if it fails, try a bigger one */
            match wlock.freepages.lists[o].pop() {
                Some(b) => {
                    let s = order_to_size(o);
                    self.get_pages_from_block(b, s, &mut left, wlock,
                                              &mut res)?;
                    if left != 0 {
                        return Err(RmdbError::InvalidIndexSize)
                    }
                    break;
                },
                None => {
                    o = o + 1;
                },
            };
            if o > RMDB_MAXORDER && retries < 1 {
                if contiguous == true {
                    self.growdb(wlock.num_pages + size as u32, wlock)?;
                    /* this should assure at least one block big enough */
                }
                retries += 1;
                o = order;
            }
        }
        if left == 0 {
            return Ok(res)
        } else if contiguous {
            return Err(RmdbError::InvalidIndexSize)
        }

        /* we have to fragment this allocation, go to smaller blocks */
        let mut o = size_to_order(left);
        while left > 0 {
            match wlock.freepages.lists[o].pop() {
                Some(b) => {
                    let s = 1 << o; /* size of block for this order */
                    self.get_pages_from_block(b, s, &mut left, wlock,
                                              &mut res)?;
                    o = size_to_order(left);
                },
                None => {
                    if o == 0 {
                        /* can't find free pages ? */
                        return Err(RmdbError::InvalidIndexSize)
                    }
                    o = o - 1;
                },
            };
        }

        if left > 0 {
            /* umpossible !? */
            return Err(RmdbError::InvalidMetadata)
        }

        Ok(res)
    }

    fn put_page_consolidate(&self, page: u32, order: usize,
                            wlock: &mut RmdbWr) -> Result<(), RmdbError> {
        let mut item = page;
        let mut o = order;
        while o < RMDB_MAXORDER {
            let v = &mut wlock.freepages.lists[o];
            match v.binary_search(&item) {
                Ok(_pos) => {
                    /* we never have duplicates!! */
                    return Err(RmdbError::InvalidIndexSize)
                }
                Err(pos) => {
                    /* see if we can consolidate to higher order */
                    let size = 1 << o;
                    let parity = size << 1;
                    if item % parity == 0 { /* "even" */
                        if v.len() > pos + 1 {
                            if v[pos] == item + size {
                                v.remove(pos);
                                o = o + 1;
                                continue;
                            }
                        }
                    } else { /* "odd" */
                        if pos > 0 {
                            if v[pos - 1] == item - size {
                                item = v.remove(pos - 1);
                                o = o + 1;
                                continue;
                            }
                        }
                    }
                    v.insert(pos, item);
                    return Ok(())
                }
            }
        }
        /* just insert at highest order */
        let v = &mut wlock.freepages.lists[o];
        match v.binary_search(&item) {
            Ok(_pos) => {
                /* we never have duplicates!! */
                return Err(RmdbError::InvalidIndexSize)
            }
            Err(pos) => {
                v.insert(pos, item);
            }
        };
        Ok(())
    }

    fn put_free_pages(&self, pvec: &mut Vec<u32>, wlock: &mut RmdbWr)
            -> Result<(), RmdbError> {
        /* first sort (inverted) so we know we go in order */
        pvec.sort_by(|a, b| b.cmp(a));
        while let Some(page) = pvec.pop() {
            let len = pvec.len();
            if page & 1 == 1 { /* odd */
                self.put_page_consolidate(page, 0, wlock)?;
            } else if len > 0 {
                /* see if these can constitute a block */
                let mut num = 0;
                let mut order = 0;
                let mut next = page + 1;
                let mut idx = len - 1;
                'double: while len > num {
                    let s = order_to_size(order);
                    for i in 0..s {
                        if pvec[idx - i] == next {
                            next = next + 1;
                        } else {
                            break 'double;
                        }
                    }
                    idx -= num;
                    num += s;
                    order += 1;
                }
                /* we found a block of order elements (can be 0) */
                pvec.truncate(len - num);
                self.put_page_consolidate(page, order, wlock)?;
            }
        }
        Ok(())
    }

    fn get_free_pages_map(&self, wlock: &mut RmdbWr) -> Result<(), RmdbError> {
        let main = page_get_payload!(self, wlock.mmap, 0);
        let fpptr = pagebuf_get_int!(u32, main, RMDB_P_FREEPAGES);
        let curpages = pagebuf_get_int!(u32, main, RMDB_P_FREESIZE);
        let free = page_get_payload!(self, wlock.mmap, fpptr);
        let cursize = pagebuf_get_int!(u32, free, FREE_MAP_SIZE) as usize;

        let ps = self.pagesize;
        let pl = self.payload;
        /* absolute start and end of free map */
        let fs = fpptr as usize * ps;
        let fe = fs + FREE_MAP + cursize;
        let freemap = &wlock.mmap[fs..fe];

        if self.flags.contains(RmdbFlags::PAGE_INTEGRITY) {
            let hash = compute_hash(&vec![freemap]);
            let lastpage = fpptr + curpages - 1;
            let hashpage = page_get_whole!(self, wlock.mmap, lastpage);
            if hash != hashpage[pl..ps] {
                return Err(RmdbError::IntegrityCheck)
            }
        }

        let mut lists = Vec::with_capacity(RMDB_MAXORDER + 1);
        let mut ptr = FREE_MAP;
        let mut free = 0u32;
        for o in 0..(RMDB_MAXORDER + 1) {
            let num = pagebuf_get_int!(u32, freemap, ptr) as usize;
            lists.insert(o, Vec::with_capacity(num));
            ptr = ptr + PTRSZ;
            for i in 0..num {
                let entry = pagebuf_get_int!(u32, freemap, ptr);
                lists[o].insert(i, entry);
                ptr = ptr + PTRSZ;
            }
            free = free + (num * order_to_size(o)) as u32;
        }
        wlock.freepages.lists = lists;
        wlock.freepages.free = free;

        Ok(())
    }

    fn set_free_pages_map(&self, fpptr: u32, fpsize: u32, wlock: &mut RmdbWr)
            -> Result<(u32, u32), RmdbError> {
        let ps = self.pagesize;
        let pl = self.payload;
        let overhead = FREE_MAP + ps - pl;

        /* always allocate a new freepages area, so that a commit failure
         * leaves the DB in a good state */
        let mut newptr = fpptr;
        let mut newsize = 0u32;
        let mut bytesize = 0usize;
        let mut allocsize = fpsize;
        let mut retries = 0;
        while retries < 3 {
            /* calculate how much space is necessary */
            bytesize = 0;
            for r in &wlock.freepages.lists {
                bytesize = bytesize + (1 + r.len()) * PTRSZ;
            }
            newsize = ((bytesize + overhead + ps - 1) / ps) as u32;

            if allocsize == newsize {
                break;
            }

            /* zero on initialization */
            if allocsize > 0 {
                let mut freevec = Vec::with_capacity(allocsize as usize);
                for p in 0..allocsize {
                    freevec.push(newptr + p);
                }
                self.put_free_pages(&mut freevec, wlock)?;
            }

            let vec = self.get_free_pages(newsize as usize, wlock, true)?;
            newptr = vec[0];
            allocsize = vec.len() as u32;
            retries += 1;
        }
        if allocsize != newsize {
            return Err(RmdbError::InvalidMetadata);
        }

        /* absolute start and end of free map */
        let fs = newptr as usize * ps;
        let fe = fs + FREE_MAP + bytesize;

        let freemap = &mut wlock.mmap[fs..fe];
        pagebuf_set_int!(u16, freemap, POS_PAGETYPE, PAGE_FREE);
        pagebuf_set_int!(u32, freemap, FREE_MAP_SIZE, bytesize as u32);

        let mut ptr = FREE_MAP;
        let freevec = &wlock.freepages.lists;
        for r in freevec {
            pagebuf_set_int!(u32, freemap, ptr, r.len() as u32);
            ptr = ptr + PTRSZ;
            for e in r {
                pagebuf_set_int!(u32, freemap, ptr, e);
                ptr = ptr + PTRSZ;
            }
        }

        /* optionally integrity protect freepages */
        if self.flags.contains(RmdbFlags::PAGE_INTEGRITY) {
            let hash = compute_hash(&vec![&freemap]);
            let lastpage = newptr + newsize - 1;
            let hashpage = page_get_whole!(mut, self, wlock.mmap, lastpage);
            hashpage[pl..ps].copy_from_slice(&hash);
        }

        Ok((newptr, newsize))
    }

    fn init_free_pages_map(&self, wlock: &mut RmdbWr)
            -> Result<(), RmdbError> {
        let mut lists = vec![Vec::new(); RMDB_MAXORDER + 1];
        let order = size_to_order(wlock.num_pages as usize);
        /* start at 1 as page 0 is always reserved */
        let mut pnum = 1u32;
        /* given a few used pages we must split the highest order
         * block in two, so use (order - 1) for size of first block */
        let mut s = (order_to_size(order - 1)) - 1;
        let mut o = 0usize;
        while s > 0 {
            if s & 1 == 1 {
                let v = &mut lists[o];
                v.push(pnum);
                /* mark as entered al pages within this order block */
                pnum = pnum + order_to_size(o) as u32;
            }
            s = s >> 1;
            o = o + 1;
            if o > RMDB_MAXORDER {
                return Err(RmdbError::InvalidIndexSize);
            }
        }
        /* NOTE: that pnum here is aligned to #o (order-1) size,
         * so we need to walk backwards to split blocks to add
         * the remaining pages here */
        s = (wlock.num_pages - pnum) as usize;
        o = size_to_order(s);
        while s > 0 {
            let t = order_to_size(o);
            if t <= s {
                let v = &mut lists[o];
                v.push(pnum);
                pnum = pnum + t as u32;
                s = s - t;
            }
            o = o - 1;
        }
        wlock.freepages.lists = lists;
        wlock.freepages.free = wlock.num_pages - 1;
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

fn size_to_order(n: usize) -> usize {
    let mut o = 0usize;
    let mut s = 1usize;
    while n > s {
        o = o + 1;
        s = s << 1;
    }
    o
}

fn order_to_size(o: usize) -> usize {
    1 << o
}

fn size_to_pages(pagesize: usize, size: usize) -> u32 {
    return ((size + pagesize - 1) / pagesize) as u32;
}

pub fn payload_size(pagesize: usize, flags: RmdbFlags) -> usize {
    let mut size = pagesize;
    if flags.contains(RmdbFlags::PAGE_INTEGRITY) {
        size -= RMDB_INTGSIZE;
    }
    return size;
}

fn page_range(pagesize: usize, index: u32, offset: usize, size: usize)
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

fn compute_hash(data: &Vec<&[u8]>) -> [u8; RMDB_INTGSIZE] {
    let mut hasher = sha::Sha256::new();
    for d in data {
        hasher.update(d);
    }
    hasher.finish()
}

pub enum RmdbTxnState {
    Open,
    Committed,
    Scrubbed
}

struct RmdbFetch<'a> {
    rmdb: &'a Rmdb,
    mmap: &'a [u8],
    rootpage: u32,
}

impl<'a> RmdbFetch<'a> {

    fn new(rmdb: &'a Rmdb, mmap: &'a [u8], rootpage: u32)
            -> RmdbFetch<'a> {
        RmdbFetch {
            rmdb: rmdb,
            mmap: mmap,
            rootpage: rootpage,
        }
    }

    // returns root when key not found
    fn get_data(&self, leafnum: u32, key: &[u8], integrity_check: bool)
            -> Result<Vec<&'a [u8]>, RmdbError> {
        let page = page_get_payload!(self.rmdb, self.mmap, leafnum);
        let ptype = pagebuf_get_int!(u16, page, POS_PAGETYPE);
        if ptype & PAGE_LEAF != PAGE_LEAF {
            return Err(RmdbError::InvalidMetadata);
        }

        let mut res = Vec::new();

        /* find data */
        let keynum = pagebuf_get_int!(u16, page, LEAF_KEYNUM);
        for k in 0..keynum as usize {
            let base = pagebuf_get_int!(u16, page, LEAF_KEYPTRS + k) as usize;
            let klen = pagebuf_get_int!(u16, page, base + LEAF_PL_KLEN);
            let kl = (klen & 0x7FFF) as usize;
            let kk = pagebuf_get_buf!(page, base + LEAF_PL_KEY as usize, kl);
            if kk != key {
                continue;
            }
            let dataptr = align!(u32, base + 2 + kl);
            if klen as usize == kl {
                let datalen = pagebuf_get_int!(u16, page, dataptr) as usize;
                res.push(&page[(dataptr + 2)..(dataptr + 2 + datalen)]);
            } else {
                let dsize = pagebuf_get_int!(u32, page, dataptr) as usize;
                let pnum = pagebuf_get_int!(u32, page, dataptr + 4) as u32;
                let ps = self.rmdb.pagesize;
                let pages = (dsize + ps - 1) / ps;
                let data = page_get_many!(self.rmdb, self.mmap, pnum, pages);
                if integrity_check == true {
                    let h = pagebuf_get_buf!(page, dataptr + 8, RMDB_INTGSIZE);
                    self.rmdb.data_integrity_check(&vec![&data[0..dsize]], h)?;
                }
                res.push(&data[0..dsize]);
            }
            break;
        }
        Ok(res)
    }

    /* FIXME: returns first key only ... until change */
    fn get_leaf_key(&self, leaf: u32) -> Result<&'a [u8], RmdbError> {
        let page = page_get_payload!(self.rmdb, self.mmap, leaf);
        let ptype = pagebuf_get_int!(u16, page, POS_PAGETYPE);
        if ptype & PAGE_LEAF != PAGE_LEAF {
            return Err(RmdbError::PageNotLeaf)
        }
        let keynum = pagebuf_get_int!(u16, page, LEAF_KEYNUM);
        if keynum != 1 {
            return Err(RmdbError::InvalidMetadata)
        }
        let base = pagebuf_get_int!(u16, page, LEAF_KEYPTRS) as usize;
        let klen = pagebuf_get_int!(u16, page, base + LEAF_PL_KLEN) as usize;
        Ok(pagebuf_get_buf!(page, base + LEAF_PL_KEY, (klen & 0x7FFF)))
    }

    /* base must be a node page, if 0 is provided we start from rootpage */
    fn get_parents_leaf(&self, base: u32, key: &[u8],
                        parents: &mut Vec<u32>) -> Result<u32, RmdbError> {
        let mut pagenum = base;
        if pagenum == 0 {
            if self.rootpage == 0 {
                return Err(RmdbError::KeyNotFound);
            }
            pagenum = self.rootpage;
        }
        let page = page_get_payload!(self.rmdb, self.mmap, pagenum);
        let ptype = pagebuf_get_int!(u16, page, POS_PAGETYPE);
        if ptype & PAGE_NODE != PAGE_NODE {
            return Err(RmdbError::InvalidMetadata);
        }
        parents.push(pagenum);
        let parents_size = parents.len();

        let nptrs = pagebuf_get_int!(u16, page, NODE_NUMPTRS) as usize;

        /* test head and tail first, then dive into */
        /* HEAD */
        if nptrs == 0 {
            return Err(RmdbError::KeyNotFound);
        }

        let head = 0usize;
        let tail = nptrs - 1;

        let pageptr = pagebuf_get_int!(u32, page, NODE_FIRSTPTR);
        match self.get_leaf_key(pageptr) {
            Ok(pkey) => {
                if key == pkey {
                    return Ok(pageptr);
                }
                if key < pkey {
                    return Err(RmdbError::KeyTooSmall);
                }
            },
            Err(error) => {
                /* PageNotLeaf means this is a node of nodes */
                match error {
                    RmdbError::PageNotLeaf => (),
                    _ => return Err(error),
                };
                match self.get_parents_leaf(pageptr, key, parents) {
                    Ok(leaf) => return Ok(leaf),
                    Err(error) => {
                        /* KeyTooBig means continue with loop */
                        match error {
                            RmdbError::KeyTooBig => (),
                            _ => return Err(error),
                        };
                    },
                };
            },
        };

        /* remove any parent the HEAD check may have added */
        parents.truncate(parents_size);

        /* TAIL */
        if tail == head {
            return Err(RmdbError::KeyTooBig);
        }
        let pageptr = pagebuf_get_int!(u32, page,
                                       NODE_FIRSTPTR + tail * PTRSZ);
        match self.get_leaf_key(pageptr) {
            Ok(pkey) => {
                if key == pkey {
                    return Ok(pageptr);
                }
                if key > pkey {
                    /* key not found, and found pkey is smaller, stop looking
                     * as the key is not in here */
                    return Err(RmdbError::KeyTooBig);
                }
            },
            Err(error) => {
                /* PageNotLeaf means this is a node of nodes */
                match error {
                    RmdbError::PageNotLeaf => (),
                    _ => return Err(error),
                };
                match self.get_parents_leaf(pageptr, key, parents) {
                    Ok(leaf) => return Ok(leaf),
                    Err(error) => {
                        /* KeyTooBig means we can't find it at all,
                         * while KeyTooSmall means it may be in the
                         * rest of the array */
                        match error {
                            RmdbError::KeyTooSmall => (),
                            _ => return Err(error),
                        };
                    },
                };
            },
        };

        /* inner array, the key belongs to this node, whether it is found or not */
        if nptrs == 2 {
            return Err(RmdbError::KeyNotFound);
        }

        let mut bisect = [head + 1, tail - 1];
        while bisect[0] <= bisect[1] {
            /* remove any parent the previous check may have added */
            parents.truncate(parents_size);
            let mid = (bisect[0] + bisect[1]) / 2;
            let pageptr = pagebuf_get_int!(u32, page,
                                           NODE_FIRSTPTR + mid * PTRSZ);
            match self.get_leaf_key(pageptr) {
                Ok(pkey) => {
                    if key == pkey {
                        return Ok(pageptr);
                    }
                    if key > pkey {
                        bisect[0] = mid + 1;
                    } else {
                        bisect[1] = mid - 1;
                    }
                },
                Err(error) => {
                    /* PageNotLeaf means this is a node of nodes */
                    match error {
                        RmdbError::PageNotLeaf => (),
                        _ => return Err(error),
                    };
                    match self.get_parents_leaf(pageptr, key, parents) {
                        Ok(leaf) => {
                            return Ok(leaf);
                        },
                        Err(error) => {
                            match error {
                                RmdbError::KeyTooSmall => bisect[1] = mid -1,
                                RmdbError::KeyTooBig => bisect[0] = mid + 1,
                                _ => return Err(error),
                            };
                        },
                    };
                },
            };
        }
        return Err(RmdbError::KeyNotFound);
    }

    fn get_parents(&self, key: &[u8]) -> Result<Vec<u32>, RmdbError> {
        let mut parents = Vec::new();
        match self.get_parents_leaf(0, key, &mut parents) {
            Ok(_leaf) => Ok(parents),
            Err(error) => match error {
                RmdbError::KeyNotFound => Ok(parents),
                RmdbError::KeyTooSmall => Ok(parents),
                RmdbError::KeyTooBig => Ok(parents),
                _ => Err(error),
            },
        }
    }

    fn get_leaf(&self, key: &[u8]) -> Result<u32, RmdbError> {
        let mut parents = Vec::new();
        match self.get_parents_leaf(0, key, &mut parents) {
            Ok(leaf) => Ok(leaf),
            Err(error) => match error {
                RmdbError::KeyTooSmall => Err(RmdbError::KeyNotFound),
                RmdbError::KeyTooBig => Err(RmdbError::KeyNotFound),
                _ => Err(error),
            },
        }
    }

    fn get_first_element(&self) -> Result<Vec<u32>, RmdbError> {
        if self.rootpage == 0 {
            return Err(RmdbError::KeyNotFound);
        }
        let mut res: Vec<u32> = Vec::new();
        let mut pagenum = self.rootpage;
        let mut page = page_get_payload!(self.rmdb, self.mmap, pagenum);
        let mut ptype = pagebuf_get_int!(u16, page, POS_PAGETYPE);
        while ptype & PAGE_NODE == PAGE_NODE {
            res.push(pagenum);
            pagenum = pagebuf_get_int!(u32, page, NODE_FIRSTPTR);
            page = page_get_payload!(self.rmdb, self.mmap, pagenum);
            ptype = pagebuf_get_int!(u16, page, POS_PAGETYPE);
        }
        if res.len() == 0 || ptype & PAGE_LEAF != PAGE_LEAF {
            return Err(RmdbError::InvalidMetadata);
        }
        /* add the leaf too */
        res.push(pagenum);
        Ok(res)
    }

    fn get_next_element(&self, chain: &Vec<u32>)
            -> Result<Vec<u32>, RmdbError> {
        let mut walker = chain.to_vec();
        let mut current = walker.pop().ok_or_else(
                                            || RmdbError::InvalidMetadata)?;
        while walker.len() > 0 {
            let parent = *walker.last().ok_or_else(
                                            || RmdbError::InvalidMetadata)?;
            let page = page_get_payload!(self.rmdb, self.mmap, parent);
            let ptype = pagebuf_get_int!(u16, page, POS_PAGETYPE);
            if  ptype & PAGE_NODE != PAGE_NODE {
                return Err(RmdbError::InvalidMetadata);
            }
            let nptrs = pagebuf_get_int!(u16, page, NODE_NUMPTRS) as usize;
            if nptrs == 0 {
                return Err(RmdbError::InvalidMetadata);
            }

            let mut ptr = 0usize;
            if current == 0 {
                ptr = NODE_FIRSTPTR;
            } else {
                let mut idx = NODE_FIRSTPTR;
                for _ in 0..(nptrs - 1) {
                    let node = pagebuf_get_int!(u32, page, idx);
                    if node == current {
                        ptr = idx + PTRSZ;
                        break;
                    }
                    idx += PTRSZ;
                }
            }
            if ptr != 0 {
                let node = pagebuf_get_int!(u32, page, ptr);
                let page = page_get_payload!(self.rmdb, self.mmap, node);
                let ptype = pagebuf_get_int!(u16, page, POS_PAGETYPE);
                if  ptype & PAGE_LEAF == PAGE_LEAF {
                    /* found */
                    walker.push(node);
                    return Ok(walker);
                } else if ptype & PAGE_NODE == PAGE_NODE {
                    walker.push(node);
                    current = 0;
                }
            } else {
                current = walker.pop().ok_or_else(
                                            || RmdbError::InvalidMetadata)?;
            }
        }
        /* we reached the last element */
        Err(RmdbError::KeyNotFound)
    }
}

pub struct RmdbCursor<'a> {
    txn: &'a RmdbTxn<'a>,
    cursor: Vec<u32>,
}

impl<'a> RmdbCursor<'a> {

    pub fn get_current(&mut self) -> Result<(&[u8], Vec<&'a [u8]>), RmdbError> {
        let fetch = RmdbFetch::new(self.txn.rmdb, &self.txn.rlock.mmap,
                                   self.txn.rlock.rootpage);
        let leafnum = match self.cursor.last() {
            Some(x) => *x,
            None => {
                self.cursor = fetch.get_first_element()?;
                *self.cursor.last().unwrap()
            },
        };
        let key = fetch.get_leaf_key(leafnum)?;
        let val = fetch.get_data(leafnum, key, true)?;
        Ok((key, val))
    }

    pub fn get_next(&mut self) -> Result<(&[u8], Vec<&'a [u8]>), RmdbError> {
        let fetch = RmdbFetch::new(self.txn.rmdb, &self.txn.rlock.mmap,
                                   self.txn.rlock.rootpage);
        if self.cursor.len() == 0 {
            self.cursor = fetch.get_first_element()?;
        } else {
            self.cursor = fetch.get_next_element(&self.cursor)?;
        }
        self.get_current()
    }

    pub fn set_to(&mut self, key: &[u8]) -> Result<(), RmdbError> {
        let fetch = RmdbFetch::new(self.txn.rmdb, &self.txn.rlock.mmap,
                                   self.txn.rlock.rootpage);
        let mut chain = Vec::new();
        let leaf = fetch.get_parents_leaf(0, key, &mut chain)?;
        chain.push(leaf);
        self.cursor = chain;
        Ok(())
    }
}

pub struct RmdbTxn<'a> {
    rlock: RwLockReadGuard<'a, RmdbRd>,
    status: RmdbTxnState,
    rmdb: &'a Rmdb,
}

impl RmdbTxn<'_> {

    pub fn get_entry(&self, key: &[u8]) -> Result<Vec<&[u8]>, RmdbError> {
        let fetch = RmdbFetch::new(self.rmdb, &self.rlock.mmap,
                                   self.rlock.rootpage);
        let leaf = fetch.get_leaf(key)?;
        self.rmdb.integrity_check(&self.rlock.mmap, leaf)?;
        fetch.get_data(leaf, key, true)
    }

    fn _scrub(&mut self) {
        self.status = RmdbTxnState::Scrubbed
    }

    pub fn get_cursor<'a>(&'a mut self) -> Result<RmdbCursor<'a>, RmdbError> {
        Ok(RmdbCursor {
            txn: self,
            cursor: Vec::new(),
        })
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
    rootpage: u32,
    rmdb: &'a Rmdb,
    dirtypages: Vec<u32>,
    deletepages: Vec<u32>,
}

impl RmdbWTxn<'_> {

    fn put_free_pages(&mut self, pvec: &mut Vec<u32>) -> Result<(), RmdbError> {
        self.rmdb.put_free_pages(pvec, &mut self.wlock)
    }

    pub fn get_entry(&mut self, key: &[u8]) -> Result<Vec<&[u8]>, RmdbError> {
        if self.rootpage == 0 {
            return Err(RmdbError::KeyNotFound);
        }
        let fetch = RmdbFetch::new(self.rmdb, &self.wlock.mmap, self.rootpage);
        let leaf = fetch.get_leaf(key)?;
        fetch.get_data(leaf, key, true)
    }

    pub fn add_entry(&mut self, key: &[u8], value: &[u8])
                                                -> Result<(), RmdbError> {

        let mut leaf_payload = self.rmdb.payload;
        if self.rmdb.flags.contains(RmdbFlags::PAGE_INTEGRITY) {
            leaf_payload -= RMDB_INTGSIZE;
        }

        /* create new pages */
        let datasize = value.len();
        let ps = self.rmdb.pagesize;
        let mut pages = (datasize + ps + 1) / ps;
        if pages == 1 {
            /* FIXME: bogus */
            let overhead = PTRSZ + LEAF_KEYPTRS +
                           align!(u32, key.len()) as usize;
            if leaf_payload < overhead {
                return Err(RmdbError::InvalidDataSize);
            }
            let avail_space = leaf_payload - overhead;
            if avail_space > datasize {
                pages = 0;
            }
        }

        /* write leaf page */
        let pagevec = self.rmdb.get_free_pages(pages + 1, &mut self.wlock, true)?;
        let leaf = pagevec[0];
        self.mark_dirty(leaf, true);

        let mut page = page_get_payload!(mut, self.rmdb, self.wlock.mmap, leaf);

        pagebuf_set_int!(u16, &mut page, POS_PAGETYPE, PAGE_LEAF);
        pagebuf_set_int!(u16, &mut page, LEAF_KEYNUM,  1u16);

        /* todo use a sub slice so we have boundary checks and ptrs */
        let leafcell = 8usize;
        let dataptr = align!(u32, leafcell + 2 + key.len());

        /* until we support multiple keys hardcode: */
        pagebuf_set_int!(u16, &mut page, LEAF_KEYPTRS + 0, leafcell as u16);

        let mut klen = key.len() as u16;
        if pages > 0 {
            klen = klen | 0x8000;
        }
        pagebuf_set_int!(u16, &mut page, leafcell, klen);
        pagebuf_set_buf!(&mut page, leafcell + LEAF_PL_KEY, key);

        /* copy data */
        if pages > 0 {
            /* get consecutive pages for data */
            let data = page_get_many!(mut, self.rmdb, self.wlock.mmap,
                                      pagevec[1], pagevec.len() - 1);
            data[0..datasize].copy_from_slice(value);

            page = page_get_payload!(mut, self.rmdb, self.wlock.mmap, leaf);
            pagebuf_set_int!(u32, &mut page, dataptr, datasize as u32);
            pagebuf_set_int!(u32, &mut page, dataptr + 4, pagevec[1]);
            if self.rmdb.flags.contains(RmdbFlags::PAGE_INTEGRITY) {
                let hash = compute_hash(&vec![value]);
                pagebuf_set_buf!(&mut page, dataptr + 8, &hash);
            }
        } else {
            pagebuf_set_int!(u16, &mut page, dataptr, value.len() as u16);
            pagebuf_set_buf!(&mut page, dataptr + 2, value);
        }

        /* then add them to the tree */
        let fetch = RmdbFetch::new(self.rmdb, &self.wlock.mmap, self.rootpage);
        let cur_leaf = fetch.get_leaf(key);
        let cur_leaf = match cur_leaf {
            Ok(cur_leaf) => cur_leaf,
            Err(error) => {
                match error {
                    RmdbError::KeyNotFound => 0u32,
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
        let fetch = RmdbFetch::new(self.rmdb, &self.wlock.mmap, self.rootpage);
        let mut parents = Vec::new();
        let result = fetch.get_parents_leaf(0, key, &mut parents);
        let leaf = match result {
            Ok(leaf) => leaf,
            Err(error) => match error {
                RmdbError::KeyTooSmall => return Err(RmdbError::KeyNotFound),
                RmdbError::KeyTooBig => return Err(RmdbError::KeyNotFound),
                _ => return Err(error),
            },
        };
        self.del_leaf(&mut parents, leaf)
    }

    fn delete_page(&mut self, pagenum: u32) {
        let page = page_get_payload!(self.rmdb, self.wlock.mmap, pagenum);
        let ptype = pagebuf_get_int!(u16, page, POS_PAGETYPE);
        if (ptype & PAGE_DIRTY) == PAGE_DIRTY {
            /* if dirty return immediately to free pages */
            self.put_free_pages(&mut [pagenum].to_vec()).unwrap();
            /* and remove from dirty pages */
            self.dirtypages.retain(|&x| x != pagenum);
        } else {
            /* otherwise mark for deletion on commit */
            self.deletepages.push(pagenum);
        }
    }

    fn replace_childptr(&mut self, parent: u32, curptr: u32, newptr: u32)
            -> Result<(), RmdbError> {
        let mut page = page_get_payload!(mut, self.rmdb, self.wlock.mmap, parent);
        let nptrs = pagebuf_get_int!(u16, page, NODE_NUMPTRS) as usize;
        if nptrs == 0 {
            return Err(RmdbError::KeyNotFound);
        }
        for n in 0..nptrs {
            let idx = NODE_FIRSTPTR + n * PTRSZ;
            let pageptr = pagebuf_get_int!(u32, page, idx);
            if pageptr == curptr {
                pagebuf_set_int!(u32, &mut page, idx, newptr);
                return Ok(());
            }
        }
        Err(RmdbError::KeyNotFound)
    }

    fn page_copy(&mut self, src: u32, dst: u32) -> Result<(), RmdbError> {
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

    fn get_new_page_copy(&mut self, source: u32) -> Result<u32, RmdbError> {
        let copy = self.rmdb.get_free_pages(1, &mut self.wlock, false)?[0];
        self.mark_dirty(copy, false);
        self.page_copy(source, copy)?;

        Ok(copy)
    }

    fn mark_dirty(&mut self, pagenum: u32, zeropage: bool) {
        let mut page = page_get_payload!(mut, self.rmdb, self.wlock.mmap, pagenum);
        let mut ptype = pagebuf_get_int!(u16, page, POS_PAGETYPE);
        ptype |= PAGE_DIRTY;
        pagebuf_set_int!(u16, &mut page, POS_PAGETYPE, ptype);
        if ! self.dirtypages.contains(&pagenum) {
            self.dirtypages.push(pagenum);
        }
        if zeropage && self.rmdb.flags.contains(RmdbFlags::ZERO_PAGES) {
            let mut zero: Vec<u8> = Vec::new();
            zero.resize_with(page.len() - POS_PAGEDATA, Default::default);
            pagebuf_set_buf!(page, POS_PAGEDATA, &zero);
        }
    }

    fn replace_node(&mut self, parents: &mut Vec<u32>, current: u32)
            -> Result<u32, RmdbError> {
        let newpage = self.get_new_page_copy(current)?;
        self.delete_page(current);
        if current == self.rootpage {
            self.rootpage = newpage;
        } else {
            let mut parent = match parents.pop() {
                Some(parent) => parent,
                None => return Err(RmdbError::InvalidMetadata),
            };
            let page = page_get_payload!(self.rmdb, self.wlock.mmap, parent);
            let ptype = pagebuf_get_int!(u16, page, POS_PAGETYPE);
            if ptype & PAGE_DIRTY != PAGE_DIRTY {
                parent = self.replace_node(parents, parent)?;
            }
            /* reload, may have changed */
            let page = page_get_payload!(mut, self.rmdb, self.wlock.mmap, parent);
            let nptrs = pagebuf_get_int!(u16, page, NODE_NUMPTRS) as usize;

            let mut idx = NODE_FIRSTPTR;
            for _ in 0..nptrs {
                let node = pagebuf_get_int!(u32, page, idx);
                if node == current {
                    pagebuf_set_int!(u32, page, idx, newpage);
                    break;
                }
                idx += PTRSZ;
            }
            if idx == NODE_FIRSTPTR + nptrs * PTRSZ {
                return Err(RmdbError::InvalidMetadata);
            }
            /* put, potentially new, parent back in the parents stack */
            parents.push(parent);
        }
        Ok(newpage)
    }

    fn replace_leaf(&mut self, curchild: u32, newchild: u32)
            -> Result<(), RmdbError> {
        let fetch = RmdbFetch::new(self.rmdb, &self.wlock.mmap, self.rootpage);
        let key = fetch.get_leaf_key(curchild)?;
        let mut parents = fetch.get_parents(key)?;
        let mut parent = match parents.pop() {
            Some(parent) => parent,
            None => return Err(RmdbError::InvalidMetadata),
        };
        let page = page_get_payload!(self.rmdb, self.wlock.mmap, parent);
        let ptype = pagebuf_get_int!(u16, page, POS_PAGETYPE);
        if ptype & PAGE_DIRTY == 0 {
            /* page not dirty, we must Copy on Write */
            parent = self.replace_node(&mut parents, parent)?;
        }
        self.replace_childptr(parent, curchild, newchild)?;
        self.delete_page(curchild);

        Ok(())
    }

    fn split_node(&mut self, parents: &mut Vec<u32>, current: u32)
            -> Result<(u32, u32), RmdbError> {
        let mut parent = match parents.pop() {
            Some(parent) => parent,
            None => {
                /* splitting root node */
                let rootpage = self.rmdb.get_free_pages(1, &mut self.wlock,
                                                        false)?[0];
                self.mark_dirty(rootpage, true);
                let mut page = page_get_payload!(mut, self.rmdb, self.wlock.mmap,
                                                 rootpage);
                pagebuf_set_int!(u16, &mut page, POS_PAGETYPE,
                                 PAGE_NODE | PAGE_ROOT);
                pagebuf_set_int!(u16, &mut page, NODE_NUMPTRS, 0u16);
                self.rootpage = rootpage;
                rootpage
            },
        };
        let page = page_get_payload!(self.rmdb, self.wlock.mmap, parent);
        let ptype = pagebuf_get_int!(u16, page, POS_PAGETYPE);
        let nptrs = pagebuf_get_int!(u16, page, NODE_NUMPTRS) as usize;
        let topptr = NODE_FIRSTPTR + nptrs * PTRSZ;
        if topptr + PTRSZ <= self.rmdb.payload {
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
            let nptrs = pagebuf_get_int!(u16, page, NODE_NUMPTRS) as usize;
            let mut idx = NODE_FIRSTPTR;
            for _ in 0..nptrs {
                let node = pagebuf_get_int!(u32, page, idx);
                if node == current {
                    idx = 1;
                    break;
                }
                idx += PTRSZ;
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
        pagebuf_set_int!(u16, page, POS_PAGETYPE, PAGE_NODE | PAGE_DIRTY);
        let nptrs = pagebuf_get_int!(u16, page, NODE_NUMPTRS) as usize;
        let lptrs = nptrs / 2;
        pagebuf_set_int!(u16, page, NODE_NUMPTRS, lptrs as u16);

        /* update right */
        let page = page_get_payload!(mut, self.rmdb, self.wlock.mmap, right);
        /* mark as dirty node (removes PAGE_ROOT on split of rootpage) */
        pagebuf_set_int!(u16, page, POS_PAGETYPE, PAGE_NODE | PAGE_DIRTY);
        let rptrs = nptrs - lptrs;
        let mut sidx = NODE_FIRSTPTR + lptrs * PTRSZ;
        let mut didx = NODE_FIRSTPTR;
        for _ in 0..rptrs {
            let node = pagebuf_get_int!(u32, page, sidx);
            pagebuf_set_int!(u32, page, didx, node);
            sidx += PTRSZ;
            didx += PTRSZ;
        }
        pagebuf_set_int!(u16, page, NODE_NUMPTRS, rptrs as u16);

        /* update the parent to insert two pages where the current is */
        let page = page_get_payload!(mut, self.rmdb, self.wlock.mmap, parent);
        let nptrs = pagebuf_get_int!(u16, page, NODE_NUMPTRS) as usize;

        let mut idx = NODE_FIRSTPTR;
        let mut ins = 0usize;
        for n in 0..nptrs {
            let node = pagebuf_get_int!(u32, page, idx);
            if node == current {
                ins = n;
                break;
            }
            idx += PTRSZ;
        }

        /* found insertion point, copy the rest one over */
        for n in (ins..nptrs).rev() {
            idx = NODE_FIRSTPTR + n * PTRSZ;
            let node = pagebuf_get_int!(u32, page, idx);
            pagebuf_set_int!(u32, page, idx + PTRSZ, node);
        }
        /* set left and right nodes */
        idx = NODE_FIRSTPTR + ins * PTRSZ;
        pagebuf_set_int!(u32, page, idx, left);
        pagebuf_set_int!(u32, page, idx + PTRSZ, right);

        if nptrs > 0 {
            pagebuf_set_int!(u16, page, NODE_NUMPTRS, (nptrs + 1) as u16);
        } else {
            /* if we split the root we get a new empty top node */
            pagebuf_set_int!(u16, page, NODE_NUMPTRS, 2u16);
        }

        /* add new parent onto the parents stack now */
        parents.push(parent);

        /* remove old splitted page */
        self.delete_page(current);
        Ok((left, right))
    }

    fn add_leaf(&mut self, leaf: u32, key: &[u8])
            -> Result<(), RmdbError> {
        let fetch = RmdbFetch::new(self.rmdb, &self.wlock.mmap, self.rootpage);
        let mut parents = fetch.get_parents(key)?;
        drop(fetch);
        let mut parent = match parents.pop() {
            Some(parent) => parent,
            None => return Err(RmdbError::InvalidMetadata),
        };
        let page = page_get_payload!(self.rmdb, self.wlock.mmap, parent);
        let ptype = pagebuf_get_int!(u16, page, POS_PAGETYPE);
        let nptrs = pagebuf_get_int!(u16, page, NODE_NUMPTRS) as usize;
        let topptr = NODE_FIRSTPTR + nptrs * PTRSZ;
        if topptr + PTRSZ <= self.rmdb.payload {
            /* there is space here */
            if ptype & PAGE_DIRTY != PAGE_DIRTY {
                /* page not dirty, we must Copy on Write */
                parent = self.replace_node(&mut parents, parent)?;
            }
        } else {
            /* page split */
            let (left, right) = self.split_node(&mut parents, parent)?;

            /* after split find again which node to be added to */
            let fetch = RmdbFetch::new(self.rmdb, &self.wlock.mmap,
                                       self.rootpage);
            let mut dummy = Vec::new();
            parent = match fetch.get_parents_leaf(left, key, &mut dummy) {
                Ok(_leaf) => return Err(RmdbError::InvalidMetadata),
                Err(error) => match error {
                    RmdbError::KeyNotFound => left,
                    RmdbError::KeyTooSmall => left,
                    RmdbError::KeyTooBig => right,
                    _ => return Err(error),
                },
            };
            drop(fetch);
        }

        /* map page again as it may have changed */
        let page = page_get_payload!(self.rmdb, self.wlock.mmap, parent);

        let nptrs = pagebuf_get_int!(u16, page, NODE_NUMPTRS) as usize;
        let topptr = NODE_FIRSTPTR + nptrs * PTRSZ;
        if topptr + PTRSZ > self.rmdb.payload {
            return Err(RmdbError::InvalidMetadata)
        }

        /* add leaf to index */
        let fetch = RmdbFetch::new(self.rmdb, &self.wlock.mmap, self.rootpage);
        let mut idx = NODE_FIRSTPTR;
        for n in (0..nptrs).rev() {
            idx = NODE_FIRSTPTR + n * PTRSZ;
            let node = pagebuf_get_int!(u32, page, idx);
            let pkey = fetch.get_leaf_key(node).unwrap();
            if key == pkey {
                return Err(RmdbError::InvalidMetadata);
            }
            if key > pkey {
                idx += PTRSZ;
                break;
            }
        }
        drop(fetch);

        /* we found the insertion point, add key index here, and move,
         * all other upwards */

        /* get again page as mutuable now to make changes */
        let page = page_get_payload!(mut, self.rmdb, self.wlock.mmap, parent);

        let mptrs = (topptr - idx) / PTRSZ;

        /* ignored if we are operating on the highest slot */
        let mut savedptr = pagebuf_get_int!(u32, page, idx);

        /* set new in slot */
        pagebuf_set_int!(u32, page, idx, leaf);

        /* move all others up if any */
        idx += PTRSZ;
        for _ in 0..mptrs {
            let curptr = pagebuf_get_int!(u32, page, idx);
            pagebuf_set_int!(u32, page, idx, savedptr);
            savedptr = curptr;
            idx += PTRSZ;
        }

        pagebuf_set_int!(u16, page, NODE_NUMPTRS, nptrs as u16 + 1);

        Ok(())
    }

    fn del_leaf(&mut self, parents: &mut Vec<u32>, leaf: u32)
            -> Result<(), RmdbError> {

        let mut parent = match parents.pop() {
            Some(parent) => parent,
            None => return Err(RmdbError::InvalidMetadata),
        };
        let page = page_get_payload!(self.rmdb, self.wlock.mmap, parent);
        let ptype = pagebuf_get_int!(u16, page, POS_PAGETYPE);
        let nptrs = pagebuf_get_int!(u16, page, NODE_NUMPTRS) as usize;
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
        for n in 0..nptrs {
            let idx = NODE_FIRSTPTR + n * PTRSZ;
            let node = pagebuf_get_int!(u32, page, idx);
            if node == leaf {
                loc = n;
                break;
            }
        }
        /* found insertion point, copy the rest one over */
        loc += 1;
        for n in loc..nptrs {
            let idx = NODE_FIRSTPTR + n * PTRSZ;
            let node = pagebuf_get_int!(u32, page, idx);
            pagebuf_set_int!(u32, page, idx - PTRSZ, node);
        }
        /* update size */
        pagebuf_set_int!(u16, page, NODE_NUMPTRS, (nptrs - 1) as u16);
        self.delete_page(leaf);
        Ok(())
    }

    fn _scrub(&mut self) -> Result<(), RmdbError>{
        self.status = RmdbTxnState::Scrubbed;
        /* restore freepgaes from db */
        self.rmdb.get_free_pages_map(&mut *self.wlock)
    }

    pub fn scrub(&mut self) -> Result<(), RmdbError> {
        match self.status {
            RmdbTxnState::Open => self._scrub()?,
            _ => return Err(RmdbError::InvalidTransaction),
        };
        Ok(())
    }

    fn finalize_page(&mut self, page: u32)
            -> Result<(), RmdbError> {
        if page != 0 {
            let mut pagebuf = page_get_buf!(mut, self.rmdb, self.wlock.mmap,
                                            page, 0, self.rmdb.payload);
            let mut ptype = pagebuf_get_int!(u16, pagebuf, POS_PAGETYPE);
            if ptype & PAGE_DIRTY != 0 {
                ptype &= !PAGE_DIRTY;
                pagebuf_set_int!(u16, &mut pagebuf, POS_PAGETYPE, ptype);
            }
        }
        self.rmdb.integrity_protect(&mut self.wlock.mmap, page)?;
        self.rmdb.page_flush(&mut self.wlock.mmap, page)
    }

    pub fn commit(&mut self) -> Result<(), RmdbError> {
        /* free deleted pages */
        self.put_free_pages(&mut self.deletepages.to_vec())?;

        /* integrity check all dirty pages */
        let pages = self.dirtypages.to_vec();
        for dirty in pages {
            self.finalize_page(dirty)?;
        }

        /* wait until all readers are done */
        let mut rlock = self.rmdb.rlock.write().unwrap();

        /* set readers root page */
        rlock.rootpage = self.rootpage;

        let main = page_get_payload!(self.rmdb, self.wlock.mmap, 0);
        let fp = pagebuf_get_int!(u32, main, RMDB_P_FREEPAGES);
        let fs = pagebuf_get_int!(u32, main, RMDB_P_FREESIZE);

        /* write the freepages back to the file */
        let (fp, fs) = self.rmdb.set_free_pages_map(fp, fs, &mut *self.wlock)?;

        /* now update Main page */
        let main = page_get_payload!(mut, self.rmdb, self.wlock.mmap, 0);
        pagebuf_set_int!(u32, main, RMDB_P_ROOT, rlock.rootpage);
        pagebuf_set_int!(u32, main, RMDB_P_FREEPAGES, fp);
        pagebuf_set_int!(u32, main, RMDB_P_FREESIZE, fs);
        self.rmdb.integrity_protect(&mut self.wlock.mmap, 0)?;

        /* flush whole file if requested */
        if self.rmdb.flags.contains(RmdbFlags::TRANSACTION_FLUSH) {
            self.wlock.mmap.flush_async()?;
        } else if self.rmdb.flags.contains(RmdbFlags::TRANSACTION_SYNC_FLUSH) {
            self.wlock.mmap.flush()?;
        }

        /* check if we grew/shrunk the db in this transaction, and adust the
         * read map as well if that's the case */
        if rlock.mmap.len() != self.wlock.mmap.len() {
            rlock.mmap = unsafe {
                Mmap::map(&self.rmdb.file).map_err(RmdbError::Io)?
            };
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

#[cfg(test)]
mod tests {
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time;

use openssl::rand::rand_bytes;

use super::*;

fn db_filename(sname: &str) -> String {
    String::from(sname)
}

fn get_rand_val(fill: u8, maxsize: usize) -> Vec<u8> {
    let mut r = [0; 2];
    rand_bytes(&mut r).unwrap();
    let size = u16::from_le_bytes(r) as usize % maxsize;
    vec![fill; size]
}

fn test(name: String, opt: Option<RmdbOptions>) {

    let rmdb = Arc::new(Rmdb::create(PathBuf::from(name.clone()), opt).unwrap());
    let mut txn = rmdb.get_write_transaction().unwrap();

    let result = txn.add_entry(b"test", &get_rand_val(b'v', 65536));
    match result {
        Ok(()) => (),
        Err(error) => {
            println!("Add error: {}", error);
            return();
        },
    };
    let value = txn.get_entry(b"test").unwrap();
    println!("Value = {}", std::str::from_utf8(&value[0]).unwrap());
    txn.commit().unwrap();
    drop(txn);
    drop(rmdb);

    /* reopen */
    let rmdb = Arc::new(Rmdb::open(PathBuf::from(name)).unwrap());

    let mut handles = vec![];
    for t in 0..10 {
        let rmdb = Arc::clone(&rmdb);
        let handle = thread::spawn(move || {
            if t % 2 == 0 {
                let mut txn = rmdb.get_write_transaction().unwrap();
                let key = format!("test{}", t);
                let value = format!("value{}", t);
                txn.add_entry(key.as_bytes(), value.as_bytes()).unwrap();
                println!("Written '{}' from thread {}", key, t);
                txn.commit().unwrap();
            } else {
                thread::sleep(time::Duration::from_secs(1));
                let txn = rmdb.get_read_transaction().unwrap();
                let key = format!("test{}", 9 - t);
                match txn.get_entry(key.as_bytes()) {
                    Ok(value) => {
                        println!("Value '{}' from thread {}",
                            std::str::from_utf8(&value[0]).unwrap(), t);
                    },
                    Err(error) => {
                        println!("Error '{}' from thread {}", error, t);
                    }
                };
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let mut txn = rmdb.get_read_transaction().unwrap();
    for i in [0,2,4,6,8].iter() {
        let key = format!("test{}", i);
        let value = txn.get_entry(key.as_bytes()).unwrap();
        println!("Key/Value = {}/{}", key,
            std::str::from_utf8(&value[0]).unwrap());
    }

    /* test cursor setting */
    let key1 = "test4".as_bytes();
    let key2 = "test6".as_bytes();
    let mut cursor = txn.get_cursor().unwrap();
    cursor.set_to(key1).unwrap();
    let res = cursor.get_current().unwrap();
    if res.0 != key1 {
        println!("Setting cursor, expected {}, got {}",
                 std::str::from_utf8(key1).unwrap(),
                 std::str::from_utf8(res.0).unwrap());
    }
    let res = cursor.get_next().unwrap();
    if res.0 != key2 {
        println!("Setting cursor, expected {}, got {}",
                 std::str::from_utf8(key2).unwrap(),
                 std::str::from_utf8(res.0).unwrap());
    }
}

fn testload(name: String, opt: Option<RmdbOptions>,
            num: usize, vsize: usize, delete: bool) {

    let rmdb = Rmdb::create(PathBuf::from(name.clone()), opt).unwrap();
    let mut txn = rmdb.get_write_transaction().unwrap();

    println!("Adding {} test records", num);

    for i in 0..num {
        let key = format!("test{}", i);
        let value = get_rand_val(b'v', vsize);
        let result = txn.add_entry(key.as_bytes(), &value);
        match result {
            Ok(()) => (),
            Err(error) => {
                println!("Adding Key {} with value length {}, got {}",
                         key, value.len(), error);
            },
        };
    }
    txn.commit().unwrap();
    drop(txn);

    let mut txn = rmdb.get_read_transaction().unwrap();
    for i in 0..num {
        let key = format!("test{}", i);
        let result = txn.get_entry(key.as_bytes());
        match result {
            Ok(_val) => (),
            Err(error) => {
                println!("Reading Key {} got {}", key, error);
            },
        };
    }
    /* also check we find all elements via cursor */
    let mut keys = Vec::new();
    for i in 0..num {
        keys.push(format!("test{}", i));
    }
    let mut cursor = txn.get_cursor().unwrap();
    while let Ok(x) = cursor.get_next() {
        keys.retain(|k| k != std::str::from_utf8(x.0).unwrap());
    }
    if keys.len() != 0 {
        println!("Could not find entries: {:?}", keys);
    }
    drop(txn);

    if delete {
        let mut txn = rmdb.get_write_transaction().unwrap();
        for i in 0..num {
            let key = format!("test{}", i);
            let result = txn.del_entry(key.as_bytes());
            match result {
                Ok(_val) => (),
                Err(error) => {
                    println!("Deleting Key {} got {}", key, error);
                },
            };
        }
    }
}

#[test]
fn main_test() {

    let name = db_filename("test1db.rmdb");
    /* remove file if exist, ignore errors */
    let _ = fs::remove_file(name.as_str());

    /* use default flags */
    test(name, None);

    let name = db_filename("test2db.rmdb");
    /* remove file if exist, ignore errors */
    let _ = fs::remove_file(name.as_str());

    /* use no integrity and no flush, also small pagesize and db size */
    let opt =  Some(*RmdbOptions::new()
                                  .pagesize(1024)
                                  .initial_size(1024 * 100)
                                  .flags(RmdbFlags::empty()));
    test(name, opt);

    let name = db_filename("test3db.rmdb");
    /* remove file if exist, ignore errors */
    let _ = fs::remove_file(name.as_str());

    /* smallest page size then fill db with more leaves than a single
     * node can hold */
    let opt =  Some(*RmdbOptions::new()
                                  .pagesize(256)
                                  .initial_size(1024 * 4096));
    testload(name, opt, 64, 1024, false);

    let name = db_filename("test4db.rmdb");
    /* remove file if exist, ignore errors */
    let _ = fs::remove_file(name.as_str());

    /* More, entries, delete entries, enough entries to cause db growth */
    let opt =  Some(*RmdbOptions::new().pagesize(128).initial_size(128*64));
    testload(name, opt, 1024, 512, true);
}
} /* mod tests */
