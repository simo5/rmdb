use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use rmdb::Rmdb;
use rmdb::RmdbFlags;

fn db_filename(sname: &str) -> String {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        return args[1].clone();
    }
    String::from(sname)
}

fn main() {

    let name = db_filename("test1db.rmdb");
    let flags = <RmdbFlags as Default>::default() | RmdbFlags::PAGE_INTEGRITY;
    let rmdb = Arc::new(Rmdb::open(PathBuf::from(name), flags, true).unwrap());
    let mut handles = vec![];

    for t in 0..10 {
        let rmdb = Arc::clone(&rmdb);
        let handle = thread::spawn(move || {
            //let mut page = rmdb.get_write_page(10+t).unwrap();
            //page.set_u64(pagesize -16, t).unwrap();
            //drop(page);
            //let page = rmdb.get_read_page(10+t).unwrap();
            //println!("Page {} value from Thread{}: {}",
            //         10+t, t, page.get_u64(pagesize - 16).unwrap());
            //drop(page);
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let mut txn = rmdb.get_write_transaction().unwrap();
    let result = txn.add_entry(b"test", b"value");
    match result {
        Ok(()) => (),
        Err(error) => {
            println!("Add error: {}", error);
            return();
        },
    };
    let value = txn.get_entry(b"test");
    let value = match value {
        Ok(value) => value,
        Err(error) => {
            println!("Get error: {}", error);
            return();
        },
    };
    println!("Value = {}", std::str::from_utf8(&value[0]).unwrap());
    txn.commit(&*rmdb).unwrap();
    drop(txn);
}
