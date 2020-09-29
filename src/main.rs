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

fn dev_tests_1(rmdb: &mut rmdb::Rmdb, pagesize: usize) {
    rmdb.resize(64).expect("Resize failed");

    let page_1 = rmdb.get_read_page(1).unwrap();
    println!("Page 1 value: {}", page_1.get_u64(pagesize - 16).unwrap());

    let page_2 = rmdb.get_read_page(2).unwrap();
    println!("Page 2 value: {}", page_2.get_u64(pagesize - 16).unwrap());

    drop(page_1);
    drop(page_2);

    let mut page_3 = rmdb.get_write_page(3).unwrap();
    page_3.set_u64(pagesize - 16, 3).unwrap();
    drop(page_3);

    let page_3 = rmdb.get_read_page(3).unwrap();
    println!("Page 3 value: {}", page_3.get_u64(pagesize - 16).unwrap());

    let page_blows = rmdb.get_read_page(2000);
    match page_blows {
        Ok(_page) => panic!("Got page but should have failed!"),
        Err(_err) => return
    }
}

fn main() {

    let name = db_filename("test1db.rmdb");
    let flags = <RmdbFlags as Default>::default() | RmdbFlags::PAGE_INTEGRITY;
    let mut rmdb = Rmdb::open(PathBuf::from(name), flags, true).unwrap();

    let pagesize = rmdb::page_size(rmdb.flags());

    dev_tests_1(&mut rmdb, pagesize);

    drop(rmdb);

    let name = db_filename("test1db.rmdb");
    let rmdb = Arc::new(Rmdb::open(PathBuf::from(name), flags, true).unwrap());
    let mut handles = vec![];

    for t in 0..10 {
        let rmdb = Arc::clone(&rmdb);
        let handle = thread::spawn(move || {
            let mut page = rmdb.get_write_page(10+t).unwrap();
            page.set_u64(pagesize -16, t).unwrap();
            drop(page);
            let page = rmdb.get_read_page(10+t).unwrap();
            println!("Page {} value from Thread{}: {}",
                     10+t, t, page.get_u64(pagesize - 16).unwrap());
            drop(page);
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
