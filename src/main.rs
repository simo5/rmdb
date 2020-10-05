use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time;

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
    let mut txn = rmdb.get_write_transaction().unwrap();

    let result = txn.add_entry(b"test", b"value");
    match result {
        Ok(()) => (),
        Err(error) => {
            println!("Add error: {}", error);
            return();
        },
    };
    let value = txn.get_entry(b"test").unwrap();
    println!("Value = {}", std::str::from_utf8(&value[0]).unwrap());
    txn.commit(&*rmdb).unwrap();
    drop(txn);

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
                txn.commit(&*rmdb).unwrap();
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

    let txn = rmdb.get_read_transaction().unwrap();
    for i in [0,2,4,6,8].iter() {
        let key = format!("test{}", i);
        let value = txn.get_entry(key.as_bytes()).unwrap();
        println!("Key/Value = {}/{}", key,
            std::str::from_utf8(&value[0]).unwrap());
    }
}
