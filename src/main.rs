use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time;

use openssl::rand::rand_bytes;

use rmdb::Rmdb;
use rmdb::RmdbFlags;
use rmdb::RmdbOptions;

fn db_filename(sname: &str) -> String {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        return args[1].clone();
    }
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
    txn.commit(&*rmdb).unwrap();
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

fn testload(name: String, opt: Option<RmdbOptions>,
            num: usize, vsize: usize) {

    let rmdb = Rmdb::create(PathBuf::from(name.clone()), opt).unwrap();
    let mut txn = rmdb.get_write_transaction().unwrap();

    println!("Adding {} test records", num);

    for i in 0..num {
        let key = format!("test{}", i);
        let value = get_rand_val(b'v', vsize);
        let result = txn.add_entry(key.as_bytes(), &value);
        match result {
            Ok(()) => {
                println!("Added Key {} with value length {}",
                         key, value.len());
            },
            Err(error) => {
                println!("Adding Key {} with value length {}, got {}",
                         key, value.len(), error);
            },
        };
    }
    txn.commit(&rmdb).unwrap();
    drop(txn);

    let txn = rmdb.get_read_transaction().unwrap();
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
}

fn main() {

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
    testload(name, opt, 64, 1024);
}
