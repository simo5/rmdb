use std::fs;
use std::path::PathBuf;

use rmdb::Rmdb;
use rmdb::RmdbOptions;

#[macro_use]
extern crate bencher;

use bencher::Bencher;

fn testprep() -> (Rmdb, Vec<String>) {

    let name = String::from("bench1.rmdb");
    let mut vec = Vec::with_capacity(512);
    for i in 0..vec.capacity() {
        let key = format!("test{}", i);
        vec.push(key);
    }
    /* remove file if exist, ignore errors */
    let _ = fs::remove_file(name.as_str());
    let opt =  Some(*RmdbOptions::new()
                                  .pagesize(512)
                                  .initial_size(512 * 64));
    let rmdb = Rmdb::create(PathBuf::from(name.clone()), opt).unwrap();
    (rmdb, vec)
}

fn testadds(rmdb: &Rmdb, keys: &Vec<String>, commit: bool) {
    let value = vec![b'v'; 1024];
    let mut txn = rmdb.get_write_transaction().unwrap();

    for i in 0..keys.len() {
        let result = txn.add_entry(keys[i].as_bytes(), &value);
        match result {
            Ok(()) => (),
            Err(error) => {
                println!("Adding Key {}, got {}", keys[i], error);
            },
        };
    }
    if commit {
        txn.commit().unwrap();
    } else {
        txn.scrub().unwrap();
    }
    drop(txn);
}

fn testreads(rmdb: &Rmdb, keys: &Vec<String>) {
    let txn = rmdb.get_read_transaction().unwrap();

    for i in 0..keys.len() {
        let result = txn.get_entry(keys[i].as_bytes());
        match result {
            Ok(_val) => (),
            Err(error) => {
                println!("Reading Key {} got {}", keys[i], error);
            },
        };
    }
    drop(txn);
}

fn testdels(rmdb: &Rmdb, keys: &Vec<String>) {
    let mut txn = rmdb.get_write_transaction().unwrap();

    for i in 0..keys.len() {
        let result = txn.del_entry(keys[i].as_bytes());
        match result {
            Ok(()) => (),
            Err(error) => {
                println!("Deleting Key {}, got {}", keys[i], error);
            },
        };
    }
    txn.scrub().unwrap();
    drop(txn);
}

fn benchadds(bench: &mut Bencher) {
    let (rmdb, keys) = testprep();
    bench.iter(|| {
        testadds(&rmdb, &keys, false);
    });
}

fn benchreads(bench: &mut Bencher) {
    let (rmdb, keys) = testprep();
    testadds(&rmdb, &keys, true);

    bench.iter(|| {
        testreads(&rmdb, &keys);
    });
}

fn benchdels(bench: &mut Bencher) {
    let (rmdb, keys) = testprep();
    testadds(&rmdb, &keys, true);

    bench.iter(|| {
        testdels(&rmdb, &keys);
    });
}

benchmark_group!(benches, benchadds, benchreads, benchdels);
benchmark_main!(benches);
