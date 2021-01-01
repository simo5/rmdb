use std::fs;
use std::path::PathBuf;
use std::time::SystemTime;

use num_format::{SystemLocale, ToFormattedString};

use rand::thread_rng;
use rand::seq::SliceRandom;

use rmdb::Rmdb;
use rmdb::RmdbFlags;
use rmdb::RmdbOptions;

fn prepdata(keynum: usize, valsize: usize) -> (Vec<String>, Vec<u8>) {

    let mut keys = Vec::with_capacity(keynum);
    for i in 0..keys.capacity() {
        keys.push(format!("testKeyName{:09}", i));
    }
    let mut val = Vec::with_capacity(valsize);
    for _ in 0..val.capacity() {
        val.push("v".as_bytes()[0]);
    }
    (keys, val)
}

fn opendb(keynum: usize, pagesize: usize) -> Rmdb {
    let name = String::from("bench2.rmdb");
    /* remove file if exist, ignore errors */
    let _ = fs::remove_file(name.as_str());
    let opt =  Some(*RmdbOptions::new()
                                  .pagesize(pagesize)
                                  .initial_size(keynum * pagesize)
                                  .flags(RmdbFlags::empty()));
    Rmdb::create(PathBuf::from(name.clone()), opt).unwrap()
}

fn iteradd(rmdb: &Rmdb, keys: &Vec<String>, value: &Vec<u8>) -> f64 {
    let start = SystemTime::now();

    let mut txn = rmdb.get_write_transaction().unwrap();
    for i in 0..keys.len() {
        txn.add_entry(keys[i].as_bytes(), &value).unwrap();
    }
    txn.commit().unwrap();

    start.elapsed().unwrap().as_secs_f64()
}

fn summary(entries: f64, iters: f64, sum: f64, vsize: f64, dbsize: u64) {
    let locale = SystemLocale::default().unwrap();

    let iter = sum / iters;
    let item = (iter / entries * 1000000000f64) as u64;
    let items = entries / iter;
    println!("    Perf: {} seconds/iter, {} ns/entry, {:.2} entries/sec",
             iter, item.to_formatted_string(&locale), items);
    let item = dbsize / entries as u64;
    println!("    DB size: {} bytes ({} bytes/item, overhead {:.2}%)",
             dbsize.to_formatted_string(&locale),
             item.to_formatted_string(&locale),
             item as f64/ vsize * 100f64);
}

fn bench_add_seq() {

    println!("Sequential Adds");

    for b in &[(128, 128),
               (128, 1024),
               (128, 4096),
               (1024, 1024),
               (1024, 4096)] {

        let iterations = 5;
        let entries = 50000;
        println!("  test: {} entries, value size: {}, page size: {} ({} times)",
                 entries, b.0, b.1, iterations);

        let mut sum = 0f64;
        let mut size = 0u64;

        let (keys, value) = prepdata(entries, b.0);

        for _ in 0..iterations {
            let rmdb = opendb(entries, b.1);

            let elapsed = iteradd(&rmdb, &keys, &value);

            sum = sum + elapsed;
            size = rmdb.size().unwrap();
        }

        summary(entries as f64, iterations as f64, sum, b.0 as f64, size);
    }
}

fn bench_add_rnd() {

    println!("Randomized Adds");

    for b in &[(128, 128),
               (128, 1024),
               (128, 4096),
               (1024, 1024),
               (1024, 4096)] {

        let iterations = 5;
        let entries = 50000;
        println!("test: {} entries, value size: {}, page size: {} ({} times)",
                 entries, b.0, b.1, iterations);

        let mut sum = 0f64;
        let mut size = 0u64;

        let (mut keys, value) = prepdata(entries, b.0);
        keys.shuffle(&mut thread_rng());

        for _ in 0..iterations {
            let rmdb = opendb(entries, b.1);

            let elapsed = iteradd(&rmdb, &keys, &value);

            sum = sum + elapsed;
            size = rmdb.size().unwrap();
        }

        summary(entries as f64, iterations as f64, sum, b.0 as f64, size);
    }
}

fn main() {
    bench_add_seq();
    bench_add_rnd();
}
