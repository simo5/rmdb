use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use rmdb::Rmdb;

fn db_filename() -> String {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        return args[1].clone();
    }
    String::from("testdb.rmdb")
}

fn main() {
    let name = db_filename();
    //println!("Opening {}", name);
    let rmdb = Rmdb::open(PathBuf::from(name), true);
    let rmdb = Arc::new(match rmdb {
        Ok(db) => db,
        Err(error) => panic!("DB error: {:?}", error),
    });
    rmdb.resize(123456).expect("Resize failed");
    drop(rmdb);
}
