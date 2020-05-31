use std::env;
use std::path::PathBuf;

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
    let x = Rmdb::open(&PathBuf::from(name), true);
    let _x = match x {
        Ok(db) => db.close(),
        Err(error) => panic!("DB error: {:?}", error),
    };
}
