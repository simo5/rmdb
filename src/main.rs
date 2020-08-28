use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use rmdb::Rmdb;
use rmdb::RmdbPage;

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
    let rmdb = Arc::new(Rmdb::open(PathBuf::from(name), true).unwrap());

    rmdb.resize(123456).expect("Resize failed");

    let page_1 = RmdbPage::new(&rmdb, 1).unwrap();
    println!("Page 1 value: {}", page_1.get_page_num());
    drop(page_1);

    let page_2 = RmdbPage::new(&rmdb, 2).unwrap();
    println!("Page 2 value: {}", page_2.get_page_num());
    drop(page_2);

    drop(rmdb);
}
