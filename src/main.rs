use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use rmdb::Rmdb;
use rmdb::RmdbFlags;
use rmdb::RmdbPage;
use rmdb::RmdbWPage;

fn db_filename(sname: &str) -> String {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        return args[1].clone();
    }
    String::from(sname)
}

fn dev_tests_1(rmdb: &mut rmdb::Rmdb) {
    rmdb.resize(10).expect("Resize failed");

    let mut db = rmdb.db.write().unwrap();
    let page_1 = RmdbPage::new(&*db, rmdb.flags(), 1).unwrap();
    println!("Page 1 value: {}", page_1.get_page_num().unwrap());
    drop(page_1);

    let page_2 = RmdbPage::new(&db, rmdb.flags(), 2).unwrap();
    println!("Page 2 value: {}", page_2.get_page_num().unwrap());
    drop(page_2);

    let mut page_3 = RmdbWPage::new(&mut *db, rmdb.flags(), 3).unwrap();
    page_3.set_page_num(3).unwrap();
    drop(page_3);

    let page_3_r = RmdbPage::new(&db, rmdb.flags(), 3).unwrap();
    println!("Page 3 value: {}", page_3_r.get_page_num().unwrap());

    let page_blows = RmdbPage::new(&db, rmdb.flags(), 2000);
    match page_blows {
        Ok(_page) => panic!("Got page but should have failed!"),
        Err(_err) => return
    }
}

fn main() {
    let name = db_filename("test1db.rmdb");
    let flags = <RmdbFlags as Default>::default() | RmdbFlags::PAGE_INTEGRITY;
    let mut rmdb = Rmdb::open(PathBuf::from(name), flags, true).unwrap();

    dev_tests_1(&mut rmdb);

    drop(rmdb);

    let name = db_filename("test1db.rmdb");
    let rmdb = Arc::new(Rmdb::open(PathBuf::from(name), flags, true).unwrap());
    let mut handles = vec![];

    for t in 0..10 {
        let rmdb = Arc::clone(&rmdb);
        let handle = thread::spawn(move || {
            let db = rmdb.db.read().unwrap();
            let page = RmdbPage::new(&*db, rmdb.flags(), 1).unwrap();
            println!("Page 1 value from {:?}({}): {}",
                     thread::current().name(), t, page.get_page_num().unwrap());
            drop(page);
            drop(db);
            let mut db = rmdb.db.write().unwrap();
            let mut page = RmdbWPage::new(&mut *db, rmdb.flags(), 1).unwrap();
            page.set_page_num(t).unwrap();
            drop(page);
            let page = RmdbPage::new(&*db, rmdb.flags(), 1).unwrap();
            println!("Page 1 value from {:?}({})[after]: {}",
                     thread::current().name(), t, page.get_page_num().unwrap());
            drop(page);
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let mut db = rmdb.db.write().unwrap();
    let page = RmdbPage::new(&*db, rmdb.flags(), 1).unwrap();
    println!("Page 1 value: {}", page.get_page_num().unwrap());
    drop(page);
    /* Reset to leave db consistent */
    let mut page = RmdbWPage::new(&mut *db, rmdb.flags(), 1).unwrap();
    page.set_page_num(1).unwrap();
    drop(page);
}
