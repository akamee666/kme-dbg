fn main() {
    println!("Hello world from debugee main!");

    do_loop();
    let differnt = something_really_different();
    println!("{differnt}");
}

#[no_mangle]
pub fn do_loop() {
    println!("We entered the debugee do_loop function");

    for i in 0..5 {
        println!("i: {i}");
    }
}

fn something_really_different() -> u32 {
    let x = 5;

    println!("I am something really different so you may find me, say hello to x: {x}");
    return 123;
}
