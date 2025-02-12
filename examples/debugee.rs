fn main() {
    println!("Hello world from debugee main!");

    do_loop();
}

fn do_loop() {
    println!("We entered the debugee do_lopp function");

    for i in 0..5 {
        println!("i: {i}");
    }
}
