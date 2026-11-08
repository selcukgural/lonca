fn first() -> i32 {
    1
}

struct C;

impl C {
    fn a(&self) -> i32 {
        1
    }

    fn b(&self) -> i32 {
        2
    }
}

fn last() -> i32 {
    3
}
