pub async fn twice<F: AsyncFn(u32) -> u32>(f: F) -> u32 {
    f(1).await + f(2).await
}

pub async fn run() -> u32 {
    let step = 3;
    twice(async |x| x + step).await
}
