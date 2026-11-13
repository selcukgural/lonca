//! Work on several threads whose answer is the one a single thread gives:
//! the same question of every item, and the answers in the items' order.
//! Only for work that is done on a whole log at once (a daemon's start, an
//! audit); a request is answered on its own thread.

/// Fewer items than this are worked on by the thread that asked.
const ALONE: usize = 512;
/// The most threads one piece of work is spread over.
const MOST: usize = 8;

/// How many threads `items` items are worth on this machine.
pub(crate) fn worth(items: usize) -> usize {
    if items < ALONE {
        return 1;
    }
    std::thread::available_parallelism()
        .map_or(1, usize::from)
        .min(MOST)
}

/// `part` of every part of `items`, joined in the order of the items, the
/// parts running on up to `threads` threads. `part` answers one item with
/// one answer, so the result is `part(items)` whatever the number.
///
/// A thread that can not be started is no error: its part is worked here.
pub(crate) fn in_order<T: Sync, R: Send>(
    items: &[T],
    threads: usize,
    part: impl Fn(&[T]) -> Vec<R> + Sync,
) -> Vec<R> {
    let per = items.len().div_ceil(threads.max(1)).max(1);
    if per >= items.len() {
        return part(items);
    }
    let part = &part;
    std::thread::scope(|scope| {
        let runs: Vec<_> = items
            .chunks(per)
            .map(|items| {
                let run = std::thread::Builder::new().spawn_scoped(scope, move || part(items));
                (run, items)
            })
            .collect();
        let mut out = Vec::with_capacity(items.len());
        for (run, items) in runs {
            out.extend(match run {
                Ok(handle) => match handle.join() {
                    Ok(answers) => answers,
                    Err(panic) => std::panic::resume_unwind(panic),
                },
                Err(_) => part(items),
            });
        }
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_answers_are_in_the_order_of_the_items_on_any_number_of_threads() {
        for len in [0usize, 1, 2, 7, 100, 1000] {
            let items: Vec<usize> = (0..len).collect();
            let want: Vec<usize> = items.iter().map(|i| i * 3).collect();
            for threads in [0, 1, 2, 3, 8, 64, 2000] {
                let got = in_order(&items, threads, |part| part.iter().map(|i| i * 3).collect());
                assert_eq!(got, want, "{len} items, {threads} threads");
            }
        }
    }

    #[test]
    fn a_short_list_is_not_worth_a_thread() {
        assert_eq!(worth(0), 1);
        assert_eq!(worth(ALONE - 1), 1);
        assert!((1..=MOST).contains(&worth(ALONE)));
        assert!((1..=MOST).contains(&worth(usize::MAX)));
    }
}
