# Add Our Observers and Feedbacks

<!-- TODO: Link to countersmapsobserver once it's on docs.rs --> We will use a
[`CountersMapsObserver`]() wrapped by a
[`HitcountsIterableMapObserver`](https://docs.rs/libafl/latest/libafl/observers/map/struct.HitcountsIterableMapObserver.html)
to observe the state of our 8-bit instrumentation counters. The
[`CountersMapsObserver`]() observes the state of the counters directly, and resets the
state of the counters each iteration. The
[`HitcountsIterableMapObserver`](https://docs.rs/libafl/latest/libafl/observers/map/struct.HitcountsIterableMapObserver.html) will wrap it and allow us to use it with the
AFL-style feedback.

We'll also us the aforementioned
[`AflMapFeedback`](https://docs.rs/libafl/latest/libafl/feedbacks/map/type.AflMapFeedback.html)
to determine whether inputs are interesting based on the observed hit counter states.

Finally, we'll use a special feedback, the
[`CrashFeedback`](https://docs.rs/libafl/latest/libafl/feedbacks/struct.CrashFeedback.html)
which returns interesting if the harness crashed. We won't use this feedback to inform
our corpus, we'll use it as an *Objective* which means if this feedback returns
interesting, we will save the input that caused it.

First, we'll add a few `use` declarations for the types we will be using. Add these
at the top of your file.

```rust
use libafl::prelude::{AflMapFeedback, CrashFeedback, HitcountsIterableMapObserver};

```

Now we'll add our observers and feedbacks to our `main` function:


```rust
fn main() {
    let args = Args::parse();

    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();
        println!("Fuzzing with {:?} ({})", buf, buf.len());
        unsafe { decode(buf) };
        ExitKind::Ok
    }

    let counters_observer =
        HitcountsIterableMapObserver::new(unsafe { counters_maps_observer("counters-maps") });
    let mut counters_feedback = AflMapFeedback::new(&counters_observer);

    let mut objective = CrashFeedback::new();
}
```

Notice that we print out our buffer and its length, just so we can see what is happening
when we run it later.
