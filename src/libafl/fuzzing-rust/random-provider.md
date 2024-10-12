# Random Provider

Random providers provide random data, generally optimized for speed because fuzzing
does not require cryptographically secure randomness.

We will use the default [`StdRand`](https://docs.rs/libafl/latest/libafl/bolts/rands/type.StdRand.html):


Add the `use` declaration for it:

```rust
use libafl_bolts::{rands::StdRand, current_nanos};
```

And create the random source in your `main` function:

```rust
let rand = StdRand::with_seed(current_nanos());
```
