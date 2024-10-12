# Stages

The [`Stage`](https://docs.rs/libafl/latest/libafl/stages/trait.Stage.html)s of a
fuzzing campaign are the set of steps the fuzzer moves through for each cycle of the
fuzzer. These stages can include mutation (and almost always do), but can also include
various other steps like symbolic execution, corpus minimization, synchronization
between fuzzers, and more.

For the final time, we will opt for the simplest option and use only a single mutational
stage with our just-created havoc mutator.

Add the declaration:

```rust
use libafl::stages::StdMutationalStage;
```

And add the mutational stage. Notice that once again, we have a `tuple_list` of one
item. This is where we would put more stages, if we had them.

```rust
let mut stages = tuple_list!(StdMutationalStage::new(mutator));
```
