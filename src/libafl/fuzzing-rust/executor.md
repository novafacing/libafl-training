# Executor

The final piece of the test case execution puzzle is the [`Executor`](https://docs.rs/libafl/latest/libafl/executors/trait.Executor.html). Executors provide different ways to actually run the harness, whether
by forking then executing the harness, running it by directly calling the function,
executing a command on the system, and more. We will use the simplest one, the
[`InProcessExecutor`](https://docs.rs/libafl/latest/libafl/executors/inprocess/type.InProcessExecutor.html)
which will just call our harness over and over with new testcases.

Add the `use` declaration for it, and the `tuple_list` macro which we use to create
a tuple of observers to pass in. In our case, we only have one, so we create a tuple
of one value.

```rust
use libafl::prelude::InProcessExecutor;
use libafl_bolts::tuples::tuple_list;
```

Then create the executor:


```rust
let mut executor = InProcessExecutor::new(
    &mut harness,
    tuple_list!(counters_observer),
    &mut fuzzer,
    &mut state,
    &mut mgr,
)
.expect("Failed to create the Executor");
```
