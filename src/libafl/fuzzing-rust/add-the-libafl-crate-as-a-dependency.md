# Add the LibAFL Crate as a Dependency

To add LibAFL and its utilities as a dependency to our crate, we can just run:

```sh
$ cargo add libafl@0.11.2 libafl_bolts@0.11.2
```

This may take a minute because it will update your `crates.io` index if this is the
first time you have added a `crates.io` dependency.

Check that the depedency is added by viewing the `Cargo.toml` for the crate. It should
have `libafl = "0.11.2"` and `libafl_bolts = "0.11.2"` under the `[dependencies]` section.

Let's check to make sure we can build and run with the dependency added.

```sh
$ cargo build
$ cargo run --bin first-fuzzer
```

You should have the same result as above, but you'll see `libafl` and its
sub-dependencies compile.
