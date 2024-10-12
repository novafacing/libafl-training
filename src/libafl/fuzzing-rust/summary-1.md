# Summary

You can view the completed source for the fuzzer
[here](https://github.com/novafacing/practical-fuzzing/blob/main/src/libafl/fuzzing-rust/).

In this exercise, we learned:

- About creating rust library and binary crates
- How to add dependencies
- What LibAFL_Targets does
- How to choose and create a good fuzz target
- About Rust memory and ownership semantics
- How to unsafely allocate memory
- How to implement a simple decoder
- How to unit test a rust function
- How to instrument a library with SanitizerCoverage
- How to link a fuzzer with a static library
- How to set a new global allocator
- How to create a fuzzer using LibAFL including all its components
  - Observers
  - Feedbacks
  - Fuzzers
  - Monitors
  - Mutators
  - Schedulers
  - Stages
  - Executors
  - ...
- How to parse command line arguments
- How to find crashing inputs using a fuzzer and fix the bugs that cause them




