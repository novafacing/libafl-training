# Implement the Fuzz Target

Now that we know what a *slice* is, we can implement our function. Remember our
function skeleton from our `lib.rs`:

```rust
#[no_mangle]
pub fn decode(mut encoded_input: &[u8]) -> Vec<u8> {
    Vec::new()
}
```

We'll implement a simple decoder for URL-encoded text. URL-encoding looks something like
`This%20string%20is%20URL%20encoded`. We want to have a bug in this program that causes
it to crash, so we will use a bit of *unsafe* Rust. You can read all about unsafe Rust
[here](https://doc.rust-lang.org/book/ch19-01-unsafe-rust.html) but basically the
`unsafe` keyword lets you:

- Dereference a raw pointer
- Call an unsafe function or method
- Access or modify a mutable static variable
- Implement an unsafe trait
- Access fields of unions

We'll use it to program like we're writing C/C++. You don't need to do this (there's a
perfectly good [safe
implementation](https://docs.rs/urlencoding/latest/src/urlencoding/dec.rs.html) of URL
decoding), we're just doing it for an example of a fuzz target that will actually crash.
