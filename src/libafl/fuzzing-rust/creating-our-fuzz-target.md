# Creating our Fuzz Target

For our fuzz target, we'll assume we're writing some sort of internet accessible service
and that the function we create takes some untrusted data. That means it would falls
into category 1 above. We will create our fuzz target in Rust, and we are going to put a
bug in it intentionally for the sake of demonstration.

In your `lib.rs` file, we'll first delete the all the contents `cargo` gave us, and 
create a new function. Our fuzz target will be a decoder for a simple encoding format.

Add this (functionally incomplete, but we'll fill in the body later) definition for our
`decode` function:

```rust
#[no_mangle]
pub fn decode(mut encoded_input: &[u8]) -> Vec<u8> {
    Vec::new()
}
```

This is a `pub` function (that is, it is exported) that takes a slice of encoded bytes
and returns a result (either a value or an error) where the value is a *vector* of
decoded bytes. Before we actually implement it, we need to learn a few concepts to
understand its parameter and return type.

This function takes a *slice* of unsigned 8-bit bytes. A slice is a *reference* to a
sequence of values of the same *type* (in this case `u8`) of some length. To understand
what a slice is, we need to understand the basics of *references*, *ownership*, and
*borrowing*.
