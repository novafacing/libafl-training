# Allocate Some Memory

We need to allocate some memory to store our decoded data. Here's where our bug will
live. We'll naively assume that because a `%` followed by two characters decodes to the
byte with the hex value of those two characters, that we can count up the `%` signs,
multiply it by 2, then subtract that count from the length of the input bytes to get the
decoded size. This is a bug because `%%` is a special case: it simply escapes the `%` and
decodes to one `%`. Thus, `aa%` would calculate a buffer length of `1`, but we actually
need `2` bytes of space to store the decoded string.

```rust
use std::{
    alloc::{alloc, Layout},
    str::from_utf8_unchecked,
};

const DEFAULT_BUFFER_SIZE: usize = 128;

#[no_mangle]
pub fn decode(encoded_input: &[u8]) -> Vec<u8> {
    let decoded_len = DEFAULT_BUFFER_SIZE +
        encoded_input.len() - (encoded_input.iter().filter(|c| **c == b'%').count() * 2);
      
    if decoded_len <= 0 {
      return Vec::new();
    }

    let decoded_layout = Layout::array::<u8>(decoded_len).expect("Could not create layout");

    let decoded = unsafe { alloc(decoded_layout) };
    let mut decoded_ptr = decoded;

    Vec::new()
}
```

There are a few things going on here. We'll go step by step. First, we filter our
encoded input for '%' characters and count them, then subtract double that count from
the length of the encoded input to find the length of the decoded data. We'll also add a
constant `128` to our buffer size, to make our fuzzer at least do a little bit of work
to find this bug.Remember, this is an *intentional bug* because of various nuances in
the decoding process.

Next, we create a `Layout` (a description of an element size and length of an array of
`u8`s) of the length we just calculated. Notice the syntax of the `Layout` constructor
contains a *turbofish* (`::<>`), which is the syntax Rust uses for generic parameters.
Rust's generics are somewhat similar to C++, where if we wanted to construct a `Layout`
of an array of `u32`s instead, we would write `Layout::array::<u8>(decoded_len)`. We'll
dive further into generic parameters later in these exercises, and you can read about
them [here](https://doc.rust-lang.org/reference/items/generics.html).

The `.expect()` function makes sure that a `Result<T, E>` is `Ok(T)` or that an
`Option<T>` is `Some(T)`. If not, it will *panic* (or abort) with the message in the
call to `.expect()`.

Finally, we have an `unsafe` block with a call to `alloc()`. This performs the
allocation for the decoded data. This is unsafe, because an `alloc` call with a
zero-sized layout is undefined behavior. Thus, this allocation in our code is actually
*safe* because we already checked to make sure the size is positive and non-zero. This
is a good reminder that `unsafe` in Rust does not mean the code is actually unsafe to
run, it only means that it is *allowed* to violate Rust's safety guarantees. We save the
pointer to the beginning of our decoded data (`decoded`) and duplicate the pointer to
(`decoded_ptr`) that we will use to write into our allocated memory.
