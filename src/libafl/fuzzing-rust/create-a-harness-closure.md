# Create A Harness Closure

Before we can write our closure, we'll need to add a few `use` declarations from
`libafl`. Add these at the top of your `main.rs` file:

```rust
use libafl::prelude::{BytesInput, HasTargetBytes, ExitKind};
use libafl_bolts::AsSlice;
```

[`BytesInput`](https://docs.rs/libafl/latest/libafl/inputs/bytes/struct.BytesInput.html)
is a type that describes an input from the fuzzer that is just a sequence of bytes. It's
the standard input type, although it is possible to define custom input types as we'll
see in later exercises.
[`BytesInput`](https://docs.rs/libafl/latest/libafl/inputs/bytes/struct.BytesInput.html)
under the hood is just a
[`Vec<u8>`](https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html) with some sugar
around it to make it easy to use in the context of a possibly distributed and
multi-threaded fuzzer.

[`HasTargetBytes`](https://docs.rs/libafl/latest/libafl/inputs/trait.HasTargetBytes.html)
is a *trait* (which we will dive deep into later, but for now you can think of as
similar to an *interface* in Java or a *concept* in C++) that is implemented by
[`BytesInput`](https://docs.rs/libafl/latest/libafl/inputs/bytes/struct.BytesInput.html)
and returns the contents of the
[`BytesInput`](https://docs.rs/libafl/latest/libafl/inputs/bytes/struct.BytesInput.html)
as an [`OwnedSlice<u8>`](https://docs.rs/libafl/latest/libafl/bolts/ownedref/struct.OwnedSlice.html).

An
[`OwnedSlice<T>`](https://docs.rs/libafl/latest/libafl/bolts/ownedref/struct.OwnedSlice.html)
wraps a slice (in this case a `&[u8]`) so that it is *serializable* (we'll discuss
serializability later) and can be sent between threads, processes, and machines over the
network easily. LibAFL has several `Owned` types used for this purpose:
[`OwnedRef<T>`](https://docs.rs/libafl/latest/libafl/bolts/ownedref/enum.OwnedRef.html),
[`OwnedRefMut<T>`](https://docs.rs/libafl/latest/libafl/bolts/ownedref/enum.OwnedRefMut.html),
[`OwnedPtr<T>`](https://docs.rs/libafl/latest/libafl/bolts/ownedref/enum.OwnedPtr.html),
[`OwnedMutPtr<T>`](https://docs.rs/libafl/latest/libafl/bolts/ownedref/enum.OwnedMutPtr.html),
[`OwnedSlice<T>`](https://docs.rs/libafl/latest/libafl/bolts/ownedref/struct.OwnedSlice.html)
and
[`OwnedMutSlice<T>`](https://docs.rs/libafl/latest/libafl/bolts/ownedref/struct.OwnedMutSlice.html).
Each wraps the underlying type, whether it is a `&T/&mut T`, `*const T/*mut T`, or
`&[T]/&mut [T]`.

[`AsSlice`](https://docs.rs/libafl/latest/libafl/bolts/trait.AsSlice.html) is another
trait implemented by
[`OwnedSlice`](https://docs.rs/libafl/latest/libafl/bolts/ownedref/struct.OwnedSlice.html)
and allows the
[`OwnedSlice<u8>`](https://docs.rs/libafl/latest/libafl/bolts/ownedref/struct.OwnedSlice.html)
to be converted to `&[u8]`, which we'll then input to our `decode` function.

With all that knowledge, our harness closure is pretty simple. We take our
[`BytesInput`](https://docs.rs/libafl/latest/libafl/inputs/bytes/struct.BytesInput.html),
convert it to an
[`OwnedSlice<u8>`](https://docs.rs/libafl/latest/libafl/bolts/ownedref/struct.OwnedSlice.html),
convert that to a `&[u8]`, and call our target function.


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
}
```
