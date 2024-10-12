# Ownership and Moves

To start understanding ownership and moves, we'll look at this function:

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
what a slice is, we first need to understand the basics of *references*, *ownership*,
and
*borrowing*.

In Rust, all values have an *owner*. To check out ownership in action, we can create a
`String`  variable using a *let* binding (the keyword for a statement to create a
variable in the current scope). Notice that we call `.to_string()` to convert the string
literal (a `&str`) into a `String`, although we'll avoid discussing that until a bit
later on.

```rust
fn main() {
    let _x: String = "Hello, World!".to_string();
}
```

<center>
<a href="https://play.rust-lang.org/?version=stable&mode=debug&edition=2021&code=fn+main%28%29+%7B%0A++++let+_x%3A+String+%3D+%22Hello%2C+World%21%22.to_string%28%29%3B%0A%7D">Playground</a>
</center>
<br>

We then *own* the value `_x`. In Rust, there can only be *one* owner of a variable at a
time, so if we call a function that takes a `String` as a parameter and prints it out.
Notice that `println!` is a variadic macro, and formats instances of `{}` in its first
argument with its remaining arguments, similar to `printf` in C, although using curly
braces instead of `%` symbols.

```rust
fn foo(bar: String) {
    println!("Got {}", bar);
}

fn main() {
    let x: String = "Hello, World!".to_string();
    foo(x);
}
```

<center>
<a href="https://play.rust-lang.org/?version=stable&mode=debug&edition=2021&code=fn+foo%28bar%3A+String%29+%7B%0A++++println%21%28%22Got+%7B%7D%22%2C+bar%29%3B%0A%7D%0A%0Afn+main%28%29+%7B%0A++++let+x%3A+String+%3D+%22Hello%2C+World%21%22.to_string%28%29%3B%0A++++foo%28x%29%3B%0A%7D">Playground</a>
</center>
<br>

We will *move*, or transfer ownership, of `x` to `foo` when we pass `x` to it as a
parameter. If we then want to use the value `x` later in the `main` function, for
example to print it out:

```rust
fn foo(bar: String) {
    println!("Got {}", bar);
}

fn main() {
    let x: String = "Hello, World!".to_string();
    foo(x);
    println!("X is {}", x);
}
```

<center>
<a href="https://play.rust-lang.org/?version=stable&mode=debug&edition=2021&code=fn+foo%28bar%3A+String%29+%7B%0A++++println%21%28%22Got+%7B%7D%22%2C+bar%29%3B%0A%7D%0A%0Afn+main%28%29+%7B%0A++++let+x%3A+String+%3D+%22Hello%2C+World%21%22.to_string%28%29%3B%0A++++foo%28x%29%3B%0A++++println%21%28%22X+is+%7B%7D%22%2C+x%29%3B%0A%7D">Playground</a>
</center>
<br>

You'll notice if you build or run this code in the Playground, we get a compile error:

```sh
   Compiling playground v0.0.1 (/playground)
error[E0382]: borrow of moved value: `x`
 --> src/main.rs:8:25
  |
6 |     let x: String = "Hello, World!".to_string();
  |         - move occurs because `x` has type `String`, which does not implement the `Copy` trait
7 |     foo(x);
  |         - value moved here
8 |     println!("X is {}", x);
  |                         ^ value borrowed here after move
  |
note: consider changing this parameter type in function `foo` to borrow instead if owning the value isn't necessary
 --> src/main.rs:1:13
  |
1 | fn foo(bar: String) {
  |    ---      ^^^^^^ this parameter takes ownership of the value
  |    |
  |    in this function
  = note: this error originates in the macro `$crate::format_args_nl` which comes from the expansion of the macro `println` (in Nightly builds, run with -Z macro-backtrace for more info)
help: consider cloning the value if the performance cost is acceptable
  |
7 |     foo(x.clone());
  |          ++++++++

For more information about this error, try `rustc --explain E0382`.
error: could not compile `playground` due to previous error

```

The error breaks down exactly what is happening here. `main` owned `x` when it was
declared, but it transferred ownership of `x` to `foo` when it passed `x` to `foo` as a
parameter. This means that when we try to use `x` in the `println!` statement we just
added to `main`, `main` actually no longer owns `x`, so it is an error to try and use
it!

This relationship is the core of how Rust ensures its safety guarantees, but may be
surprising to experienced C/C++ programmers because those languages have no enforced
concept of ownership of variables at all. There are a few ways to resolve this. The
first is to do what the compiler suggests, and `clone()` the string. This creates a
duplicate of the string in memory, and passes that duplicate to `foo`. This way, `main`
retains ownership of `x`, and `foo` gets its own duplicate as a parameter. These are
two *different* values, of course, but we are not modifying them so this is semantically
equivalent.

```rust
fn foo(bar: String) {
    println!("Got {}", bar);
}

fn main() {
    let x: String = "Hello, World!".to_string();
    foo(x.clone());
    println!("X is {}", x);
}
```

<center>
<a href="https://play.rust-lang.org/?version=stable&mode=debug&edition=2021&code=fn+foo%28bar%3A+String%29+%7B%0A++++println%21%28%22Got+%7B%7D%22%2C+bar%29%3B%0A%7D%0A%0Afn+main%28%29+%7B%0A++++let+x%3A+String+%3D+%22Hello%2C+World%21%22.to_string%28%29%3B%0A++++foo%28x.clone%28%29%29%3B%0A++++println%21%28%22X+is+%7B%7D%22%2C+x%29%3B%0A%7D">Playground</a>
</center>
<br>

If we run this, it'll succeed! However, we have made two tradeoffs. First, `clone()`
isn't free, either in terms of memory space or compute cycles. Second, if we added code
that modifies `x` in `foo`, `main` wouldn't print that modified value, it would print
the initial value. In this example, note that we have added the `mut` keyword to the
`bar` parameter in `foo`. This means this variable is *mutable*, so we can change it. If
we didn't add `mut`, it would be a compile error to modify the value of `bar` in this
function.

```rust
fn foo(mut bar: String) {
    bar += " I'm here!";
    println!("Got {}", bar);
}

fn main() {
    let x: String = "Hello, World!".to_string();
    foo(x.clone());
    println!("X is {}", x);
}
```

<center>
<a href="https://play.rust-lang.org/?version=stable&mode=debug&edition=2021&code=fn+foo%28mut+bar%3A+String%29+%7B%0A++++bar+%2B%3D+%22+I%27m+here%21%22%3B%0A++++println%21%28%22Got+%7B%7D%22%2C+bar%29%3B%0A%7D%0A%0Afn+main%28%29+%7B%0A++++let+x%3A+String+%3D+%22Hello%2C+World%21%22.to_string%28%29%3B%0A++++foo%28x.clone%28%29%29%3B%0A++++println%21%28%22X+is+%7B%7D%22%2C+x%29%3B%0A%7D">Playground</a>
</center>
<br>

If we run this program in the Playground now, we'll see:

```
Got Hello, World! I'm here!
X is Hello, World!
```

This is, semantically, what we expect. `foo` modified its duplicate of `x` and printed
out the duplicate, while `main` printed out the original value. But what if we wanted
`foo` to modify the original value, instead? In C/C++, we'd pass a *pointer* to `x` to
`foo` if we wanted to do that. Rust has a similar concept called a *reference*, and the
act of creating a reference is called *borrowing*.
