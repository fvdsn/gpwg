# GPWG - A Good Password Generator

Gpwg is a command line utility that generates strong, secure passwords that are 
accepted by all password inputs. It can be installed using pre-compiled binaries
or with the Rust package manager, Cargo.

```
$ gpwg
> NMc@8ciaPyoH8WbSkU

$ gpwg --strong
> FV8QSMBR-amZhCNb-KLjKgBa-b2328cM

$ gpwg --entropy=256
> LKNTqNS3-4CBeAJy-9g2MxPv-WYMG9yP-t9wAZT8-X8amqaY-buE@uXR

$ gpwg --length=8
> A@q4PnLE

$ gpwg --copy
> Generated password sent to the clipboard. Clear & exit with Ctrl-C.
  ^C
```

## Installation

### Pre-compiled binaries

You can find pre-compiled binaries for Windows, Mac and Linux [on the latest release](https://github.com/fvdsn/gpwg/releases/tag/v1.1.0)

### Compiling with Rust/Cargo

First, [download and install rust](https://www.rust-lang.org/tools/install). Then, use Cargo to install gpwg.

```
$ cargo install gpwg
```

## What Makes GPWG Passwords Good ?

GPWG passwords have the following properties:

- Accepted by all password inputs
- 100bit of entropy by default (strong enough for most use cases)
- Compliant with NIST, Microsoft, IBM, ANSSI, CNIL guidelines
- Always include uppercase and lowercase letters, numbers and special characters
- No confusing sequences of characters
- No dictionary words or common password patterns
- Maximum score on the zxcvbn password checker
- Always start with an uppercase letter to prevent mistyping on smartphones
- Special characters `!@` are easy to type on most on-screen keyboards,
  do not interfere with text encoding, and are accepted by most
  password inputs with special character restrictions.

In case 100bit of entropy is not enough, the `--strong` option generates a longer
password with 160 bits of entropy suitable for cryptography. If 160 bits are still 
not enough, the `--entropy` option allows you to specify an arbitrary entropy target.

By default, the password is printed to standard output. If you are in an environment where someone
might be able to see your screen or terminal logs, the `--copy` option can be used to copy the password
to the clipboard. The clipboard is automatically cleared when you exit `gpwg` with `Ctrl-C`.
