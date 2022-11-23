# GPWG, a good password generator

Gpwg is a command line utility that generates good passwords.

```
$ gpwg
> NMc@8ciaPyoH8WbSkU

$ gpwg --strong
> FV8QSMBR-amZhCNb-KLjKgBa-b2328cM

$ gpwg --weak
> BL!74Z5vhU

$ gpwg --copy
> Generated password sent to the clipboard. Clear & exit with Ctrl-C.
  ^C
```

## Installation

### Pre-compiled binaries

You can find pre-compiled binaries for Windows, Mac and Linux [on the latest release page](https://github.com/fvdsn/gpwg/releases/tag/v1.0.0)

### Compile & install with rust/cargo

First you need to download & install [rust](https://www.rust-lang.org/tools/install)

Then use cargo to install gpwg.

```
$ cargo install gpwg
```

## What's good about gpwg's passwords ?

The generated password has the following properties:

- 100bit of entropy; strong enough for the vast majority of usecases.
- Respects the NIST, Microsoft, IBM, ANSSI, CNIL guidelines.
- Always has uppercase, lowercase, numbers and special characters.
- Looks like a good password.
- Accepted by every website password inputs.
- Does not contain similar looking letters or other confusing sequences of characters.
- Does not contain dictionary words and other common password patterns.
- Has maximum score on the zxcvbn password checker.
- Starts with an uppercase letter to avoid mistypes with smartphone inputs.
- The special characters, `!@` are easy to type with most on-screen keyboards,
  do not interfere with various text encoding formats, and are accepted by most
  password inputs that impose special character restrictions.

In case 100bit of entropy is not enough, consider using the `--strong` option for
a longer password with 160bit of entropy, fit for cryptographic needs.

If 160bit is not enough, you can specify an arbitrary length with `--length=N`

In case you find the password too long to type or remember, and cannot use a password
manager, consider using the `--weak` option. It produces a shorter password with 56bit
of entropy. While not generally secure, it is good enough if your password is used in a
system with bruteforce protection, or uses a second factor of authentication.

By default the password is printed on stdout. If you are in an environment where somebody
might look at your screen or watch your terminal logs, you can use the `--copy` option which
copies the password to the clipboard. The clipboard is then cleared when you exit `gpwg` with
`Ctrl-C`

## A word about password entropy

Entropy is a measure of how many random guesses on average are needed to find the
password, and is thus a measure of its security. However in practice password cracking softwares
do not guess passwords randomly, they try specific password patterns first.

Take for example these two passwords: `QSYUNP` and `ZXCVBN`. Those two passwords have the same entropy, but the second one
corresponds to a row of keys on the querty keyboard, a common password pattern. A password cracking software would try the
second one first, making it a lot less secure than its entropy would have predicted.

When generating passwords, there is a small probability to generate such a bad password. The chances are very small,
but the result is catastrophic. Such bad passwords are fortunately easy to detect, because the common patterns used by password
crackers are well known. `gpwg` uses the `zxcvbn` library to analyse the generated passwords and reject the ones that match
common patterns, so you only get truly secure passwords.

## A word about passphrases

Passphrases are passwords made of sentences or sequences of random words -- for example `correct horse battery staple` --
and you might wonder why `gpwg` does not uses this approach.

First those passwords are not really secure; four random words is about 45bit of entropy, which can be guessed in a few minutes
on modern hardware. `gpwg` passwords are 100bit which is considered to be the minimum to be cryptographically secure.

Another problem with passphrases is that they are often not accepted by the password 'quality' checks that require
the presence of numbers or special characters. `gpwg` aims to generate passwords that are always accepted.

And last, passphrases use a specific language such as english, and `gpwg` aims to generate universally usable passwords.
