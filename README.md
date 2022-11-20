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

## Installation

First you need to download & install [rust](https://www.rust-lang.org/tools/install)

Then use cargo to install gpwg.

```
$ cargo install gpwg
```

## A word about passphrases

Passphrases are passwords made of sentences or sequences of random words -- for example `correct horse battery staple` --
and you might wonder why `gpwg` does not uses this approach.

First those passwords are not really secure; four random words is about 45bit of entropy, which can be guessed in a few minutes
on modern hardware. `gpwg` passwords are 100bit which is considered to be the minimum to be cryptographically secure.

Another problem with passphrases is that they are often not accepted by the password 'quality' checks that require
the presence of numbers or special characters. `gpwg` aims to generate passwords that are always be accepted.

And last, passphrases use a specific language such as english, and `gpwg` aims to generate passwords that are useful for everybody.
