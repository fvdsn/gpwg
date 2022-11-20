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
- Always has uppercase, lowercase, numbers and special characters.
- Does not contain similar looking letters.
- Does not contain dictionary words and other common passwords patterns.
- Starts with an uppercase letter to avoid mistypes with smartphone inputs.
- The special characters, `!@` are easy to type with most on screen keyboards,
  do not interfere with various text encoding formats, and are accepted by most
  password inputs that impose special character restrictions.

In case 100bit of entropy is not enough, consider using the `--strong` option for
a longer password with 160bit of entropy, fit for cryptographic needs.

In case you find the password too long to type or remember, and cannot use a password
manager, consider using the `--weak` option. It produces a shorter password with 56bit
of entropy, Which is good enough if your password is used in a system with bruteforce
protection, or uses a second factor of authentication.
