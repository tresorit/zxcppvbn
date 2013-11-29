zxcppvbn
========

`zxcppvbn` is a C++11 password strength estimation library. This library is the C++11 implementation of the similarly
named `zxcvbn` library, written in CoffeeScript, and which you can find [here](https://github.com/lowe/zxcvbn).

`zxcvbn` attempts to give sound password advice through pattern matching and conservative entropy calculations.
It finds 10k common passwords, common American names and surnames, common English words, and common patterns like dates,
repeats (aaa), sequences (abcd), and QWERTY patterns.

This library follows the original CoffeeScript implementation as much as possible, with slight modifications because of
the C++ programming language specificities, and some improvements, as well.
