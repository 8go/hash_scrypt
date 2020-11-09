# hash_scrypt
Small CLI app in Python to hash passphrase for key derivation based 
on scrypt, for key derivation, for password stretching, and for hashing. 

# Dependencies

See `requirements.txt` file: [requirements.txt](requirements.txt)

# Comments

If you like it give it a :star: on Github. PRs are welcome.

# 2 Variants: passlib-based and cryptography-based

The same logic has been programmed in two ways, in two variants:
- variant A: based on [passlib](https://passlib.readthedocs.io/)
- variant B: based on [pyca/cryptography](https://github.com/pyca/cryptography)

Both produce identical results.

# Comparison of 2 Variants

In comparison with the passlib-based variant (hash_scrypt_passlib.py),
the pyca/cryptography-based variant (hash_scrypt_pycacrypto.py) has 3 advantages:

- pyca/cryptography (hash_scrypt_pycacrypto.py): allows chosing key size.
- pyca/cryptography (hash_scrypt_pycacrypto.py): has no RAM limit, allows higher N.
- pyca/cryptography (hash_scrypt_pycacrypto.py): is about 18% faster on std. CPU.

One disputable disadvantage of pyca/cryptography might be:
- passlib (hash_scrypt_passlib.py) is simpler and results in fewer lines of code.

# hash_scrypt_passlib.py

## hash_scrypt_passlib.py: Reading material, References:

- https://passlib.readthedocs.io/en/stable/lib/passlib.hash.scrypt.html?highlight=scrypt
- https://passlib.readthedocs.io/en/stable/narr/quickstart.html
- https://passlib.readthedocs.io/en/stable/narr/hash-tutorial.html
- https://foss.heptapod.net/python-libs/passlib # rsources, repo
- https://tools.ietf.org/html/rfc7914.html  # standard
- https://stackoverflow.com/questions/11126315/what-are-optimal-scrypt-work-factors#12581268

## hash_scrypt_passlib.py: Limitations:

- ValueError: maxmem must be positive and smaller than 2147483647
- So, it can use a max of 2GB of RAM.
- That limits N to 20 for other default settings.
- Derived key size/length cannot be set, it is fixed at 32 bytes.

## hash_scrypt_passlib.py: Performance:

Your performance may vary depending on CPU, GPU, RAM, etc.
Just to give a rough idea. On an average 2020 PC with 12GB of RAM and
a Linux operating system:
```
$ time hash_scrypt_passlib.py  'my passphrase' --salt-utf8 'salty' -ln 20 -r 8 -p 1 -c 2> /dev/null
$scrypt$ln=20,r=8,p=1$c2FsdHk$dErZxELnD6YP5sFs182F9jUfjGIxuNvSlVdjr8L4axQ
real	0m5,378s
user	0m4,916s
sys	0m0,439s
```

## hash_scrypt_passlib.py: How to run it, examples:

```
# get help
hash_scrypt_passlib.py  -h

# derive one key, input from command line
hash_scrypt_passlib.py  'my passphrase'

# derive one key, input from file
hash_scrypt_passlib.py  -f  my_passphrase_file.txt

# piping passphrase into program, input from stdio/pipe
echo 'my passphrase' | hash_scrypt_passlib.py -c -f - 2> /dev/null
$scrypt$ln=16,r=8,p=1$3LyuY7klz5Oej9aAfRW+8A$ZXvOGuIDTp4J3j68kBVD6qsl3JDVVQt4Fd
q124f/VZ0

# terse, just 1 line output
hash_scrypt_passlib.py  'my passphrase' -c 2> /dev/null
$scrypt$ln=16,r=8,p=1$f1TXjocFIl8FfQwqj4LT9A$RQJZboPWKenfrv44QhWONjTqTDDzF8xvR6
F1Gv4zx2g

# test the program, run standardized test cases
hash_scrypt_passlib.py  -t # show test cases and some comments
hash_scrypt_passlib.py  -t 2>&1 | grep 'test case'  # just show test results
INFO:root:run_test_case:: ✅ test case 1 passed. 😀
...

# use existing salt, available in UTF-8 (not base64)
hash_scrypt_passlib.py  'my passphrase' --salt-utf8 'battery horse staple'

# use existing salt, available in Base64 encoding
hash_scrypt_passlib.py  'my passphrase' --salt-base64 'YmF0dGVyeSBob3JzZSBzdGFw
bGU'

# to set the scrypt paramers N, R, and P use:
hash_scrypt_passlib.py  'my passphrase' -ln 20 -r 8 -p 1

# There are many more options, have a look at them:
hash_scrypt_passlib.py  --help
```

## hash_scrypt_passlib.py: Usage

```
usage: hash_scrypt_passlib.py [-h] [-d] [-c] [-v] [-t] [-f PASSPHRASE_FILE]
                              [-m [METADATA]] [-s SALT_UTF8] [-b SALT_BASE64]
                              [-u SALT_LENGTH] [-k KEY_LENGTH] [-ln LN]
                              [-r R] [-p P]
                              [passphrase [passphrase ...]]

positional arguments:
  passphrase            Zero or more passphrases to be stretched and hashed.
                        Zero is useful for --run-test-cases or --passphrase-
                        file.

optional arguments:
  -h, --help            show this help message and exit
  -d, --debug           Turn debug on
  -c, --terse           Produce only terse output, i.e. just one line
                        containing the derived key will be printed to stdout.
  -v, --verify          Turn verification on. Verification will take as many
                        resources and clock time as the hash itself.
  -t, --run-test-cases  Run standard hard-coded test cases to verify
                        correctness. Now hash will be produced for use. All
                        other arguments will beignored.
  -f PASSPHRASE_FILE, --passphrase-file PASSPHRASE_FILE
                        File containing a single passphrase. If specified,
                        the passphrase will be read from the specified file
                        instead of from the arguments. If specified passwords
                        from the command line arguments will be ignored.
                        Passphrase must be in the first line of the specified
                        UTF-8 file without any extra characters such as
                        comments. Newline will be removed from passphrase.
                        You can use the single letter "-" to specify stdin as
                        file. This way you can pipe a passphrase into the
                        program. E.g. "echo 'my passphrase' |
                        hash_scrypt_passlib.py -d -f -".
  -m [METADATA], --metadata [METADATA]
                        Filename for storing metadata. Optional argument. If
                        specified, this program will produce a few lines of
                        metadata (configuration parameters of the performed
                        hash(es)) and store them in a small metadata text
                        file. If -m is specified without filename but -f is
                        specified, then the metadata filename will be the -f
                        filename appended with ".meta". If neither -m
                        specifies a file nor -f is specified, then metadata
                        will be written to default metadata file
                        "hash_scrypt_passlib.meta".If -m is specified with a
                        filename then this will overwrite the default values
                        and the metadata will be writen to the file specified
                        with the -m.
  -s SALT_UTF8, --salt-utf8 SALT_UTF8
                        A salt string in UTF-8. (Not base64 encoded.)
  -b SALT_BASE64, --salt-base64 SALT_BASE64
                        A salt string that is base64 encoded.
  -u SALT_LENGTH, --salt-length SALT_LENGTH
                        Usually 16 or 32. 16 gives 16*8=128bits of salt
                        randomness. 32 gives 32*8=265bits of salt randomness.
                        Standards use 16. Default is 16. Do not use this
                        --salt-length parameter if you are specifying the
                        salt yourself with --salt-utf8 or --salt-base64.
  -k KEY_LENGTH, --key-length KEY_LENGTH
                        Usually 32. 32 gives 32*8=265bits of salt randomness.
                        Default is 32.
  -ln LN, --ln LN       Log N: Log2 of scrypt parameter N. Standards
                        recommend 14 for interactive use (t < 100ms). 20 for
                        file encryption (t < 5s). Default is 16.
  -r R, --r R           R: scrypt parameter R. Block Size parameter.
                        Standards recommend 8. Some use 16. Default is 8.
  -p P, --p P           P: scrypt parameter P. Parallelization parameter.
                        Common use is 1. Default is 1.
```

# hash_scrypt_pycacrypto.py

## hash_scrypt_pycacrypto.py: Reading material, References:
- https://cryptography.io/en/latest/index.html
- https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions.html#scrypt
- https://tools.ietf.org/html/rfc7914.html  # standard
- https://stackoverflow.com/questions/11126315/what-are-optimal-scrypt-work-factors#12581268

## hash_scrypt_pycacrypto.py: Limitations:

- RAM limitations are in the Exabytes range.
- Most PCs will run out of RAM way before set internal limit is reached.

## hash_scrypt_pycacrypto.py: Performance:

Your performance may vary depending on CPU, GPU, RAM, etc.
Just to give a rough idea. On an average 2020 PC with 12GB of RAM and
a Linux operating system:
```$ time hash_scrypt_pycacrypto.py  'my passphrase' --salt-utf8 'salty' -ln 20 -r  8 -p 1 -c 2> /dev/null
$scrypt$ln=20,r=8,p=1$c2FsdHk$dErZxELnD6YP5sFs182F9jUfjGIxuNvSlVdjr8L4axQ
real	0m4,589s
user	0m4,162s
sys	0m0,408s
```

## hash_scrypt_pycacrypto.py: How to run it, examples:

```
# get help
hash_scrypt_pycacrypto.py  -h

# derive one key, input from command line
hash_scrypt_pycacrypto.py  'my passphrase'

# derive one key, input from file
hash_scrypt_pycacrypto.py  -f  my_passphrase_file.txt

# piping passphrase into program, input from stdio/pipe
echo 'my passphrase' | hash_scrypt_pycacrypto.py -c -f - 2> /dev/null
$scrypt$ln=16,r=8,p=1$3LyuY7klz5Oej9aAfRW+8A$ZXvOGuIDTp4J3j68kBVD6qsl3JDVVQt4Fd
q124f/VZ0

# terse, just 1 line output
hash_scrypt_pycacrypto.py  'my passphrase' -c 2> /dev/null
$scrypt$ln=16,r=8,p=1$f1TXjocFIl8FfQwqj4LT9A$RQJZboPWKenfrv44QhWONjTqTDDzF8xvR6
F1Gv4zx2g

# test the program, run standardized test cases
hash_scrypt_pycacrypto.py  -t # show test cases and some comments
hash_scrypt_pycacrypto.py  -t 2>&1 | grep 'test case'  # just show test results
INFO:root:run_test_case:: ✅ test case 1 passed. 😀
...

# use existing salt, available in UTF-8 (not base64)
hash_scrypt_pycacrypto.py  'my passphrase' --salt-utf8 'battery horse staple'

# use existing salt, available in Base64 encoding
hash_scrypt_pycacrypto.py  'my passphrase' --salt-base64 'YmF0dGVyeSBob3JzZSBzd
GFwbGU'

# to set the scrypt paramers N, R, and P use:
hash_scrypt_pycacrypto.py  'my passphrase' -ln 20 -r 8 -p 1

# There are many more options, have a look at them:
hash_scrypt_pycacrypto.py  --help
```

## hash_scrypt_pycacrypto.py: Usage hash_scrypt_pycacrypto.py

```
usage: hash_scrypt_pycacrypto.py [-h] [-d] [-c] [-v] [-t]
                                 [-f PASSPHRASE_FILE] [-m [METADATA]]
                                 [-s SALT_UTF8] [-b SALT_BASE64]
                                 [-u SALT_LENGTH] [-k KEY_LENGTH] [-ln LN]
                                 [-r R] [-p P]
                                 [passphrase [passphrase ...]]

positional arguments:
  passphrase            Zero or more passphrases to be stretched and hashed.
                        Zero is useful for --run-test-cases or --passphrase-
                        file.

optional arguments:
  -h, --help            show this help message and exit
  -d, --debug           Turn debug on
  -c, --terse           Produce only terse output, i.e. just one line
                        containing the derived key will be printed to stdout.
  -v, --verify          Turn verification on. Verification will take as many
                        resources and clock time as the hash itself.
  -t, --run-test-cases  Run standard hard-coded test cases to verify
                        correctness. Now hash will be produced for use. All
                        other arguments will beignored.
  -f PASSPHRASE_FILE, --passphrase-file PASSPHRASE_FILE
                        File containing a single passphrase. If specified,
                        the passphrase will be read from the specified file
                        instead of from the arguments. If specified passwords
                        from the command line arguments will be ignored.
                        Passphrase must be in the first line of the specified
                        UTF-8 file without any extra characters such as
                        comments. Newline will be removed from passphrase.
                        You can use the single letter "-" to specify stdin as
                        file. This way you can pipe a passphrase into the
                        program. E.g. "echo 'my passphrase' |
                        hash_scrypt_pycacrypto.py -d -f -".
  -m [METADATA], --metadata [METADATA]
                        Filename for storing metadata. Optional argument. If
                        specified, this program will produce a few lines of
                        metadata (configuration parameters of the performed
                        hash(es)) and store them in a small metadata text
                        file. If -m is specified without filename but -f is
                        specified, then the metadata filename will be the -f
                        filename appended with ".meta". If neither -m
                        specifies a file nor -f is specified, then metadata
                        will be written to default metadata file
                        "hash_scrypt_pycacrypto.meta".If -m is specified with
                        a filename then this will overwrite the default
                        values and the metadata will be writen to the file
                        specified with the -m.
  -s SALT_UTF8, --salt-utf8 SALT_UTF8
                        A salt string in UTF-8. (Not base64 encoded.)
  -b SALT_BASE64, --salt-base64 SALT_BASE64
                        A salt string that is base64 encoded.
  -u SALT_LENGTH, --salt-length SALT_LENGTH
                        Usually 16 or 32. 16 gives 16*8=128bits of salt
                        randomness. 32 gives 32*8=265bits of salt randomness.
                        Standards use 16. Default is 16. Do not use this
                        --salt-length parameter if you are specifying the
                        salt yourself with --salt-utf8 or --salt-base64.
  -k KEY_LENGTH, --key-length KEY_LENGTH
                        Usually 32. 32 gives 32*8=265bits of salt randomness.
                        Default is 32.
  -ln LN, --ln LN       Log N: Log2 of scrypt parameter N. Standards
                        recommend 14 for interactive use (t < 100ms). 20 for
                        file encryption (t < 5s). Default is 16.
  -r R, --r R           R: scrypt parameter R. Block Size parameter.
                        Standards recommend 8. Some use 16. Default is 8.
  -p P, --p P           P: scrypt parameter P. Parallelization parameter.
                        Common use is 1. Default is 1.
```

# Source code format

- The import statments are sorted with: isort
- linted with: pylama with pydocstyle-pep8, pydocstyle-257, pyflakes, McCabe
- line length: 79
- beautified with: black (line length 79)
- pydocstyle: convention=numpy
- e.g. set `.pydocstyle` to
    ```
    [pydocstyle]
    inherit = false
    match = .*\.py  # noqa
    convention=numpy
    ```
   
