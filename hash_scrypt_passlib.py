#!/usr/bin/python3
r"""Stretch passphrase and compute hash using scrypt.

Summary:
hash_scrypt_passlib.py
Uses scrypt algorithm for Key derivation function (KDF) and hashing.
Uses Python package passlib for implementation.

Dependencies:
pip3 install --user --upgrade passlib
pip3 install --user --upgrade cryptography

Reading material, References:
https://passlib.readthedocs.io/en/stable/lib/passlib.hash.scrypt.html?highlight=scrypt
https://passlib.readthedocs.io/en/stable/narr/quickstart.html
https://passlib.readthedocs.io/en/stable/narr/hash-tutorial.html
https://foss.heptapod.net/python-libs/passlib # rsources, repo
https://tools.ietf.org/html/rfc7914.html  # standard
https://stackoverflow.com/questions/11126315/what-are-optimal-scrypt-work-factors#12581268

Limitations:
ValueError: maxmem must be positive and smaller than 2147483647
So, it can use a max of 2GB of RAM.
That limits N to 20 for other default settings.
Derived key size/length cannot be set, it is fixed at 32 bytes.

Comparison:
In comparison with pyca/cryptography (hash_scrypt_pycacrypto.py)
passlib (hash_scrypt_passlib.py) has 3 disadvantages:
pyca/cryptography (hash_scrypt_pycacrypto.py): allows chosing key size.
pyca/cryptography (hash_scrypt_pycacrypto.py): has no RAM limit, allows higher N.
pyca/cryptography (hash_scrypt_pycacrypto.py): is about 18% faster on std. CPU.
One disputable disadvantage of pyca/cryptography might be:
passlib (hash_scrypt_passlib.py) is simpler and results in fewer lines of code.

Performance:
Your performance may vary depending on CPU, GPU, RAM, etc.
Just to give a rough idea. On an average 2020 PC with 12GB of RAM and
a Linux operating system:
$ time hash_scrypt_passlib.py  'my passphrase' --salt-utf8 'salty' -ln 20 -r 8 -p 1 -c 2> /dev/null
$scrypt$ln=20,r=8,p=1$c2FsdHk$dErZxELnD6YP5sFs182F9jUfjGIxuNvSlVdjr8L4axQ
real	0m5,378s
user	0m4,916s
sys	0m0,439s


Source code format:
The import statments are sorted with: isort
linted with: pylama with pydocstyle-pep8, pydocstyle-257, pyflakes, McCabe
line length: 79
beautified with: black (line length 79)
pydocstyle: convention=numpy
    ~/.pydocstyle
    [pydocstyle]
    inherit = false
    match = .*\.py  # noqa
    convention=numpy


How to run it, examples:
# get help
hash_scrypt_passlib.py  -h

# derive one key, input from command line
hash_scrypt_passlib.py  'my passphrase'

# derive one key, input from file
hash_scrypt_passlib.py  -f  my_passphrase_file.txt

# piping passphrase into program, input from stdio/pipe
echo 'my passphrase' | hash_scrypt_passlib.py -c -f - 2> /dev/null
$scrypt$ln=16,r=8,p=1$3LyuY7klz5Oej9aAfRW+8A$ZXvOGuIDTp4J3j68kBVD6qsl3JDVVQt4Fdq124f/VZ0

# terse, just 1 line output
hash_scrypt_passlib.py  'my passphrase' -c 2> /dev/null
$scrypt$ln=16,r=8,p=1$f1TXjocFIl8FfQwqj4LT9A$RQJZboPWKenfrv44QhWONjTqTDDzF8xvR6F1Gv4zx2g

# test the program, run standardized test cases
hash_scrypt_passlib.py  -t # show test cases and some comments
hash_scrypt_passlib.py  -t 2>&1 | grep 'test case'  # just show test results
INFO:root:run_test_case:: ✅ test case 1 passed. 😀
...

# use existing salt, available in UTF-8 (not base64)
hash_scrypt_passlib.py  'my passphrase' --salt-utf8 'battery horse staple'

# use existing salt, available in Base64 encoding
hash_scrypt_passlib.py  'my passphrase' --salt-base64 'YmF0dGVyeSBob3JzZSBzdGFwbGU'

# to set the scrypt paramers N, R, and P use:
hash_scrypt_passlib.py  'my passphrase' -ln 20 -r 8 -p 1

# There are many more options, have a look at them:
hash_scrypt_passlib.py  --help

"""

# Imports, sorted by isort
import argparse
import base64
import binascii
import logging
import os
import sys
from io import TextIOWrapper
from typing import Union

from passlib.hash import scrypt

# Global Constants
# All values are set to match passlib defaults
# https://passlib.readthedocs.io/en/stable/lib/passlib.hash.scrypt.html?highlight=scrypt
DEFAULT_LN = 16
DEFAULT_R = 8
DEFAULT_P = 1
DEFAULT_SALT_LENGTH = 16  # usually, 16 or 32, 32*8=256 bits of randomness
DEFAULT_KEY_LENGTH = 32  # usually 32, 32*8=256 bits of randomness
PROG_NAME = os.path.basename(__file__)
PROG_NAME_NOEXT = os.path.splitext(PROG_NAME)[0]
METADATA_FILE_EXT = ".meta"  # file extension for metadata file
# default file name for metadata file
DEFAULT_METADATA_FILE = PROG_NAME_NOEXT + METADATA_FILE_EXT


################################################################
# Classes
################################################################

# None

################################################################
# Regular functions
################################################################


def fnln() -> str:
    """Return function name and line number of caller."""
    calling_line_number = sys._getframe().f_back.f_lineno
    calling_function = sys._getframe().f_back.f_code.co_name
    return calling_function + ":" + str(calling_line_number)


def init_args() -> argparse.Namespace:
    """Initialize the arguments.

    Returns
    -------
        argparse.Namespace -- namespace with all arguments

    """
    # argparse
    # 2 parsers are used because we want to evaluate once in the middle
    # of specifying the args.
    # pparser ... parent parser
    # no help -h on the parent parser to avoid getting 2 helps
    pparser = argparse.ArgumentParser(
        description="Stretch passphrase and hash", add_help=False
    )
    pparser.add_argument(
        "-d",
        "--debug",
        default=False,  # False ... turned off by default
        action="store_true",
        help="Turn debug on",
    )
    pparser.add_argument(
        "-c",  # concise, condensed
        "--terse",
        default=False,  # False ... turned off by default
        action="store_true",
        help="Produce only terse output, i.e. just one line containing the "
        "derived key will be printed to stdout.",
    )
    pparser.add_argument(
        "-v",
        "--verify",
        default=False,  # False ... turned off by default
        action="store_true",
        help="Turn verification on. Verification will take as many resources "
        "and clock time as the hash itself.",
    )
    pparser.add_argument(
        "-t",
        "--run-test-cases",
        default=False,  # False ... turned off by default
        action="store_true",
        help="Run standard hard-coded test cases to verify correctness. "
        "Now hash will be produced for use. All other arguments will be"
        "ignored.",
    )
    pparser.add_argument(
        "passphrase",
        nargs="*",
        help="Zero or more passphrases to be stretched and hashed. "
        "Zero is useful for --run-test-cases or --passphrase-file.",
    )
    pparser.add_argument(
        "-f",
        "--passphrase-file",
        type=argparse.FileType("rt"),
        help="File containing a single passphrase. "
        "If specified, the passphrase will be read from the specified file "
        "instead of from the arguments. If specified passwords from the "
        "command line arguments will be ignored. Passphrase must be in "
        "the first line of the specified UTF-8 file "
        "without any extra characters such as comments. Newline will be "
        'removed from passphrase. You can use the single letter "-" '
        "to specify stdin as file. This way you can pipe a passphrase "
        "into the program. E.g. "
        f"\"echo 'my passphrase' | {PROG_NAME} -d -f -\".",
    )
    pargs = pparser.parse_known_args()[0]  # get already known args from parent
    if pargs.passphrase_file is not None:
        metadata_filename = pargs.passphrase_file.name + METADATA_FILE_EXT
    else:
        metadata_filename = DEFAULT_METADATA_FILE
    # create the child parser inheriting from parent parser
    parser = argparse.ArgumentParser(parents=[pparser])
    parser.add_argument(
        "-m",
        "--metadata",
        type=argparse.FileType("wt"),
        nargs="?",
        # returns None if -m is not used
        const=metadata_filename,  # use this for -m without filename
        help="Filename for storing metadata. "
        "Optional argument. If specified, this program will produce "
        "a few lines of metadata (configuration parameters of the "
        "performed hash(es)) and store them in a small metadata text file. "
        "If -m is specified without filename but -f is specified, "
        "then the metadata filename "
        f'will be the -f filename appended with "{METADATA_FILE_EXT}". '
        "If neither -m specifies a file nor -f is specified, "
        "then metadata will be written to "
        f'default metadata file "{DEFAULT_METADATA_FILE}".'
        "If -m is specified with a filename then this will overwrite "
        "the default values and the metadata will be writen to the "
        "file specified with the -m. ",
    )
    parser.add_argument(
        "-s",
        "--salt-utf8",
        help="A salt string in UTF-8. (Not base64 encoded.)",
    )
    parser.add_argument(
        "-b", "--salt-base64", help="A salt string that is base64 encoded. "
    )
    parser.add_argument(
        "-u",
        "--salt-length",
        type=int,
        # default: must not set default so we detect if arg was used or not
        help="Usually 16 or 32. "
        "16 gives 16*8=128bits of salt randomness. "
        "32 gives 32*8=265bits of salt randomness. "
        "Standards use 16. "
        f"Default is {DEFAULT_SALT_LENGTH}. "
        "Do not use this --salt-length parameter if you are specifying "
        "the salt yourself with --salt-utf8 or --salt-base64.",
    )
    parser.add_argument(
        "-k",
        "--key-length",
        type=int,
        default=DEFAULT_KEY_LENGTH,
        help="Usually 32. "
        "32 gives 32*8=265bits of salt randomness. "
        f"Default is {DEFAULT_KEY_LENGTH}.",
    )
    parser.add_argument(
        "-ln",
        "--ln",
        type=int,
        default=DEFAULT_LN,
        help="Log N: Log2 of scrypt parameter N. "
        "Standards recommend 14 for interactive use "
        "(t < 100ms). 20 for file encryption (t < 5s). "
        f"Default is {DEFAULT_LN}.",
    )
    parser.add_argument(
        "-r",
        "--r",
        type=int,
        default=DEFAULT_R,
        help="R: scrypt parameter R. Block Size parameter. "
        "Standards recommend 8. Some use 16. "
        f"Default is {DEFAULT_R}.",
    )
    parser.add_argument(
        "-p",
        "--p",
        type=int,
        default=DEFAULT_P,
        help="P: scrypt parameter P. Parallelization parameter. "
        "Common use is 1. "
        f"Default is {DEFAULT_P}.",
    )
    args = parser.parse_args()
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    logging.debug(f"{fnln()}:: args before cleanup: ")
    for arg in vars(args):
        logging.debug(f"{fnln()}::     {arg}={getattr(args, arg)}")
    # check arguments
    # salt_utf8 not used --> None, not the same as "", but both are False
    if args.salt_length is not None and (
        args.salt_utf8 is not None or args.salt_base64 is not None
    ):
        logging.error(
            f"{fnln()}:: ❌ Must not use --salt-length if --salt-utf8 "
            "or --salt-base64 are used."
        )
        sys.exit(1)
    if args.salt_utf8 is not None and args.salt_base64 is not None:
        logging.error(
            f"{fnln()}:: ❌ Must not use both --salt-utf8 and --salt-base64."
        )
        sys.exit(1)
    if (
        args.salt_length is None
        and args.salt_utf8 is None
        and args.salt_base64 is None
    ):
        # none of the 3 arguments was set
        args.salt_length = DEFAULT_SALT_LENGTH
    if (
        args.passphrase is not None
        and len(args.passphrase) > 0
        and args.passphrase_file is not None
    ):
        logging.error(
            f"{fnln()}:: ❌ Must not specify passphrase in arguments as well "
            "as in --passphrase-file. Specify passphrase either as command "
            "line argument or in passphrase file."
        )
        sys.exit(1)
    if args.passphrase_file is not None:
        # args.passphrase_file is an TextIOWrapper ready for read
        # read first line, remove \n or OS specific line ending
        args.passphrase = [args.passphrase_file.readline().rstrip()]
        args.passphrase_file.close()  # no longer needed
    logging.debug(f"{fnln()}:: args after cleanup: ")
    for arg in vars(args):
        logging.debug(f"{fnln()}::     {arg}={getattr(args, arg)}")
    return args


def init() -> argparse.Namespace:
    """Initialize the program.

    Returns
    -------
        argparse.Namespace -- namespace with all arguments from argparse

    """
    # general
    # signal.signal(signal.SIGINT, signal.SIG_DFL)  # for PyQt5 GUI
    # arguments
    args = init_args()
    return args


def hash(  # noqa
    passphrase: str,
    key_length: int = DEFAULT_KEY_LENGTH,
    salt_length: Union[int, None] = None,
    salt_utf8: Union[str, None] = None,
    salt_base64: Union[str, None] = None,
    ln: int = DEFAULT_LN,
    r: int = DEFAULT_R,
    p: int = DEFAULT_P,
    verify: bool = False,
    metadata_textio: Union[TextIOWrapper, None] = None,
    terse: bool = False,
) -> str:
    """Use KDF to stretch and hash passphrase.

    Uses scrypt algorithm.

    Arguments:
    ---------
        passphrase: str -- passphrase to be stretched and hashed
        key_length: int -- lengths in bytes of key to be derived
        salt_length: Union[int, None] -- in bytes
        salt_utf8: Union[str, None] -- UTF-8 string to use as salt
        salt_base64: Union[str, None] -- base64 string to use as salt
        ln: int -- log N, scrypt parameter
        r: int -- r, scrypt parameter
        p: int -- p, scrypt parameter
        verify: bool -- verify derived key?
        metadata_textio: Union[TextIOWrapper, None] -- file to which metadata
            will be written
        terse: bool -- if true keep output to stdout terse/short

    Returns
    -------
        str -- returns a PHC formatted string of the hash, the derived key
        Looks like this:
        $scrypt$ln=16,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E

    Scrypt Parameters:
    -----------------
    salt (bytes) – A salt.
    length (int) – The desired length of the derived key in bytes.
    n (int) – CPU/Memory cost parameter. Must be a power of 2.
    r (int) – Block size parameter. (Usually 8 or 16)
    p (int) – Parallelization parameter.
    backend – An optional instance of ScryptBackend.

    Maximum difficulty:
    ------------------
    Set r to 8.
    Determine n: First increase n until machine runs out of memory.
    Leave r at 8,
       or increase r from 8 to 9, 10, ... 15 to absolutely max out memory.
    Memory used is: 128 * 2**n * r bytes plus some small overhead
    Use the n and r from above, and now increase p from 1 to 2, 3, ... 100, ...
       to increase total time needed for hashing, p=2 means twice as much
       time or memory is needed as with p=1, etc. So, since on given machine
       memory is maxed out, p=10 takes 10 times as much clock time to hash as
       with p=1.

    """
    # the scrypt parameters
    if salt_length is not None and salt_length <= 0:
        logging.error(
            f"{fnln()}:: ❌ salt length must be positive. "
            "No key can be derived."
        )
        return "Error 10"
    if salt_length is not None:
        custom_scrypt = scrypt.using(salt_size=salt_length)  # int
        salt = b""  # not set in this case, will be set by scrypt.hash()
    elif salt_utf8 is not None:
        # salt must be bytes (not string)!
        salt = salt_utf8.encode("utf-8")
        custom_scrypt = scrypt.using(salt=salt)
    elif salt_base64 is not None:
        # padded?
        if (len(salt_base64) % 4) == 0:
            # padded or no pad needed
            pass
        elif (len(salt_base64) % 4) == 1:
            logging.error(f"{fnln()}:: ❌ invalid base64 string {salt_base64}")
            sys.exit(2)
        elif (len(salt_base64) % 4) == 2:
            salt_base64 += "=="
        else:  # if (len(salt_base64) % 4) == 3:
            salt_base64 += "="
        # salt must be bytes (not string)!
        # s-to-b-to-b64
        try:
            salt = base64.b64decode(salt_base64.encode("utf-8"), validate=True)
        except binascii.Error as e:
            logging.error(
                f"{fnln()}:: ❌ invalid base64 string {salt_base64}: {e}"
            )
            sys.exit(5)
        custom_scrypt = scrypt.using(salt=salt)

    if ln < 1:
        logging.error(
            f"{fnln()}:: ❌ ln must be larger than 0. No key can be derived."
        )
        return "Error 6"
    if r <= 0:
        logging.error(
            f"{fnln()}:: ❌ r must be larger than 0. No key can be derived."
        )
        return "Error 7"
    if r * p >= 2 ** 30:
        logging.error(
            f"{fnln()}:: ❌ r*p must be less than 2**30. No key can be derived."
        )
        return "Error 8"
    # specific limitation of passlib
    if key_length != 32:
        logging.error(
            f"{fnln()}:: ❌ Requested key length is {key_length} but passlib "
            "exclusively supports key length of 32 bytes. Use program "
            "hash_scrypt_pycacrypto.py instead."
        )
        return "Error 9"
    if key_length <= 0:
        logging.error(
            f"{fnln()}:: ❌ key length must be positive. No key can be derived."
        )
        return "Error 9"

    # salt_length = len(salt)
    n = 2 ** ln
    # N, with r, determines the memory block size and hashing iterations
    # 128⋅N⋅r bytes of RAM
    # 2⋅N⋅r rounds of hashing
    logging.info(f"{fnln()}:: {128*r*n/1024/1024} MB of " "RAM will be used.")
    logging.info(
        f"{fnln()}:: {2*r*n/1024/1024} million rounds of internal "
        "hashing will be performed."
    )
    # changing deault parameters to context
    hash_phc = custom_scrypt.using(
        rounds=ln,  # int, ln, log n
        block_size=r,  # int, r
        parallelism=p,  # int, p
    ).hash(
        passphrase
    )  # hashing a password...
    for idx, value in {
        "salt": salt,  # bytes
        "passphrase": passphrase,
        "hash_phc": hash_phc,  # str
    }.items():
        logging.debug(f"{fnln()}:: type of {idx} is {type(value)}")
        try:
            logging.debug(f"{fnln()}:: length of {idx} is {len(value)}")
        except:  # noqa
            pass
        logging.debug(f"{fnln()}:: {idx} has value {value}")

    if verify:
        # passphrase verification can be done like this
        if scrypt.verify(passphrase, hash_phc):
            logging.info(f"{fnln()}:: ✅ Verification passed.")
        else:
            logging.error(
                f"{fnln()}:: ❌ Severe ERROR: verification of hash failed"
            )
            sys.exit(4)
    else:
        logging.debug(
            f"{fnln()}:: no verification was done because it was not requested."  # noqa
        )
    if terse:
        print(hash_phc)  # if terse, only print this one string
    else:
        print(f"✅ Hash in PHC Format is {hash_phc}   [used passlib]")
    if metadata_textio is not None:
        meta = hash_phc.split("$")
        if len(meta) != 5:
            logging.error(
                f"{fnln()}:: ❌ Severe ERROR: wrong number of segements "
                "in PHC form."
            )
            sys.exit(9)
        metastr = f"${meta[1]}${meta[2]}${meta[3]}$"
        print(metastr, file=metadata_textio, flush=True)
    return hash_phc


################################################################
# Tests with known to be correct hashes
################################################################


def run_test_case1(number: int, match_expected: bool):
    """Run test case."""
    # known to be correct:
    # salt=b""
    # ("", "$scrypt$ln=4,r=1,p=1$$d9ZXYjhleyA7GcpCwYoEl/FrSETjB0ro39/6P+3iFEI")
    result = hash(
        "",
        key_length=32,
        salt_length=None,
        salt_utf8=None,
        salt_base64="",
        ln=4,
        r=1,
        p=1,
        verify=True,
    )
    reference = (
        "$scrypt$ln=4,r=1,p=1$$d9ZXYjhleyA7GcpCwYoEl/FrSETjB0ro39/6P+3iFEI"
    )  # noqa
    match = result == reference
    if match == match_expected:
        logging.info(f"{fnln()}:: ✅ test case {number} passed. 😀")
        # logging.info(f"{fnln()}:: result    = {result}")
        # logging.info(f"{fnln()}:: reference = {reference}")
    else:
        logging.info(f"{fnln()}:: ❌ test case {number} failed. 💀")
        # logging.info(f"{fnln()}:: result    = {result}")
        # logging.info(f"{fnln()}:: reference = {reference}")


def run_test_case2(number: int, match_expected: bool):
    """Run test case."""
    # known to be correct:
    # salt=b"NaCl"
    # ("password", "$scrypt$ln=10,r=8,p=16$TmFDbA$/bq+HJ00cgB4VucZDQHp/nxq18vII3gw53N2Y0s3MWI")  # noqa
    result = hash(
        "password",
        key_length=32,
        salt_length=None,
        salt_utf8="NaCl",
        salt_base64=None,
        ln=10,
        r=8,
        p=16,
        verify=True,
    )
    reference = "$scrypt$ln=10,r=8,p=16$TmFDbA$/bq+HJ00cgB4VucZDQHp/nxq18vII3gw53N2Y0s3MWI"  # noqa
    match = result == reference
    if match == match_expected:
        logging.info(f"{fnln()}:: ✅ test case {number} passed. 😀")
        # logging.info(f"{fnln()}:: result    = {result}")
        # logging.info(f"{fnln()}:: reference = {reference}")
    else:
        logging.info(f"{fnln()}:: ❌ test case {number} failed. 💀")
        # logging.info(f"{fnln()}:: result    = {result}")
        # logging.info(f"{fnln()}:: reference = {reference}")


def run_test_case3(number: int, match_expected: bool):
    """Run test case."""
    # known to be correct:
    # simple test
    # ("test", '$scrypt$ln=8,r=8,p=1$wlhLyXmP8b53bm1NKYVQqg$mTpvG8lzuuDk+DWz8HZIB6Vum6erDuUm0As5yU+VxWA')  # noqa
    result = hash(
        "test",
        key_length=32,
        salt_length=None,
        salt_utf8=None,
        salt_base64="wlhLyXmP8b53bm1NKYVQqg",
        ln=8,
        r=8,
        p=1,
        verify=True,
    )
    reference = "$scrypt$ln=8,r=8,p=1$wlhLyXmP8b53bm1NKYVQqg$mTpvG8lzuuDk+DWz8HZIB6Vum6erDuUm0As5yU+VxWA"  # noqa
    match = result == reference
    if match == match_expected:
        logging.info(f"{fnln()}:: ✅ test case {number} passed. 😀")
        # logging.info(f"{fnln()}:: result    = {result}")
        # logging.info(f"{fnln()}:: reference = {reference}")
    else:
        logging.info(f"{fnln()}:: ❌ test case {number} failed. 💀")
        # logging.info(f"{fnln()}:: result    = {result}")
        # logging.info(f"{fnln()}:: reference = {reference}")


def run_test_case4(number: int, match_expected: bool):
    """Run test case."""
    # known to be correct:
    # different block value
    # ("password", '$scrypt$ln=8,r=2,p=1$dO6d0xoDoLT2PofQGoNQag$g/Wf2A0vhHhaJM+addK61QPBthSmYB6uVTtQzh8CM3o')  # noqa
    result = hash(
        "password",
        key_length=32,
        salt_length=None,
        salt_utf8=None,
        salt_base64="dO6d0xoDoLT2PofQGoNQag",
        ln=8,
        r=2,
        p=1,
        verify=True,
    )
    reference = "$scrypt$ln=8,r=2,p=1$dO6d0xoDoLT2PofQGoNQag$g/Wf2A0vhHhaJM+addK61QPBthSmYB6uVTtQzh8CM3o"  # noqa
    match = result == reference
    if match == match_expected:
        logging.info(f"{fnln()}:: ✅ test case {number} passed. 😀")
        # logging.info(f"{fnln()}:: result    = {result}")
        # logging.info(f"{fnln()}:: reference = {reference}")
    else:
        logging.info(f"{fnln()}:: ❌ test case {number} failed. 💀")
        # logging.info(f"{fnln()}:: result    = {result}")
        # logging.info(f"{fnln()}:: reference = {reference}")


def run_test_case5(number: int, match_expected: bool):
    """Run test case."""
    # known to be correct:
    # different rounds
    # (UPASS_TABLE, '$scrypt$ln=7,r=8,p=1$jjGmtDamdA4BQAjBeA9BSA$OiWRHhQtpDx7M/793x6UXK14AD512jg/qNm/hkWZG4M')  # noqa
    # passphrase from from passlib.tests.test_handlers import UPASS_TABLE
    result = hash(
        "táБℓə",
        key_length=32,
        salt_length=None,
        salt_utf8=None,
        salt_base64="jjGmtDamdA4BQAjBeA9BSA",
        ln=7,
        r=8,
        p=1,
        verify=True,
    )
    reference = "$scrypt$ln=7,r=8,p=1$jjGmtDamdA4BQAjBeA9BSA$OiWRHhQtpDx7M/793x6UXK14AD512jg/qNm/hkWZG4M"  # noqa
    match = result == reference
    if match == match_expected:
        logging.info(f"{fnln()}:: ✅ test case {number} passed. 😀")
        # logging.info(f"{fnln()}:: result    = {result}")
        # logging.info(f"{fnln()}:: reference = {reference}")
    else:
        logging.info(f"{fnln()}:: ❌ test case {number} failed. 💀")
        # logging.info(f"{fnln()}:: result    = {result}")
        # logging.info(f"{fnln()}:: reference = {reference}")


def run_test_case6(number: int, match_expected: bool):
    """Run test case."""
    # known to be correct:
    # different rounds
    # (UPASS_TABLE, '$scrypt$ln=7,r=8,p=1$jjGmtDamdA4BQAjBeA9BSA$OiWRHhQtpDx7M/793x6UXK14AD512jg/qNm/hkWZG4M')  # noqa
    # b't\xc3\xa1\xd0\x91\xe2\x84\x93\xc9\x99'
    # passphrase from from passlib.tests.test_handlers import PASS_TABLE_UTF8
    result = hash(
        b"t\xc3\xa1\xd0\x91\xe2\x84\x93\xc9\x99".decode("utf-8"),
        key_length=32,
        salt_length=None,
        salt_utf8=None,
        salt_base64="jjGmtDamdA4BQAjBeA9BSA",
        ln=7,
        r=8,
        p=1,
        verify=True,
    )
    reference = "$scrypt$ln=7,r=8,p=1$jjGmtDamdA4BQAjBeA9BSA$OiWRHhQtpDx7M/793x6UXK14AD512jg/qNm/hkWZG4M"  # noqa
    match = result == reference
    if match == match_expected:
        logging.info(f"{fnln()}:: ✅ test case {number} passed. 😀")
        # logging.info(f"{fnln()}:: result    = {result}")
        # logging.info(f"{fnln()}:: reference = {reference}")
    else:
        logging.info(f"{fnln()}:: ❌ test case {number} failed. 💀")
        # logging.info(f"{fnln()}:: result    = {result}")
        # logging.info(f"{fnln()}:: reference = {reference}")


def run_test_case7(number: int, match_expected: bool):
    """Run test case."""
    # known to be correct:
    # diff block & parallel counts as well
    # ("nacl", '$scrypt$ln=1,r=4,p=2$yhnD+J+Tci4lZCwFgHCuVQ$fAsEWmxSHuC0cHKMwKVFPzrQukgvK09Sj+NueTSxKds'  # noqa
    result = hash(
        "nacl",
        key_length=32,
        salt_length=None,
        salt_utf8=None,
        salt_base64="yhnD+J+Tci4lZCwFgHCuVQ",
        ln=1,
        r=4,
        p=2,
        verify=True,
    )
    reference = "$scrypt$ln=1,r=4,p=2$yhnD+J+Tci4lZCwFgHCuVQ$fAsEWmxSHuC0cHKMwKVFPzrQukgvK09Sj+NueTSxKds"  # noqa
    match = result == reference
    if match == match_expected:
        logging.info(f"{fnln()}:: ✅ test case {number} passed. 😀")
        # logging.info(f"{fnln()}:: result    = {result}")
        # logging.info(f"{fnln()}:: reference = {reference}")
    else:
        logging.info(f"{fnln()}:: ❌ test case {number} failed. 💀")
        # logging.info(f"{fnln()}:: result    = {result}")
        # logging.info(f"{fnln()}:: reference = {reference}")


def run_test_case8(number: int, match_expected: bool):
    """Run test case."""
    # known to be correct:
    # salt=b"SodiumChloride"
    # ("pleaseletmein", "$scrypt$ln=14,r=8,p=1$U29kaXVtQ2hsb3JpZGU$cCO9yzr9c0hGHAbNgf046/2o+7qQT44+qbVD9lRdofI")  # noqa
    result = hash(
        "pleaseletmein",
        key_length=32,
        salt_length=None,
        salt_utf8="SodiumChloride",
        salt_base64=None,
        ln=14,
        r=8,
        p=1,
        verify=True,
    )
    reference = "$scrypt$ln=14,r=8,p=1$U29kaXVtQ2hsb3JpZGU$cCO9yzr9c0hGHAbNgf046/2o+7qQT44+qbVD9lRdofI"  # noqa
    match = result == reference
    if match == match_expected:
        logging.info(f"{fnln()}:: ✅ test case {number} passed. 😀")
        # logging.info(f"{fnln()}:: result    = {result}")
        # logging.info(f"{fnln()}:: reference = {reference}")
    else:
        logging.info(f"{fnln()}:: ❌ test case {number} failed. 💀")
        # logging.info(f"{fnln()}:: result    = {result}")
        # logging.info(f"{fnln()}:: reference = {reference}")


def run_test_case9(number: int, match_expected: bool):
    """Run test case."""
    # known to be correct:
    # openwall format (https://gitlab.com/jas/scrypt-unix-crypt/blob/master/unix-scrypt.txt)  # noqa
    # ("pleaseletmein", "$7$C6..../....SodiumChloride$kBGj9fHznVYFQMEn/qDCfrDevf9YDtcDdKvEqHJLV8D")  # noqa
    # Hex from https://tools.ietf.org/html/rfc7914.html page 12 test case 3:
    # 7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887
    # 70 23 bd cb 3a fd 73 48 46 1c 06 cd 81 fd 38 eb
    # fd a8 fb ba 90 4f 8e 3e a9 b5 43 f6 54 5d a1 f2
    # d5 43 29 55 61 3f 0f cf 62 d4 97 05 24 2a 9a f9
    # e6 1e 85 dc 0d 65 1e 40 df cf 01 7b 45 57 58 87
    # This hex converted into Base64 is : https://base64.guru/converter/encode/hex  # noqa
    # cCO9yzr9c0hGHAbNgf046/2o+7qQT44+qbVD9lRdofLVQylVYT8Pz2LUlwUkKpr55h6F3A1lHkDfzwF7RVdYhw==
    # We must adapt to passlib limitation of key length == 32
    # cCO9yzr9c0hGHAbNgf046/2o+7qQT44+qbVD9lRdofI=
    result = hash(
        "pleaseletmein",
        key_length=32,
        salt_length=None,
        salt_utf8="SodiumChloride",
        salt_base64=None,
        ln=14,
        r=8,
        p=1,
        verify=True,
    )
    reference = "$scrypt$ln=14,r=8,p=1$U29kaXVtQ2hsb3JpZGU$cCO9yzr9c0hGHAbNgf046/2o+7qQT44+qbVD9lRdofI"  # noqa
    match = result == reference
    if match == match_expected:
        logging.info(f"{fnln()}:: ✅ test case {number} passed. 😀")
        # logging.info(f"{fnln()}:: result    = {result}")
        # logging.info(f"{fnln()}:: reference = {reference}")
    else:
        logging.info(f"{fnln()}:: ❌ test case {number} failed. 💀")
        # logging.info(f"{fnln()}:: result    = {result}")
        # logging.info(f"{fnln()}:: reference = {reference}")


def run_test_case10(number: int, match_expected: bool):
    """Run test case."""
    # known to be correct:
    # Hex from https://tools.ietf.org/html/rfc7914.html page 12 test case 1:
    # 77 d6 57 62 38 65 7b 20 3b 19 ca 42 c1 8a 04 97
    # f1 6b 48 44 e3 07 4a e8 df df fa 3f ed e2 14 42
    # fc d0 06 9d ed 09 48 f8 32 6a 75 3a 0f c8 1f 17
    # e8 d3 e0 fb 2e 0d 36 28 cf 35 e2 0c 38 d1 89 06
    # This hex converted into Base64 is : https://base64.guru/converter/encode/hex  # noqa
    # d9ZXYjhleyA7GcpCwYoEl/FrSETjB0ro39/6P+3iFEL80Aad7QlI+DJqdToPyB8X6NPg+y4NNijPNeIMONGJBg==
    # We must adapt to passlib limitation of key length == 32
    # d9ZXYjhleyA7GcpCwYoEl/FrSETjB0ro39/6P+3iFEI=
    result = hash(
        "",
        key_length=32,
        salt_length=None,
        salt_utf8="",
        salt_base64=None,
        ln=4,
        r=1,
        p=1,
        verify=True,
    )
    reference = (
        "$scrypt$ln=4,r=1,p=1$$d9ZXYjhleyA7GcpCwYoEl/FrSETjB0ro39/6P+3iFEI"
    )  # noqa
    match = result == reference
    if match == match_expected:
        logging.info(f"{fnln()}:: ✅ test case {number} passed. 😀")
        # logging.info(f"{fnln()}:: result    = {result}")
        # logging.info(f"{fnln()}:: reference = {reference}")
    else:
        logging.info(f"{fnln()}:: ❌ test case {number} failed. 💀")
        # logging.info(f"{fnln()}:: result    = {result}")
        # logging.info(f"{fnln()}:: reference = {reference}")


def run_test_case11(number: int, match_expected: bool):
    """Run test case."""
    # known to be correct:
    # Hex from https://tools.ietf.org/html/rfc7914.html page 12 test case 2:
    # fd ba be 1c 9d 34 72 00 78 56 e7 19 0d 01 e9 fe
    # 7c 6a d7 cb c8 23 78 30 e7 73 76 63 4b 37 31 62
    # 2e af 30 d9 2e 22 a3 88 6f f1 09 27 9d 98 30 da
    # c7 27 af b9 4a 83 ee 6d 83 60 cb df a2 cc 06 40
    # This hex converted into Base64 is : https://base64.guru/converter/encode/hex  # noqa
    # /bq+HJ00cgB4VucZDQHp/nxq18vII3gw53N2Y0s3MWIurzDZLiKjiG/xCSedmDDaxyevuUqD7m2DYMvfoswGQA==
    # We must adapt to passlib limitation of key length == 32
    # /bq+HJ00cgB4VucZDQHp/nxq18vII3gw53N2Y0s3MWI=
    result = hash(
        "password",
        key_length=32,
        salt_length=None,
        salt_utf8="NaCl",
        salt_base64=None,
        ln=10,
        r=8,
        p=16,
        verify=True,
    )
    reference = "$scrypt$ln=10,r=8,p=16$TmFDbA$/bq+HJ00cgB4VucZDQHp/nxq18vII3gw53N2Y0s3MWI"  # noqa
    match = result == reference
    if match == match_expected:
        logging.info(f"{fnln()}:: ✅ test case {number} passed. 😀")
        # logging.info(f"{fnln()}:: result    = {result}")
        # logging.info(f"{fnln()}:: reference = {reference}")
    else:
        logging.info(f"{fnln()}:: ❌ test case {number} failed. 💀")
        # logging.info(f"{fnln()}:: result    = {result}")
        # logging.info(f"{fnln()}:: reference = {reference}")


def run_test_case12(number: int, match_expected: bool):
    """Run test case."""
    # known to be correct:
    # Hex from https://tools.ietf.org/html/rfc7914.html page 12 test case 4:
    # 21 01 cb 9b 6a 51 1a ae ad db be 09 cf 70 f8 81
    # ec 56 8d 57 4a 2f fd 4d ab e5 ee 98 20 ad aa 47
    # 8e 56 fd 8f 4b a5 d0 9f fa 1c 6d 92 7c 40 f4 c3
    # 37 30 40 49 e8 a9 52 fb cb f4 5c 6f a7 7a 41 a4
    # This hex converted into Base64 is : https://base64.guru/converter/encode/hex  # noqa
    # IQHLm2pRGq6t274Jz3D4gexWjVdKL/1Nq+XumCCtqkeOVv2PS6XQn/ocbZJ8QPTDNzBASeipUvvL9Fxvp3pBpA==
    # We must adapt to passlib limitation of key length == 32
    # IQHLm2pRGq6t274Jz3D4gexWjVdKL/1Nq+XumCCtqkc=
    result = hash(
        "pleaseletmein",
        key_length=32,
        salt_length=None,
        salt_utf8="SodiumChloride",
        salt_base64=None,
        ln=20,
        r=8,
        p=1,
        verify=True,
    )
    reference = "$scrypt$ln=20,r=8,p=1$U29kaXVtQ2hsb3JpZGU$IQHLm2pRGq6t274Jz3D4gexWjVdKL/1Nq+XumCCtqkc"  # noqa
    match = result == reference
    if match == match_expected:
        logging.info(f"{fnln()}:: ✅ test case {number} passed. 😀")
        # logging.info(f"{fnln()}:: result    = {result}")
        # logging.info(f"{fnln()}:: reference = {reference}")
    else:
        logging.info(f"{fnln()}:: ❌ test case {number} failed. 💀")
        # logging.info(f"{fnln()}:: result    = {result}")
        # logging.info(f"{fnln()}:: reference = {reference}")


################################################################
# Tests with known to be malformed hashes
################################################################


def run_test_case101(number: int, match_expected: bool):
    """Run test case."""
    # known to be malformed:
    # missing 'p' value
    # $scrypt$ln=16,r=8$RAjB2FuLUWotJSRkLIXQWg$O+N5g/p2gEnZwINcPQ+jY0ywliT5BIVrZSGdjiWc6OM
    result = hash(
        "",
        key_length=32,
        salt_length=None,
        salt_utf8=None,
        salt_base64="RAjB2FuLUWotJSRkLIXQWg",
        ln=16,
        r=8,
        p=1,
        verify=True,
    )
    reference = "$scrypt$ln=16,r=8$RAjB2FuLUWotJSRkLIXQWg$O+N5g/p2gEnZwINcPQ+jY0ywliT5BIVrZSGdjiWc6OM"  # noqa
    match = result == reference
    if match == match_expected:
        logging.info(f"{fnln()}:: ✅ test case {number} passed. 😀")
        # logging.info(f"{fnln()}:: result    = {result}")
        # logging.info(f"{fnln()}:: reference = {reference}")
    else:
        logging.info(f"{fnln()}:: ❌ test case {number} failed. 💀")
        # logging.info(f"{fnln()}:: result    = {result}")
        # logging.info(f"{fnln()}:: reference = {reference}")


def run_test_case102(number: int, match_expected: bool):
    """Run test case."""
    # known to be malformed:
    # rounds too low, ln too low
    result = hash(
        "",
        key_length=32,
        salt_length=None,
        salt_utf8=None,
        salt_base64="RAjB2FuLUWotJSRkLIXQWg",
        ln=0,
        r=8,
        p=1,
        verify=True,
    )
    reference = "Error 6"  # noqa
    match = result == reference
    if match == match_expected:
        logging.info(f"{fnln()}:: ✅ test case {number} passed. 😀")
        # logging.info(f"{fnln()}:: result    = {result}")
        # logging.info(f"{fnln()}:: reference = {reference}")
    else:
        logging.info(f"{fnln()}:: ❌ test case {number} failed. 💀")
        # logging.info(f"{fnln()}:: result    = {result}")
        # logging.info(f"{fnln()}:: reference = {reference}")


def run_test_case103(number: int, match_expected: bool):
    """Run test case."""
    # known to be malformed:
    # invalid block size r
    result = hash(
        "",
        key_length=32,
        salt_length=None,
        salt_utf8=None,
        salt_base64="RAjB2FuLUWotJSRkLIXQWg",
        ln=16,
        r=0,
        p=1,
        verify=True,
    )
    reference = "Error 7"  # noqa
    match = result == reference
    if match == match_expected:
        logging.info(f"{fnln()}:: ✅ test case {number} passed. 😀")
        # logging.info(f"{fnln()}:: result    = {result}")
        # logging.info(f"{fnln()}:: reference = {reference}")
    else:
        logging.info(f"{fnln()}:: ❌ test case {number} failed. 💀")
        # logging.info(f"{fnln()}:: result    = {result}")
        # logging.info(f"{fnln()}:: reference = {reference}")


def run_test_case104(number: int, match_expected: bool):
    """Run test case."""
    # known to be malformed:
    # r*p too large: ln=10,r=134217728,p=8, r * p < 2^30 == 1073741824
    result = hash(
        "",
        key_length=32,
        salt_length=None,
        salt_utf8=None,
        salt_base64="RAjB2FuLUWotJSRkLIXQWg",
        ln=10,
        r=134217728,
        p=8,
        verify=True,
    )
    reference = "Error 8"  # noqa
    match = result == reference
    if match == match_expected:
        logging.info(f"{fnln()}:: ✅ test case {number} passed. 😀")
        # logging.info(f"{fnln()}:: result    = {result}")
        # logging.info(f"{fnln()}:: reference = {reference}")
    else:
        logging.info(f"{fnln()}:: ❌ test case {number} failed. 💀")
        # logging.info(f"{fnln()}:: result    = {result}")
        # logging.info(f"{fnln()}:: reference = {reference}")


def run_test_cases():
    """Run standard hard-coded test cases to verify correctness."""
    # test cases from
    # https://foss.heptapod.net/python-libs/passlib/-/blob/branch/stable/
    #       passlib/tests/test_handlers_scrypt.py
    # (http://www.tarsnap.com/scrypt/scrypt.pdf, appendix b)
    run_test_case1(1, True)  # expected to match
    run_test_case2(2, True)  # expected to match
    run_test_case3(3, True)  # expected to match
    run_test_case4(4, True)  # expected to match
    run_test_case5(5, True)  # expected to match
    run_test_case6(6, True)  # expected to match
    run_test_case7(7, True)  # expected to match
    run_test_case8(8, True)  # expected to match
    run_test_case9(9, True)  # expected to match
    run_test_case10(10, True)  # expected to match
    run_test_case11(11, True)  # expected to match
    run_test_case12(12, True)  # expected to match
    run_test_case101(101, False)  # expected to not match
    run_test_case102(102, True)
    run_test_case103(103, True)
    run_test_case104(104, True)


def main():
    """Do all."""
    args = init()
    if args.run_test_cases:
        run_test_cases()
        return
    if args.passphrase is None:
        return
    if (len(args.passphrase) > 1) and (args.salt_utf8 or args.salt_base64):
        logging.warning(
            f"{fnln()}:: ❗ Warning: salt will be reused across multiple "
            "passphrases. This is not recommended. Be warned."
        )
    for passphrase in args.passphrase:
        hash(
            passphrase,
            args.key_length,
            args.salt_length,
            args.salt_utf8,
            args.salt_base64,
            args.ln,
            args.r,
            args.p,
            args.verify,
            args.metadata,
            args.terse,
        )
    if args.metadata is not None:
        args.metadata.close()


try:
    main()
except KeyboardInterrupt:
    logging.debug("❗ Received keyboard interrupt.")
    raise
    sys.exit()
except Exception as e:
    logging.error(f"❌ Caught exception {e}.")
    raise
    sys.exit(1)
