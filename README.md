# Modern Haskell Cryptography

[![Build Status](https://travis-ci.org/thoughtpolice/hs-nacl.png?branch=master)](https://travis-ci.org/thoughtpolice/hs-nacl)
[![BSD3](http://b.repl.ca/v1/license-BSD3-blue.png)](http://en.wikipedia.org/wiki/BSD_licenses)
[![Haskell](http://b.repl.ca/v1/language-haskell-lightgrey.png)](http://www.haskell.org)

[NaCl][] (pronounced "salt") is a fast library for cryptographic
networking. Think of it like OpenSSL, but faster, easier, and more
secure.

These are the awesome Haskell bindings.

[NaCl]: http://nacl.cr.yp.to/

# Getting started

It's just a `cabal install` away on [Hackage][]:

```bash
$ cabal install nacl
```

After you install it, be sure to check out the [wiki][] for more
documentation, examples, and help.

[wiki]: https://github.com/thoughtpolice/hs-nacl/wiki

# Join in

Be sure to read the [contributing guidelines][contribute]. File bugs
in the GitHub [issue tracker][].

Master [git repository][gh]:

* `git clone https://github.com/thoughtpolice/hs-nacl.git`

There's also a [BitBucket mirror][bb]:

* `git clone https://bitbucket.org/thoughtpolice/hs-nacl.git`

# Authors

See [AUTHORS.txt](https://raw.github.com/thoughtpolice/hs-nacl/master/AUTHORS.txt).

# License

BSD3. See
[LICENSE.txt](https://raw.github.com/thoughtpolice/hs-nacl/master/LICENSE.txt)
for terms of copyright and redistribution.

[contribute]: https://github.com/thoughtpolice/hs-nacl/blob/master/CONTRIBUTING.md
[issue tracker]: http://github.com/thoughtpolice/hs-nacl/issues
[gh]: http://github.com/thoughtpolice/hs-nacl
[bb]: http://bitbucket.org/thoughtpolice/hs-nacl
[Hackage]: http://hackage.haskell.org/package/nacl

# Cryptography Notice

This distribution includes cryptographic software. The country in
which you currently reside may have restrictions on the import,
possession, use, and/or re-export to another country, of encryption
software.  BEFORE using any encryption software, please check your
country's laws, regulations and policies concerning the import,
possession, or use, and re-export of encryption software, to see if
this is permitted.  See <http://www.wassenaar.org/> for more
information.

The U.S. Government Department of Commerce, Bureau of Industry and
Security (BIS), has classified this software as Export Commodity
Control Number (ECCN) 5D002.C.1, which includes information security
software using or performing cryptographic functions with asymmetric
algorithms.  The form and manner of this distribution makes it
eligible for export under the License Exception ENC Technology
Software Unrestricted (TSU) exception (see the BIS Export
Administration Regulations, Section 740.13) for both object code and
source code.
