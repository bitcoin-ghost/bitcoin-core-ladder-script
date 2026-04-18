Bitcoin Core (Ladder Script fork)
=================================

This is a Bitcoin Core v30.0 fork that adds **Ladder Script**, a typed
transaction condition format. The fork lives on the `ladder-script` branch.
The `master` branch tracks upstream Bitcoin Core unchanged.

- **Live signet, engine, playground, block reference, full docs:** https://ladder-script.org
- **Spec and design docs in this repository:** [`doc/ladder-script/`](doc/ladder-script/)
- **BIP wireframe:** [`doc/ladder-script/BIP-XXXX.md`](doc/ladder-script/BIP-XXXX.md) (pre-draft — see file for status)
- **Tools, engine source, website:** [github.com/defenwycke/bitcoin-ladder-script](https://github.com/defenwycke/bitcoin-ladder-script)

Ladder Script-specific code lives under [`src/rung/`](src/rung/) and is
being extracted into a standalone `libladder` library so the rest of the
fork carries only thin integration shims. Functional tests are at
[`test/functional/feature_rung_*.py`](test/functional/) and
[`test/functional/feature_qabi.py`](test/functional/feature_qabi.py).

Branches other than `ladder-script` (e.g. `feature/buds`, `feature/exorcism`,
`feature/reaper`, `feature/shroud`) are unrelated experiments on vanilla
v30.0 and are not part of this project.

This is **research-stage** protocol work on a private signet — not for
mainnet, not for real money.

The remainder of this README is the upstream Bitcoin Core text.

---

Bitcoin Core integration/staging tree
=====================================

https://bitcoincore.org

For an immediately usable, binary version of the Bitcoin Core software, see
https://bitcoincore.org/en/download/.

What is Bitcoin Core?
---------------------

Bitcoin Core connects to the Bitcoin peer-to-peer network to download and fully
validate blocks and transactions. It also includes a wallet and graphical user
interface, which can be optionally built.

Further information about Bitcoin Core is available in the [doc folder](/doc).

License
-------

Bitcoin Core is released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see https://opensource.org/license/MIT.

Development Process
-------------------

The `master` branch is regularly built (see `doc/build-*.md` for instructions) and tested, but it is not guaranteed to be
completely stable. [Tags](https://github.com/bitcoin/bitcoin/tags) are created
regularly from release branches to indicate new official, stable release versions of Bitcoin Core.

The https://github.com/bitcoin-core/gui repository is used exclusively for the
development of the GUI. Its master branch is identical in all monotree
repositories. Release branches and tags do not exist, so please do not fork
that repository unless it is for development reasons.

The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md)
and useful hints for developers can be found in [doc/developer-notes.md](doc/developer-notes.md).

Testing
-------

Testing and code review is the bottleneck for development; we get more pull
requests than we can review and test on short notice. Please be patient and help out by testing
other people's pull requests, and remember this is a security-critical project where any mistake might cost people
lots of money.

### Automated Testing

Developers are strongly encouraged to write [unit tests](src/test/README.md) for new code, and to
submit new unit tests for old code. Unit tests can be compiled and run
(assuming they weren't disabled during the generation of the build system) with: `ctest`. Further details on running
and extending unit tests can be found in [/src/test/README.md](/src/test/README.md).

There are also [regression and integration tests](/test), written
in Python.
These tests can be run (if the [test dependencies](/test) are installed) with: `build/test/functional/test_runner.py`
(assuming `build` is your build directory).

The CI (Continuous Integration) systems make sure that every pull request is tested on Windows, Linux, and macOS.
The CI must pass on all commits before merge to avoid unrelated CI failures on new pull requests.

### Manual Quality Assurance (QA) Testing

Changes should be tested by somebody other than the developer who wrote the
code. This is especially important for large or high-risk changes. It is useful
to add a test plan to the pull request description if testing the changes is
not straightforward.

Translations
------------

Changes to translations as well as new translations can be submitted to
[Bitcoin Core's Transifex page](https://explore.transifex.com/bitcoin/bitcoin/).

Translations are periodically pulled from Transifex and merged into the git repository. See the
[translation process](doc/translation_process.md) for details on how this works.

**Important**: We do not accept translation changes as GitHub pull requests because the next
pull from Transifex would automatically overwrite them again.
