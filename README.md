# Drongo

Drongo is a Java Bitcoin library built mainly to support [Sparrow Wallet](https://sparrowwallet.com).

## This fork

The `blake2b` branch of this repository supports [Sparrow
(BLAKE2b)](https://github.com/paulscode/sparrow), which follows the side of the 2026 mainnet split
that changed its proof of work at height 961640. It adds the 164 byte block header, the BLAKE2b block
hash, the one-off difficulty shift at the activation height, and the unified opt-in signature hash
that carries replay protection on that chain.

It is not upstream Drongo. Report issues against it, and any of the changes above, on the [Sparrow
(BLAKE2b)](https://github.com/paulscode/sparrow/issues) repository rather than here or upstream, so
that a fix and a release can be coordinated. Anything that reproduces on upstream Drongo belongs
[upstream](https://github.com/sparrowwallet/drongo).

## Building

Drongo can be built with

`./gradlew jar`

## License

Drongo is licensed under the Apache 2 software licence.

## Credits

Drongo was inspired by (and is in part derived from) the [bitcoinj](https://bitcoinj.org) Bitcoin library.
