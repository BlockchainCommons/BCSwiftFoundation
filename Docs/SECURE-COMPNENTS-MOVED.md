#  Secure Components and Crypto-Envelope have Moved

Blockchain Commons Secure Components, including `Envelope`, have moved to [their own respository](https://github.com/BlockchainCommons/BCSwiftSecureComponents), which is now a dependency of this repository. This repository focuses more on solutions specifically for cryptocurrency, while Secure Components focuses on tools that are more broadly applicable to not only cryptocurrency but also cryptography and semantic graphs.

Use of this package now re-exports `BCSwiftSecureComponents`, so by adding this package to your project and adding `import BCFoundation` to your project files, you also gain access to the APIs in `BCSwiftSecureComponents`
