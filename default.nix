{ haskellPackages ? (import <nixpkgs> {}).haskellPackages }:
let
  inherit (haskellPackages) cabal cabalInstall_1_18_0_2
    base64Bytestring filepath   # Haskell dependencies here
    QuickCheck hlint doctest    # Test dependencies here
    criterion deepseq;          # Benchmark dependencies here

in cabal.mkDerivation (self: {
  pname = "nacl";
  version = "0.0.0.0";
  src = ./.;
  isLibrary = true;
  buildDepends = [ base64Bytestring filepath ];
  testDepends  = [ QuickCheck hlint doctest ];
  buildTools   = [ cabalInstall_1_18_0_2 ];
  enableSplitObjs = false;

  meta = {
    homepage    = "http://github.com/thoughtpolice/hs-nacl";
    description = "Modern Haskell Cryptography";
    license     = self.stdenv.lib.licenses.bsd3;
    platforms   = self.ghc.meta.platforms;
  };
})
