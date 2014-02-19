module Main
       ( main  -- :: IO ()
       ) where
import           Control.Monad  (liftM)
import           Criterion.Main (bgroup, defaultMain)

import           BLAKE          (benchmarks)
import           BLAKE2         (benchmarks)
import           Box            (benchmarks)
import           ChaCha20       (benchmarks)
import           Curve25519     (benchmarks)
import           Ed25519        (benchmarks)
import           HMACSHA512     (benchmarks)
import           Nonce          (benchmarks)
import           Poly1305       (benchmarks)
import           Random         (benchmarks)
import           SecretBox      (benchmarks)
import           SHA            (benchmarks)
import           Siphash24      (benchmarks)
import           Siphash48      (benchmarks)
import           Stream         (benchmarks)

main :: IO ()
main = mapM (uncurry bencher) suites >>= defaultMain
  where
    bencher name act = bgroup name `liftM` act
    suites = [ ("BLAKE",            BLAKE.benchmarks)
             , ("BLAKE2",           BLAKE2.benchmarks)
             , ("Box",              Box.benchmarks)
             , ("Curve25519",       Curve25519.benchmarks)
             , ("Ed25519",          Ed25519.benchmarks)
             , ("HMAC-SHA-512-256", HMACSHA512.benchmarks)
             , ("Nonce",            Nonce.benchmarks)
             , ("Poly1305",         Poly1305.benchmarks)
             , ("Random",           Random.benchmarks)
             , ("SecretBox",        SecretBox.benchmarks)
             , ("SHA",              SHA.benchmarks)
             , ("Siphash24",        Siphash24.benchmarks)
             , ("Siphash48",        Siphash48.benchmarks)
             , ("Stream",           Stream.benchmarks)
             , ("ChaCha20",         ChaCha20.benchmarks)
             ]
