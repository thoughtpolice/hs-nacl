{-# OPTIONS_GHC -fno-warn-orphans #-}
module Curve25519
       ( benchmarks -- :: IO [Benchmark]
       ) where
import           Criterion.Main
import           Crypto.DH.Curve25519

import           Control.DeepSeq

import           Util                 ()

instance NFData SecretKey
instance NFData PublicKey

benchmarks :: IO [Benchmark]
benchmarks = do
  keys1@(p1,_s2) <- createKeypair
  keys2@(_p2,s1) <- createKeypair
  return [ bench "createKeypair" $ nfIO createKeypair
         , bench "curve25519"    $ nf (curve25519 s1) p1
         , bench "roundtrip"     $ nf (roundtrip keys1) keys2
         ]

roundtrip :: (PublicKey, SecretKey)
          -> (PublicKey, SecretKey)
          -> Bool
roundtrip (p1,s2) (p2,s1) = curve25519 s1 p1 == curve25519 s2 p2
