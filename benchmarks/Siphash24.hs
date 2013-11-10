{-# OPTIONS_GHC -fno-warn-orphans #-}
module Siphash24
       ( benchmarks -- :: IO [Benchmark]
       ) where
import           Criterion.Main
import           Crypto.Key
import           Crypto.MAC.Siphash24

import           Control.DeepSeq
import qualified Data.ByteString      as B

import           Util                 ()

instance NFData Auth

benchmarks :: IO [Benchmark]
benchmarks = do
  let dummy = B.pack [1..512]
      k     = SecretKey (B.pack [0..15])
      msg   = authenticate k dummy
  return [ bench "authenticate" $ nf (authenticate k) dummy
         , bench "verify"       $ nf (verify k)       msg
         , bench "roundtrip"    $ nf (roundtrip k)    dummy
         ]

roundtrip :: SecretKey Siphash24 -> B.ByteString -> Bool
roundtrip k xs = verify k (authenticate k xs) xs
