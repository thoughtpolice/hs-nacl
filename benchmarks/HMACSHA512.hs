{-# OPTIONS_GHC -fno-warn-orphans #-}
module HMACSHA512
       ( benchmarks -- :: IO [Benchmark]
       ) where
import           Criterion.Main
import           Crypto.HMAC.SHA512
import           Crypto.Key

import           Control.DeepSeq
import qualified Data.ByteString    as B

import           Util               ()

instance NFData Auth

benchmarks :: IO [Benchmark]
benchmarks = do
  let dummy = B.replicate 512 3
      k     = SecretKey (B.replicate 32 3)
      msg   = authenticate k dummy
  return [ bench "authenticate" $ nf (authenticate k) dummy
         , bench "verify"       $ nf (verify k)       msg
         , bench "roundtrip"    $ nf (roundtrip k)    dummy
         ]

roundtrip :: SecretKey HMACSHA512 -> B.ByteString -> Bool
roundtrip k xs = verify k (authenticate k xs) xs
