{-# OPTIONS_GHC -fno-warn-orphans #-}
module Nonce
       ( benchmarks -- :: IO [Benchmark]
       ) where
import           Criterion.Main
import           Crypto.Encrypt.Box
import           Crypto.Nonce

import           Control.DeepSeq

import           Util               ()

instance NFData Box
instance (Nonces t, NFData t) => NFData (Nonce t)

benchmarks :: IO [Benchmark]
benchmarks = do
  n <- randomNonce :: IO (Nonce Box)
  return [ bench "increment" $ nf incNonce n
         ]
