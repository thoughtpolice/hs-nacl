module BLAKE2
       ( benchmarks -- :: IO [Benchmark]
       ) where
import           Criterion.Main
import           Crypto.Hash.BLAKE2

import qualified Data.ByteString    as B

import           Util               ()

benchmarks :: IO [Benchmark]
benchmarks = return
  [ bench "blake2b"  $ nf blake2b  (B.pack [1..512])
  , bench "blake2bp" $ nf blake2bp (B.pack [1..512])
  , bench "blake2s"  $ nf blake2s  (B.pack [1..512])
  , bench "blake2sp" $ nf blake2sp (B.pack [1..512])
  ]
