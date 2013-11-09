module Random
       ( benchmarks -- :: IO [Benchmark]
       ) where
import           Criterion.Main
import           System.Crypto.Random

import           Util              ()

benchmarks :: IO [Benchmark]
benchmarks = return
  [ bench "randombytes/32" $ nfIO (randombytes 32)
  , bench "randombytes/64" $ nfIO (randombytes 64)
  ]
