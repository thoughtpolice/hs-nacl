module SHA
       ( benchmarks -- :: IO [Benchmark]
       ) where
import           Criterion.Main
import           Crypto.Hash.SHA

import qualified Data.ByteString as B

import           Util            ()

benchmarks :: IO [Benchmark]
benchmarks = return
  [ bench "sha256" $ nf sha256 (B.replicate 512 3)
  , bench "sha512" $ nf sha512 (B.replicate 512 3)
  ]
