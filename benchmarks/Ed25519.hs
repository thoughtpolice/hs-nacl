{-# OPTIONS_GHC -fno-warn-orphans #-}
module Ed25519
       ( benchmarks -- :: IO [Benchmark]
       ) where
import           Criterion.Main
import           Crypto.Key
import           Crypto.Sign.Ed25519

import           Control.DeepSeq
import qualified Data.ByteString     as B

import           Util                ()

instance NFData (SecretKey t)
instance NFData (PublicKey t)

benchmarks :: IO [Benchmark]
benchmarks = do
  keys@(pk,sk) <- createKeypair
  let dummy = B.replicate 512 3
      msg = sign sk dummy
  return [ bench "keypair"   $ nfIO createKeypair
         , bench "sign"      $ nf (sign sk)        dummy
         , bench "verify"    $ nf (verify pk)      msg
         , bench "roundtrip" $ nf (signBench keys) dummy
         ]

signBench :: (PublicKey Ed25519, SecretKey Ed25519) -> B.ByteString -> Bool
signBench (pk, sk) xs = verify pk (sign sk xs)
