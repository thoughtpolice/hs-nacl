{-# OPTIONS_GHC -fno-warn-orphans #-}
module Ed25519
       ( benchmarks -- :: IO [Benchmark]
       ) where
import           Criterion.Main
import           Crypto.Sign.Ed25519

import           Control.DeepSeq
import qualified Data.ByteString     as B

import           Util                ()

instance NFData SecretKey
instance NFData PublicKey

benchmarks :: IO [Benchmark]
benchmarks = do
  keys@(pk,sk) <- createKeypair
  let dummy = B.pack [1..512]
      msg = sign sk dummy
  return [ bench "keypair"   $ nfIO createKeypair
         , bench "sign"      $ nf (sign sk)        dummy
         , bench "verify"    $ nf (verify pk)      msg
         , bench "roundtrip" $ nf (signBench keys) dummy
         ]

signBench :: (PublicKey, SecretKey) -> B.ByteString -> Bool
signBench (pk, sk) xs = verify pk (sign sk xs)
