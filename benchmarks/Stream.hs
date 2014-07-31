module Stream
       ( benchmarks -- :: IO [Benchmark]
       ) where
import           Criterion.Main
import           Crypto.Encrypt.Stream
import           Crypto.Key
import           Crypto.Nonce

import           Data.ByteString       (ByteString)
import qualified Data.ByteString       as B

import           Util                  ()

benchmarks :: IO [Benchmark]
benchmarks = do
  key   <- randomKey
  nonce <- randomNonce
  let dummy512 = B.replicate 512 3
  return [ bench "roundtrip 512" $ nf (roundtrip key nonce) dummy512
         ]

roundtrip :: SecretKey Stream -> Nonce Stream -> ByteString -> Bool
roundtrip key nonce xs =
  let enc = encrypt nonce xs key
      dec = decrypt nonce enc key
  in dec == enc
