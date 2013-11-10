module SecretBox
       ( benchmarks -- :: IO [Benchmark]
       ) where
import           Criterion.Main
import           Crypto.Encrypt.SecretBox
import           Crypto.Key
import           Crypto.Nonce

import           Data.ByteString          (ByteString)
import qualified Data.ByteString          as B

import           Util                     ()

benchmarks :: IO [Benchmark]
benchmarks = do
  key   <- randomKey
  nonce <- randomNonce
  let dummy512 = B.pack [1..512]
  return [ bench "roundtrip 512" $ nf (roundtrip key nonce) dummy512
         ]

roundtrip :: SecretKey SecretBox -> Nonce SecretBox -> ByteString -> Bool
roundtrip key nonce xs =
  let enc = encrypt nonce xs key
      dec = decrypt nonce enc key
  in maybe False (== xs) dec
