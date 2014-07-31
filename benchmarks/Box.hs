module Box
       ( benchmarks -- :: IO [Benchmark]
       ) where
import           Criterion.Main
import           Crypto.Encrypt.Box
import           Crypto.Key
import           Crypto.Nonce

import           Data.ByteString    (ByteString)
import qualified Data.ByteString    as B

import           Util               ()

type Keypair = (PublicKey Box, SecretKey Box)

benchmarks :: IO [Benchmark]
benchmarks = do
  kp1@(pk1,sk1) <- createKeypair
  kp2@(pk2,sk2) <- createKeypair
  nonce <- randomNonce
  let dummy512 = B.replicate 512 3
      nm1      = createNM pk1 sk2
      nm2      = createNM pk2 sk1
  return [ bgroup "full"
           [ bench "roundtrip 512" $ nf (roundtrip kp1 kp2 nonce) dummy512
           ]
         , bgroup "nm"
           [ bench "roundtrip 512" $ nf (roundtripNM nm1 nm2 nonce) dummy512
           ]
         ]

roundtrip :: Keypair -> Keypair -> Nonce Box -> ByteString -> Bool
roundtrip (pk1,sk1) (pk2,sk2) nonce xs =
  let enc = encrypt nonce xs  pk1 sk2
      dec = decrypt nonce enc pk2 sk1
  in maybe False (== xs) dec

roundtripNM :: NM -> NM -> Nonce Box -> ByteString -> Bool
roundtripNM nm1 nm2 nonce xs =
  let enc = encryptNM nm1 nonce xs
      dec = decryptNM nm2 nonce enc
  in maybe False (== xs) dec
