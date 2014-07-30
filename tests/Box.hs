module Box
       ( tests -- :: Int -> Tests
       ) where
import           Data.ByteString          (ByteString)

import           Crypto.Encrypt.Box
import           Crypto.Key
import           Crypto.Nonce

import           Test.QuickCheck
import           Util

--------------------------------------------------------------------------------
-- Authenticated secret-key encryption

type KP = (PublicKey Box, SecretKey Box)

secretboxProp :: (KP -> KP -> Nonce Box -> Bool) -> Property
secretboxProp k = ioProperty $ do
  kp1   <- createKeypair
  kp2   <- createKeypair
  nonce <- randomNonce
  return (k kp1 kp2 nonce)

roundtrip :: ByteString -> Property
roundtrip xs
  = secretboxProp $ \(pk1,sk1) (pk2,sk2) nonce ->
  let enc = encrypt nonce xs  pk1 sk2
      dec = decrypt nonce enc pk2 sk1
  in maybe False (== xs) dec

roundtripNM :: ByteString -> Property
roundtripNM xs
  = secretboxProp $ \(pk1,sk1) (pk2,sk2) nonce ->
  let nm1 = createNM pk1 sk2
      nm2 = createNM pk2 sk1
      enc = encryptNM nm1 nonce xs
      dec = decryptNM nm2 nonce enc
  in maybe False (== xs) dec

tests :: Int -> Tests
tests ntests =
  [ ("curve25519xsalsa20poly1305 roundtrip",    wrap roundtrip)
  , ("curve25519xsalsa20poly1305-NM roundtrip", wrap roundtripNM)
  ]
  where
    wrap :: Testable prop => prop -> IO (Bool, Int)
    wrap = mktest ntests
