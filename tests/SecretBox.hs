module SecretBox
       ( tests -- :: Int -> Tests
       ) where
import           Control.Monad
import           Data.ByteString          (ByteString)

import           Crypto.Encrypt.SecretBox
import           Crypto.Key
import           Crypto.Nonce

import           Test.QuickCheck
import           Util

--------------------------------------------------------------------------------
-- Authenticated secret-key encryption

secretboxProp :: (SecretKey SecretBox -> Nonce SecretBox -> Bool) -> Property
secretboxProp k = ioProperty $ liftM2 k randomKey randomNonce

roundtrip :: ByteString -> Property
roundtrip xs
  = secretboxProp $ \key nonce ->
  let enc = encrypt nonce xs key
      dec = decrypt nonce enc key
  in maybe False (== xs) dec

tests :: Int -> Tests
tests ntests =
  [ ("xsalsa20poly1305 roundtrip", wrap roundtrip)
  ]
  where
    wrap :: Testable prop => prop -> IO (Bool, Int)
    wrap = mkArgTest ntests
