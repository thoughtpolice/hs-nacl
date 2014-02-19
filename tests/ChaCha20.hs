module ChaCha20
       ( tests -- :: Int -> Tests
       ) where
import           Control.Monad
import           Data.Bits
import           Data.ByteString          (ByteString)
import qualified Data.ByteString          as S

import           Crypto.Encrypt.Stream.ChaCha20
import           Crypto.Key
import           Crypto.Nonce

import           Test.QuickCheck
import           Test.QuickCheck.Property (morallyDubiousIOProperty)
import           Util

--------------------------------------------------------------------------------
-- streaming encryption

streamProp :: (SecretKey ChaCha20 -> Nonce ChaCha20 -> Bool) -> Property
streamProp k = morallyDubiousIOProperty $ liftM2 k randomKey randomNonce

roundtrip :: ByteString -> Property
roundtrip xs
  = streamProp $ \key nonce ->
  let enc = encrypt nonce xs key
      dec = decrypt nonce enc key
  in dec == xs

streamXor :: ByteString -> Property
streamXor xs
  = streamProp $ \key nonce ->
  let
      xorBS x1 x2 = S.pack $ S.zipWith xor x1 x2
      enc = encrypt nonce xs key
      str = stream nonce (S.length xs) key
  in enc == (str `xorBS` xs)

tests :: Int -> Tests
tests ntests =
  [ ("chacha20 roundtrip",        wrap roundtrip)
  , ("chacha20 stream/enc equiv", wrap streamXor)
  ]
  where
    wrap :: Testable prop => prop -> IO (Bool, Int)
    wrap = mktest ntests
