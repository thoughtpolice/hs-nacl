module Stream
       ( tests -- :: Int -> Tests
       ) where
import           Control.Monad
import           Data.Bits
import           Data.ByteString          (ByteString)
import qualified Data.ByteString          as S

import           Crypto.Encrypt.Stream
import           Crypto.Key
import           Crypto.Nonce

import           Test.QuickCheck
import           Util

--------------------------------------------------------------------------------
-- Streaming encryption

streamProp :: (SecretKey Stream -> Nonce Stream -> Bool) -> Property
streamProp k = ioProperty $ liftM2 k randomKey randomNonce

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
  [ ("xsalsa20 roundtrip",        wrap roundtrip)
  , ("xsalsa20 stream/enc equiv", wrap streamXor)
  ]
  where
    wrap :: Testable prop => prop -> IO (Bool, Int)
    wrap = mktest ntests
