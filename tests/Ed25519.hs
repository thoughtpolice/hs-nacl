{-# OPTIONS_GHC -fno-warn-orphans #-}
module Ed25519
       ( tests -- :: Int -> Tests
       ) where
import           Control.Monad
import           Data.ByteString          (ByteString)
import qualified Data.ByteString          as S

import           Crypto.Key
import           Crypto.Sign.Ed25519

import           Test.QuickCheck
import           Util

--------------------------------------------------------------------------------
-- Signatures

type KP = (PublicKey Ed25519, SecretKey Ed25519)

keypairProp :: (KP -> Bool) -> Property
keypairProp k = ioProperty $ k `liftM` createKeypair

roundtrip :: ByteString -> Property
roundtrip xs
  = keypairProp $ \(pk,sk) -> verify pk (sign sk xs)

roundtrip' :: ByteString -> Property
roundtrip' xs
  = keypairProp $ \(pk,sk) -> verify' pk xs (sign' sk xs)

-- Generally the signature format is '<signature><original message>'
-- and <signature> is of a fixed length (crypto_sign_BYTES), which in
-- ed25519's case is 64. sign' drops the message appended at the end,
-- so we just make sure we have constant length signatures.
signLength :: (ByteString,ByteString) -> Property
signLength (xs,xs2)
  = keypairProp $ \(_,sk) ->
      let s1 = unSignature $ sign' sk xs
          s2 = unSignature $ sign' sk xs2
      in S.length s1 == S.length s2

-- ed25519 has a sig length of 64
signLength2 :: ByteString -> Property
signLength2 xs
  = keypairProp $ \(_,sk) ->
      (64 == S.length (unSignature $ sign' sk xs))


tests :: Int -> Tests
tests ntests =
  [ ("ed25519 roundtrip",        wrap roundtrip)
  , ("ed25519 roundtrip #2",     wrap roundtrip')
  , ("ed25519 signature len",    wrap signLength)
  , ("ed25519 signature len #2", wrap signLength2)
  ]
  where
    wrap :: Testable prop => prop -> IO (Bool, Int)
    wrap = mktest ntests
