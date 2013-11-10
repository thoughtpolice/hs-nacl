{-# OPTIONS_GHC -fno-warn-orphans #-}
module HMACSHA512
       ( tests -- :: Int -> Tests
       ) where
import           Control.Monad
import           Data.ByteString    (ByteString)
import qualified Data.ByteString    as S

import           Crypto.HMAC.SHA512
import           Crypto.Key

import           Test.QuickCheck
import           Util

--------------------------------------------------------------------------------
-- Orphans

newtype K2 = K2 ByteString deriving Show
instance Arbitrary K2 where
  arbitrary = K2 `liftM` (arbitrary `suchThat` (\x -> S.length x == 32))

--------------------------------------------------------------------------------
-- HMAC

roundtrip :: K2 -> ByteString -> Bool
roundtrip (K2 k) xs = verify k' (authenticate k' xs) xs
  where k' = SecretKey k


tests :: Int -> Tests
tests ntests =
  [ ("hmac-sha512256 roundtrip", wrap roundtrip)
  ]
  where
    wrap :: Testable prop => prop -> IO (Bool, Int)
    wrap = mktest ntests
