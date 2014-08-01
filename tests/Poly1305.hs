{-# OPTIONS_GHC -fno-warn-orphans #-}
module Poly1305
       ( tests -- :: Int -> Tests
       ) where
import           Control.Monad
import           Data.ByteString     (ByteString)
import qualified Data.ByteString     as S

import           Crypto.Key
import           Crypto.MAC.Poly1305

import           Test.QuickCheck
import           Util

--------------------------------------------------------------------------------
-- Orphans

newtype K2 = K2 ByteString deriving Show
instance Arbitrary K2 where
  arbitrary = K2 `liftM` (arbitrary `suchThat` (\x -> S.length x == 32))

--------------------------------------------------------------------------------
-- Tests

roundtrip :: K2 -> ByteString -> Bool
roundtrip (K2 k) xs = verify k' (authenticate k' xs) xs
  where k' = SecretKey k

tests :: Int -> Tests
tests ntests =
  [ ("poly1305 roundtrip", wrap roundtrip)
  ]
  where
    wrap :: Testable prop => prop -> IO (Bool, Int)
    wrap = mkArgTest ntests
