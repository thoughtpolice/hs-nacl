{-# OPTIONS_GHC -fno-warn-orphans #-}
module Siphash2448
       ( tests -- :: Int -> Tests
       ) where
import           Control.Monad
import           Data.ByteString      (ByteString)
import qualified Data.ByteString      as S

import           Crypto.Key
import qualified Crypto.MAC.Siphash24 as Siphash24
import qualified Crypto.MAC.Siphash48 as Siphash48

import           Test.QuickCheck
import           Util

--------------------------------------------------------------------------------
-- Orphans

newtype K2 = K2 ByteString deriving Show
instance Arbitrary K2 where
  arbitrary = K2 `liftM` (arbitrary `suchThat` (\x -> S.length x == 16))

--------------------------------------------------------------------------------
-- Tests

roundtrip24 :: K2 -> ByteString -> Bool
roundtrip24 (K2 k) xs = Siphash24.verify k' (Siphash24.authenticate k' xs) xs
  where k' = SecretKey k

roundtrip48 :: K2 -> ByteString -> Bool
roundtrip48 (K2 k) xs = Siphash48.verify k' (Siphash48.authenticate k' xs) xs
  where k' = SecretKey k


tests :: Int -> Tests
tests ntests =
  [ ("siphash24 roundtrip", wrap roundtrip24)
  , ("siphash48 roundtrip", wrap roundtrip48)
  ]
  where
    wrap :: Testable prop => prop -> IO (Bool, Int)
    wrap = mkArgTest ntests
