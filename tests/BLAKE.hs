module BLAKE
       ( tests -- :: Int -> Tests
       ) where
import           Data.ByteString   (ByteString)
import qualified Data.ByteString   as S

import           Crypto.Hash.BLAKE

import           Test.QuickCheck
import           Util

--------------------------------------------------------------------------------
-- Hashing

pure256 :: ByteString -> Bool
pure256 xs = blake256 xs == blake256 xs

pure512 :: ByteString -> Bool
pure512 xs = blake512 xs == blake512 xs

length256 :: ByteString -> Bool
length256 xs = S.length (blake256 xs) == 32

length512 :: ByteString -> Bool
length512 xs = S.length (blake512 xs) == 64


tests :: Int -> Tests
tests ntests =
  [ ("blake256 purity", wrap pure256)
  , ("blake256 length", wrap length256)
  , ("blake512 purity", wrap pure512)
  , ("blake512 length", wrap length512)
  ]
  where
    wrap :: Testable prop => prop -> IO (Bool, Int)
    wrap = mktest ntests
