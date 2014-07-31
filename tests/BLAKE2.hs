{-# LANGUAGE OverloadedStrings #-}

module BLAKE2
       ( tests -- :: Int -> Tests
       ) where
import           Data.ByteString        (ByteString)
import qualified Data.ByteString        as S
import           Data.ByteString.Base16

import           Crypto.Hash.BLAKE2

import           Test.QuickCheck
import           Util

--------------------------------------------------------------------------------
-- Hashing

pure2s, length2s, pure2sp, length2sp, pure2b, length2b, pure2bp, length2bp
  :: ByteString -> Bool

pure2s   xs = blake2s xs == blake2s xs
length2s xs = S.length (blake2s xs) == 32

pure2sp   xs = blake2sp xs == blake2sp xs
length2sp xs = S.length (blake2sp xs) == 32

pure2b   xs = blake2b xs == blake2b xs
length2b xs = S.length (blake2b xs) == 64

pure2bp   xs = blake2bp xs == blake2bp xs
length2bp xs = S.length (blake2bp xs) == 64

vector2s, vector2sp, vector2b, vector2bp :: Bool

vector2s = blake2s plainText == expectation
  where
    plainText =
      "Yesterday I was clever, so I wanted to change the world. Today I am wise\
      \, so I am changing myself."
    expectation = (fst . decode)
      "f08b22a29eed644276bf25bc32de74d7fc4cb5d557666efae9b262ef566ac572"

vector2sp = blake2sp plainText == expectation
  where
    plainText =
      "Anarchism is the radical notion that other people are not your property."
    expectation = (fst . decode)
      "2d9942113a41aaa26befcc9906607869c06285a5112cf4803b1befa49c1cbdd9"

vector2b = blake2b plainText == expectation
  where
    plainText =
      "When buying and selling are controlled by legislation, the first things \
      \to be bought and sold are legislators."
    expectation = (fst . decode)
      "e75d0b0e5dfe97c7724bc052376d6bfba7ae77c0b06a988a0ab35934c86ee3bc\
      \eebb6dafc2dbb7a002b5284c2ebd71cc369176682aa2517ad1b5dfdaa0e4b62c"

vector2bp = blake2bp plainText == expectation
  where
    plainText =
      "There is nothing noble in being superior to your fellow man; true \
      \nobility is being superior to your former self."
    expectation = (fst . decode)
      "d072a4d03ef16c4fe067580f7c495f9e2432e110de1858bda44991558c7fff0e\
      \320efe983136ad3c157cfe83533509559f684684dac5aeb1456a7148ccc73753"

tests :: Int -> Tests
tests ntests =
  [ ("blake2s  purity", wrapArg pure2s)
  , ("blake2s  length", wrapArg length2s)
  , ("blake2s  vector", wrap    vector2s)
  , ("blake2sp purity", wrapArg pure2sp)
  , ("blake2sp length", wrapArg length2sp)
  , ("blake2sp vector", wrap    vector2sp)
  , ("blake2b  purity", wrapArg pure2b)
  , ("blake2b  length", wrapArg length2b)
  , ("blake2b  vector", wrap    vector2b)
  , ("blake2bp purity", wrapArg pure2bp)
  , ("blake2bp length", wrapArg length2bp)
  , ("blake2bp vector", wrap    vector2bp)
  ]
  where
    wrap, wrapArg :: Testable prop => prop -> IO (Bool, Int)
    wrap = mkTest
    wrapArg = mkArgTest ntests
