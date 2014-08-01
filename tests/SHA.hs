{-# LANGUAGE OverloadedStrings #-}

module SHA
       ( tests -- :: Int -> Tests
       ) where
import           Data.ByteString        (ByteString)
import qualified Data.ByteString        as S
import           Data.ByteString.Base16

import           Crypto.Hash.SHA

import           Test.QuickCheck
import           Util

--------------------------------------------------------------------------------
-- Hashing

pure256 :: ByteString -> Bool
pure256 xs = sha256 xs == sha256 xs

pure512 :: ByteString -> Bool
pure512 xs = sha512 xs == sha512 xs

length256 :: ByteString -> Bool
length256 xs = S.length (sha256 xs) == 32

length512 :: ByteString -> Bool
length512 xs = S.length (sha512 xs) == 64

vector256 :: Bool
vector256 = sha256 plainText == expectation
  where
    plainText =
      "So you think that money is the root of all evil. Have you ever asked \
      \what is the root of all money?"
    expectation = (fst . decode)
      "a27a1a1812b848461d6784e23f4d5ea6dfd2af17a106cd58a98f83bb24077da8"

vector512 :: Bool
vector512 = sha512 plainText == expectation
  where
    plainText =
      "You can ignore reality, but you can not ignore the consequences of \
      \ignoring reality."
    expectation = (fst . decode)
      "84167c8baf28fd5d092b264c94bb490723df71ce2dd17fece09f63704be4c5df\
      \2f880282b57f2655932af89d23a3d3c993c64539b7c7f231c12844b1dc895748"

tests :: Int -> Tests
tests ntests =
  [ ("sha256 purity", wrapArg pure256)
  , ("sha256 length", wrapArg length256)
  , ("sha256 vector", wrap    vector256)
  , ("sha512 purity", wrapArg pure512)
  , ("sha512 length", wrapArg length512)
  , ("sha512 vector", wrap    vector512)
  ]
  where
    wrap, wrapArg :: Testable prop => prop -> IO (Bool, Int)
    wrap = mkTest
    wrapArg = mkArgTest ntests
