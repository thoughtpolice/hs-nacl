{-# LANGUAGE OverloadedStrings #-}

module BLAKE
       ( tests -- :: Int -> Tests
       ) where
import           Data.ByteString        (ByteString)
import qualified Data.ByteString        as S
import           Data.ByteString.Base16

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

vector256 :: Bool
vector256 = blake256 plainText == expectation
  where
    plainText =
      "They must find it difficult -- those who take authority as the truth, \
      \rather than truth as the authority."
    expectation = (fst . decode)
      "fb7d7ccae6d7387c90701f9a4c1a0364e5b917bfe2b95272724475a109db2d96"

vector512 :: Bool
vector512 = blake512 plainText == expectation
  where
    plainText = "It's dangerous to be right when government is wrong."
    expectation = (fst . decode)
      "5e5babfd97122e28db6646326797ad3d43efda3985e25f1b27b0da614ae63334\
      \e159a5d96784002ba1f769c43e13f71d37c1df910700fcf65b17a13ce344352a"

tests :: Int -> Tests
tests ntests =
  [ ("blake256 purity", wrapArg pure256)
  , ("blake256 length", wrapArg length256)
  , ("blake256 vector", wrap    vector256)
  , ("blake512 purity", wrapArg pure512)
  , ("blake512 length", wrapArg length512)
  , ("blake512 vector", wrap    vector512)
  ]
  where
    wrap, wrapArg :: Testable prop => prop -> IO (Bool, Int)
    wrap = mkTest
    wrapArg = mkArgTest ntests
