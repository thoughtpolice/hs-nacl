{-# LANGUAGE EmptyDataDecls           #-}
{-# LANGUAGE ForeignFunctionInterface #-}
-- |
-- Module      : Crypto.DH.Curve25519
-- Copyright   : (c) Austin Seipp 2013
-- License     : MIT
--
-- Maintainer  : aseipp@pobox.com
-- Stability   : experimental
-- Portability : portable
--
-- This module provides bindings to the Curve25519 Diffie-Hellman
-- function. The underlying implementation uses the @ref@
-- implementation of curve25519 from SUPERCOP, and should be
-- relatively fast.
--
-- For more information visit <http://cr.yp.to/ecdh.html>
--
-- This module is intended to be imported @qualified@ to avoid name
-- clashes with other cryptographic primitives, e.g.
--
-- > import qualified Crypto.Hash.Curve25519 as Curve25519
--
module Crypto.DH.Curve25519
       ( -- * Introduction
         -- $intro

         -- * Security model
         -- $securitymodel

         -- * Types
         Curve25519

         -- * Key creation
       , createKeypair -- :: IO (PublicKey Curve25519, SecretKey Curve25519)

         -- * Computing shared secrets
       , curve25519    -- :: SecretKey Curve25519 -> PublicKey Curve25519 -> ByteString
       ) where
import           Foreign.C.Types
import           Foreign.ForeignPtr       (withForeignPtr)
import           Foreign.Ptr

import           System.IO.Unsafe         (unsafePerformIO)

import           Data.ByteString          as S
import           Data.ByteString.Internal as SI
import           Data.ByteString.Unsafe   as SU
import           Data.Word

import           Crypto.Key

-- $setup
-- >>> import Control.Monad
-- >>> import Test.QuickCheck
-- >>> import Test.QuickCheck.Property
-- >>> let prop k = morallyDubiousIOProperty $ liftM2 k createKeypair createKeypair

-- $intro
--
-- This module provides an interface to the curve25519 Diffie-Hellman
-- function. Diffie-Hellman is a way of computing /shared secrets/
-- between two parties, given /public/ information.
--
-- In laymans terms, given a @'PublicKey'@ from someone else and your
-- own @'SecretKey'@, @'curve25519'@ will compute a shared secret
-- between you two. This same secret can be computed with the inverse
-- key set.
--
-- So, given a set of keys for Bob, and a set of keys for Alice, they
-- can compute a shared secret:
--
-- >>> (alicePk, aliceSk) <- createKeypair
-- >>> (bobPk,   bobSk)   <- createKeypair
-- >>> curve25519 aliceSk bobPk == curve25519 bobSk alicePk
-- True

-- $securitymodel
--
-- The @'curve25519'@ function is an implementation of the well-known
-- \"Diffie-Hellman function\", a way of computing shared secrets
-- between two parties.
--
-- This function is conjectured to be strong. For background see
-- Bernstein, \"Curve25519: new Diffie-Hellman speed records,\"
-- Lecture Notes in Computer Science 3958 (2006), 207–228,
-- <http://cr.yp.to/papers.html#curve25519>.
--
-- The underlying primitive is the function
-- @crypto_scalarmult_curve25519@ specified in \"Cryptography in
-- NaCl\", Sections 2, 3, and 4:
-- <http://cr.yp.to/highspeed/naclcrypto-20090310.pdf>

--------------------------------------------------------------------------------

-- | A phantom type for representing types related to Curve25519 key
-- exchange.
data Curve25519

-- | Randomly generate a public and private key for computing a shared
-- secret.
createKeypair :: IO (PublicKey Curve25519, SecretKey Curve25519)
createKeypair = do
  pk <- SI.mallocByteString cryptoDhPUBLICKEYBYTES
  sk <- SI.mallocByteString cryptoDhSECRETKEYBYTES

  _ <- withForeignPtr pk $ \ppk -> do
    _ <- withForeignPtr sk $ \psk ->
      c_crypto_dh_keypair ppk psk >> return ()
    return ()

  return (PublicKey $ SI.fromForeignPtr pk 0 cryptoDhPUBLICKEYBYTES,
          SecretKey $ SI.fromForeignPtr sk 0 cryptoDhSECRETKEYBYTES)

-- | Compute the shared secret between two parties. Given two keys
-- created with @'createKeypair'@, @'curve25519' sk pk@ computes a
-- shared secret between your secret key and the second parties'
-- public key.
--
-- Given the inverse pair of keys (that is, the second parties' secret
-- key and your public key) then @'curve25519' sk pk@ will compute the
-- same shared secret:
--
-- prop> prop $ \(p1,s2) (p2,s1) -> curve25519 s1 p1 == curve25519 s2 p2
curve25519 :: SecretKey Curve25519 -> PublicKey Curve25519 -> ByteString
curve25519 (SecretKey sk) (PublicKey pk) =
  unsafePerformIO . SU.unsafeUseAsCString sk $ \psk ->
    SU.unsafeUseAsCString pk $ \ppk ->
      SI.create cryptoDhBYTES $ \out ->
        c_crypto_dh out ppk psk >> return ()
{-# INLINE curve25519 #-}

--
-- FFI DH binding
--

cryptoDhPUBLICKEYBYTES :: Int
cryptoDhPUBLICKEYBYTES = 32

cryptoDhSECRETKEYBYTES :: Int
cryptoDhSECRETKEYBYTES = 32

cryptoDhBYTES :: Int
cryptoDhBYTES = 32

foreign import ccall unsafe "curve25519_dh_keypair"
  c_crypto_dh_keypair :: Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "curve25519_dh"
  c_crypto_dh :: Ptr Word8 -> Ptr CChar -> Ptr CChar -> IO CInt
