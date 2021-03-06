{-# LANGUAGE EmptyDataDecls           #-}
{-# LANGUAGE ForeignFunctionInterface #-}
-- |
-- Module      : Crypto.Sign.Ed25519
-- Copyright   : (c) Austin Seipp 2013
-- License     : BSD3
--
-- Maintainer  : aseipp@pobox.com
-- Stability   : experimental
-- Portability : portable
--
-- This module provides bindings to the ed25519 public-key signature
-- system, including detached signatures. The underlying
-- implementation uses the @ref10@ implementation of ed25519 from
-- SUPERCOP, and should be relatively fast.
--
-- For more information (including how to get a copy of the software)
-- visit <http://ed25519.cr.yp.to>.
--
-- This module is intended to be imported @qualified@ to avoid name
-- clashes with other cryptographic primitives, e.g.
--
-- > import qualified Crypto.Sign.Ed25519 as Ed25519
--
module Crypto.Sign.Ed25519
       ( -- * Security model
         -- $securitymodel

         -- * Keypair creation
         Ed25519
       , createKeypair       -- :: IO (PublicKey Ed25519, SecretKey Ed25519)
         -- * Signing and verifying messages
       , sign                -- :: SecretKey Ed25519 -> ByteString -> ByteString
       , verify              -- :: PublicKey Ed25519 -> ByteString -> Bool
         -- * Detached signatures
       , Signature(..)       -- :: *
       , sign'               -- :: SecretKey Ed25519 -> ByteString -> Signature
       , verify'             -- :: PublicKey Ed25519 -> ByteString -> Signature -> Bool
       ) where
import           Foreign.C.Types
import           Foreign.ForeignPtr       (withForeignPtr)
import           Foreign.Marshal.Alloc    (alloca)
import           Foreign.Ptr
import           Foreign.Storable

import           System.IO.Unsafe         (unsafePerformIO)

import           Data.ByteString          as S
import           Data.ByteString.Internal as SI
import           Data.ByteString.Unsafe   as SU
import           Data.Word

import           Crypto.Key

-- $setup
-- >>> import qualified Data.ByteString as B
-- >>> let xs = B.pack [0..15]

-- $securitymodel
--
-- The @'sign'@ and @'sign''@ functions are designed to meet the standard
-- notion of unforgeability for a public-key signature scheme under
-- chosen-message attacks.

--------------------------------------------------------------------------------

-- | A phantom type for representing types related to signing.
data Ed25519

-- | Randomly generate a public and private key for doing
-- authenticated signing and verification.
createKeypair :: IO (PublicKey Ed25519, SecretKey Ed25519)
createKeypair = do
  pk <- SI.mallocByteString cryptoSignPUBLICKEYBYTES
  sk <- SI.mallocByteString cryptoSignSECRETKEYBYTES

  _ <- withForeignPtr pk $ \ppk -> do
    _ <- withForeignPtr sk $ \psk -> do
      _ <- c_crypto_sign_keypair ppk psk
      return ()
    return ()

  return (PublicKey $ SI.fromForeignPtr pk 0 cryptoSignPUBLICKEYBYTES,
          SecretKey $ SI.fromForeignPtr sk 0 cryptoSignSECRETKEYBYTES)

--------------------------------------------------------------------------------
-- Main API

-- | Sign a message with a particular @'SecretKey'@.
sign :: SecretKey Ed25519
     -- ^ Signers @'SecretKey'@
     -> ByteString
     -- ^ Input message
     -> ByteString
     -- ^ Resulting signed message
sign (SecretKey sk) xs =
  unsafePerformIO . SU.unsafeUseAsCStringLen xs $ \(mstr,mlen) ->
    SU.unsafeUseAsCString sk $ \psk ->
      SI.createAndTrim (mlen+cryptoSignBYTES) $ \out ->
        alloca $ \smlen -> do
          _ <- c_crypto_sign out smlen mstr (fromIntegral mlen) psk
          fromIntegral `fmap` peek smlen
{-# INLINE sign #-}

-- | Verifies a signed message against a @'PublicKey'@.
--
-- >>> (pk,sk) <- createKeypair
-- >>> verify pk (sign sk xs)
-- True
verify :: PublicKey Ed25519
       -- ^ Signers @'PublicKey'@
       -> ByteString
       -- ^ Signed message
       -> Bool
       -- ^ Verification check
verify (PublicKey pk) xs =
  unsafePerformIO . SU.unsafeUseAsCStringLen xs $ \(smstr,smlen) ->
    SU.unsafeUseAsCString pk $ \ppk ->
      alloca $ \pmlen -> do
        out <- SI.mallocByteString smlen
        r <- withForeignPtr out $ \pout ->
               c_crypto_sign_open pout pmlen smstr (fromIntegral smlen) ppk

        return (r == 0)
{-# INLINE verify #-}

--------------------------------------------------------------------------------
-- Detached signature support

-- | A @'Signature'@ which is detached from the message it signed.
newtype Signature = Signature { unSignature :: ByteString }
        deriving (Eq, Show, Ord)

-- | Sign a message with a particular @'SecretKey'@, only returning
-- the signature without the message.
sign' :: SecretKey Ed25519
      -- ^ Signers secret key
      -> ByteString
      -- ^ Input message
      -> Signature
      -- ^ Message signature, without the message
sign' sk xs =
  let sm = sign sk xs
      l  = S.length sm
  in Signature $! S.take (l - S.length xs) sm
{-# INLINE sign' #-}

-- | Verify a message with a detached @'Signature'@, for a given
-- 'PublicKey'.
verify' :: PublicKey Ed25519
        -- ^ Signers public key
        -> ByteString
        -- ^ Input message, without signature
        -> Signature
        -- ^ Message signature
        -> Bool
verify' pk xs (Signature sig) = verify pk (sig `S.append` xs)
{-# INLINE verify' #-}

--
-- FFI signature binding
--

cryptoSignSECRETKEYBYTES :: Int
cryptoSignSECRETKEYBYTES = 64

cryptoSignPUBLICKEYBYTES :: Int
cryptoSignPUBLICKEYBYTES = 32

cryptoSignBYTES :: Int
cryptoSignBYTES = 64

foreign import ccall unsafe "ed25519_sign_keypair"
  c_crypto_sign_keypair :: Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "ed25519_sign"
  c_crypto_sign :: Ptr Word8 -> Ptr CULLong ->
                   Ptr CChar -> CULLong -> Ptr CChar -> IO CULLong

foreign import ccall unsafe "ed25519_sign_open"
  c_crypto_sign_open :: Ptr Word8 -> Ptr CULLong ->
                        Ptr CChar -> CULLong -> Ptr CChar -> IO CInt
