{-# LANGUAGE EmptyDataDecls           #-}
{-# LANGUAGE ForeignFunctionInterface #-}
-- |
-- Module      : Crypto.MAC.Poly1305
-- Copyright   : (c) Austin Seipp 2013
-- License     : MIT
--
-- Maintainer  : aseipp@pobox.com
-- Stability   : experimental
-- Portability : portable
--
-- This module provides bindings to the poly1305
-- message-authentication code (MAC). The underlying implementation is
-- the @ref@ code of @poly1305@ from SUPERCOP, and should be
-- relatively fast.
--
-- For more information visit <http://cr.yp.to/mac.html>.
--
-- This module is intended to be imported @qualified@ to avoid name
-- clashes with other cryptographic primitives, e.g.
--
-- > import qualified Crypto.MAC.Poly1305 as Poly1305
--
module Crypto.MAC.Poly1305
       ( -- * Security model
         -- $securitymodel

         -- * Types
         Poly1305     -- :: *
       , Auth(..)     -- :: *

         -- * Key creation
       , randomKey    -- :: IO (SecretKey Poly1305)

         -- * One-time authentication
       , authenticate -- :: SecretKey Poly1305 -> ByteString -> Auth
       , verify       -- :: SecretKey Poly1305 -> Auth -> ByteString -> Bool
       ) where
import           Data.Word
import           Foreign.C.Types
import           Foreign.Ptr

import           System.IO.Unsafe         (unsafePerformIO)

import           Data.ByteString          (ByteString)
import           Data.ByteString.Internal (create)
import           Data.ByteString.Unsafe

import           Crypto.Key
import           System.Crypto.Random

-- $securitymodel
--
-- The @'authenticate'@ function, viewed as a function of the message
-- for a uniform random key, is designed to meet the standard notion
-- of unforgeability after a single message. After the sender
-- authenticates one message, an attacker cannot find authenticators
-- for any other messages.
--
-- The sender must not use @'authenticate'@ to authenticate more than
-- one message under the same key. Authenticators for two messages
-- under the same key should be expected to reveal enough information
-- to allow forgeries of authenticators on other messages.

data Poly1305

-- | Generate a random key for performing encryption.
randomKey :: IO (SecretKey Poly1305)
randomKey = SecretKey `fmap` randombytes onetimeauthKEYBYTES

-- | An authenticator.
newtype Auth = Auth { unAuth :: ByteString }
  deriving (Eq, Show, Ord)

-- | @'authenticate' k m@ authenticates a message @'m'@ using a secret
-- @'Key'@ @k@ and returns the authenticator, @'Auth'@.
authenticate :: SecretKey Poly1305
             -- ^ Secret key
             -> ByteString
             -- ^ Message
             -> Auth
             -- ^ Authenticator
authenticate (SecretKey k) msg =
  Auth . unsafePerformIO . create onetimeauthBYTES $ \out ->
    unsafeUseAsCStringLen msg $ \(cstr, clen) ->
      unsafeUseAsCString k $ \pk ->
        c_crypto_onetimeauth out cstr (fromIntegral clen) pk >> return ()
{-# INLINE authenticate #-}

-- | @'verify' k a m@ verifies @a@ is the correct authenticator of @m@
-- under a secret @'Key'@ @k@.
verify :: SecretKey Poly1305
       -- ^ Secret key
       -> Auth
       -- ^ Authenticator returned via 'authenticateOnce'
       -> ByteString
       -- ^ Message
       -> Bool
       -- ^ Result: @True@ if verified, @False@ otherwise
verify (SecretKey k) (Auth auth) msg =
  unsafePerformIO . unsafeUseAsCString auth $ \pauth ->
    unsafeUseAsCStringLen msg $ \(cstr, clen) ->
      unsafeUseAsCString k $ \pk -> do
        b <- c_crypto_onetimeauth_verify pauth cstr (fromIntegral clen) pk
        return (b == 0)
{-# INLINE verify #-}

--
-- FFI mac binding
--

onetimeauthKEYBYTES :: Int
onetimeauthKEYBYTES = 32

onetimeauthBYTES :: Int
onetimeauthBYTES = 16

foreign import ccall unsafe "poly1305_mac"
  c_crypto_onetimeauth :: Ptr Word8 -> Ptr CChar -> CULLong ->
                          Ptr CChar -> IO Int

foreign import ccall unsafe "poly1305_mac_verify"
  c_crypto_onetimeauth_verify :: Ptr CChar -> Ptr CChar -> CULLong ->
                                 Ptr CChar -> IO Int
