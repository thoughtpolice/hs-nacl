{-# LANGUAGE ForeignFunctionInterface #-}
-- |
-- Module      : Crypto.MAC.Siphash24
-- Copyright   : (c) Austin Seipp 2013
-- License     : MIT
--
-- Maintainer  : aseipp@pobox.com
-- Stability   : experimental
-- Portability : portable
--
-- This module provides @siphash24@ as a message-authentication code
-- (MAC.) The underlying implementation is the @little@ code of
-- @siphash24@ from SUPERCOP, and should be relatively fast.
--
-- For more information visit <https://131002.net/siphash/>.
--
-- This module is intended to be imported @qualified@ to avoid name
-- clashes with other cryptographic primitives, e.g.
--
-- > import qualified Crypto.MAC.Siphash24 as Siphash24
--
module Crypto.MAC.Siphash24
       ( -- * Security model
         -- $securitymodel

         -- * Types
         Key          -- :: *
       , Auth(..)     -- :: *

         -- * Key creation
       , key          -- :: ByteString -> Maybe Key
       , randomKey    -- :: IO Key

         -- * Authentication
       , authenticate -- :: Key -> ByteString -> Auth
       , verify       -- :: Key -> Auth -> ByteString -> Bool
       ) where
import           Data.Word
import           Foreign.C.Types
import           Foreign.Ptr

import           System.IO.Unsafe         (unsafePerformIO)

import           Data.ByteString          (ByteString)
import qualified Data.ByteString          as S
import           Data.ByteString.Internal (create)
import           Data.ByteString.Unsafe

import           System.Crypto.Random

-- $securitymodel
--
-- The @'authenticate'@ function, viewed as a function of the message
-- for a uniform random key, is designed to meet the standard notion
-- of unforgeability. This means that an attacker cannot find
-- authenticators for any messages not authenticated by the sender,
-- even if the attacker has adaptively influenced the messages
-- authenticated by the sender. For a formal definition see, e.g.,
-- Section 2.4 of Bellare, Kilian, and Rogaway, \"The security of the
-- cipher block chaining message authentication code,\" Journal of
-- Computer and System Sciences 61 (2000), 362–399;
-- <http://www-cse.ucsd.edu/~mihir/papers/cbc.html>.
--
-- NaCl does not make any promises regarding \"strong\"
-- unforgeability; perhaps one valid authenticator can be converted
-- into another valid authenticator for the same message. NaCl also
-- does not make any promises regarding \"truncated unforgeability.\"

-- | A @'Key'@ is a secret key used for authentication - be sure to
-- keep it safe!
newtype Key = Key ByteString
  deriving (Eq, Show, Ord)

-- | Create a key from a @'ByteString'@. Must be exactly 16 bytes in
-- length.
key :: ByteString -> Maybe Key
key xs | S.length xs /= siphashKEYBYTES = Nothing
       | otherwise = Just (Key xs)

-- | Generate a random key for performing encryption.
randomKey :: IO Key
randomKey = Key `fmap` randombytes siphashKEYBYTES

-- | An authenticator.
newtype Auth = Auth { unAuth :: ByteString }
  deriving (Eq, Show, Ord)

-- | @'authenticate' k m@ authenticates a message @'m'@ using a secret
-- @'Key'@ @k@ and returns the authenticator, @'Auth'@.
authenticate :: Key
             -- ^ Secret key
             -> ByteString
             -- ^ Message
             -> Auth
             -- ^ Authenticator
authenticate (Key k) msg =
  Auth . unsafePerformIO . create siphashBYTES $ \out ->
    unsafeUseAsCStringLen msg $ \(cstr, clen) ->
      unsafeUseAsCString k $ \pk ->
        c_crypto_siphash24 out cstr (fromIntegral clen) pk >> return ()
{-# INLINE authenticate #-}

-- | @'verify' k a m@ verifies @a@ is the correct authenticator of @m@
-- under a secret @'Key'@ @k@.
verify :: Key
       -- ^ Secret key
       -> Auth
       -- ^ Authenticator returned via 'authenticateOnce'
       -> ByteString
       -- ^ Message
       -> Bool
       -- ^ Result: @True@ if verified, @False@ otherwise
verify (Key k) (Auth auth) msg =
  unsafePerformIO . unsafeUseAsCString auth $ \pauth ->
    unsafeUseAsCStringLen msg $ \(cstr, clen) ->
      unsafeUseAsCString k $ \pk -> do
        b <- c_crypto_siphash24_verify pauth cstr (fromIntegral clen) pk
        return (b == 0)
{-# INLINE verify #-}

--
-- FFI mac binding
--

siphashKEYBYTES :: Int
siphashKEYBYTES = 16

siphashBYTES :: Int
siphashBYTES = 8

foreign import ccall unsafe "siphash24_mac"
  c_crypto_siphash24 :: Ptr Word8 -> Ptr CChar -> CULLong ->
                        Ptr CChar -> IO Int

foreign import ccall unsafe "siphash24_mac_verify"
  c_crypto_siphash24_verify :: Ptr CChar -> Ptr CChar -> CULLong ->
                               Ptr CChar -> IO Int
