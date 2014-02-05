{-# LANGUAGE NamedFieldPuns           #-}
{-# LANGUAGE OverloadedStrings        #-}
-- |
-- Module      : Crypto.Password.Scrypt
-- Copyright   : (c) Copyright 2011-2013 Falko Peters, Austin Seipp 2013
-- License     : BSD3
--
-- Maintainer  : aseipp@pobox.com
-- Stability   : experimental
-- Portability : GHC
--
-- Scrypt is a sequential memory-hard key derivation function. This
-- module provides a high-level password-storage API for scrypt.
--
-- This implementation is based on a variant of scrypt known as
-- @scrypt-jane@ with customizable mixing and hash functions for the
-- underlying KDF. It is a combination of BLAKE512 for hashing and
-- ChaCha20/8 for mixing.
--
-- For further information see
-- <http://www.tarsnap.com/scrypt.html>. The homepage of @scrypt-jane@
-- is at <https://github.com/floodyberry/scrypt-jane>.
--
module Crypto.Password.Scrypt
       ( -- * Password Storage
         -- $password-storage
         -- ** Types
         EncryptedPass(..)
       , Pass(..)
         -- ** Parameters
         -- $params
       , ScryptParams
       , defaultParams
       , scryptParams
         -- ** Encryption/verification
       , encryptPass
       , encryptPass'
       , verifyPass
       , verifyPass'
       ) where

import           Control.Applicative
import qualified Data.ByteString.Base64 as Base64
import qualified Data.ByteString.Char8  as B

import           Crypto.Internal.Scrypt
import           System.Crypto.Random   (randombytes)

-- | An encrypted password, which can be checked against a user
-- password with @'verifyPass'@
newtype EncryptedPass =
    EncryptedPass { getEncryptedPass :: B.ByteString } deriving (Show, Eq)

------------------------------------------------------------------------------
-- $password-storage
--
-- To allow storing encrypted passwords conveniently in a single database
-- column, the password storage API provides the data type 'EncryptedPass'. It
-- combines a 'Pass' as well as the 'Salt' and 'ScryptParams' used to compute
-- it into a single 'ByteString', separated by pipe (\"|\") characters. The
-- 'Salt' and 'PassHash' are base64-encoded. Storing the 'ScryptParams' with
-- the password allows to gradually strengthen password encryption in case of
-- changing security requirements.
--
-- A usage example is given below, showing encryption, verification and
-- changing 'ScryptParams':
--
-- > >>> encrypted <- encryptPass defaultParams (Pass "secret")
-- > >>> print encrypted
-- > EncryptedPass {unEncryptedPass = "14|8|1|Wn5x[SNIP]nM=|Zl+p[SNIP]g=="}
-- > >>> print $ verifyPass defaultParams (Pass "secret") encrypted
-- > (True,Nothing)
-- > >>> print $ verifyPass defaultParams (Pass "wrong") encrypted
-- > (False,Nothing)
-- > >>> let newParams = fromJust $ scryptParams 16 8 1
-- > >>> print $ verifyPass newParams (Pass "secret") encrypted
-- > (True,Just (EncryptedPass {unEncryptedPass = "16|8|1|Wn5x[SNIP]nM=|ZmWw[SNIP]Q=="}))
--

------------------------------------------------------------------------------
-- $params
--
-- Scrypt takes three tuning parameters: @N@, @r@ and @p@. They affect running
-- time and memory usage:
--
-- /Memory usage/ is approximately @128*r*N@ bytes. Note that the
-- 'scryptParams' function takes @log_2(N)@ as a parameter. As an example,
-- the 'defaultParams'
--
-- >   log_2(N) = 14, r = 8 and p = 1
--
-- lead to 'scrypt' using @128 * 8 * 2^14 = 16M@ bytes of memory.
--
-- /Running time/ is proportional to all of @N@, @r@ and @p@. Since it's
-- influence on memory usage is small, @p@ can be used to independently tune
-- the running time.

combine :: ScryptParams -> Salt -> PassHash -> EncryptedPass
combine params (Salt salt) (PassHash passHash) =
    EncryptedPass $ B.intercalate "|"
        [ showBS logN, showBS r, showBS p
        , Base64.encode salt, Base64.encode passHash]
  where
    (logN, r, p, _) = getParams params
    showBS = B.pack . show

separate :: EncryptedPass -> Maybe (ScryptParams, Salt, PassHash)
separate = go . B.split '|' . getEncryptedPass
  where
    go [logN', r', p', salt', hash'] = do
        [salt, hash] <- mapM decodeBase64 [salt', hash']
        [logN, r, p] <- mapM (fmap fst . B.readInteger) [logN', r', p']
        let bufLen = fromIntegral (B.length hash)
        params       <- scryptParamsLen logN r p bufLen
        return (params, Salt salt, PassHash hash)
    go _         = Nothing
    decodeBase64 = either (const Nothing) Just . Base64.decode

-- |Encrypt the password with the given parameters and a random 32-byte salt.
-- The salt is read from @\/dev\/urandom@ on Unix systems or @CryptoAPI@ on
-- Windows.
--
encryptPass :: ScryptParams -> Pass -> IO EncryptedPass
encryptPass params pass = do
    salt <- Salt <$> randombytes 32
    return $ combine params salt (scrypt params salt pass)

-- |Equivalent to @encryptPass defaultParams@.
--
encryptPass' :: Pass -> IO EncryptedPass
encryptPass' = encryptPass defaultParams

-- |Verify a 'Pass' against an 'EncryptedPass'. The function also takes
--  'ScryptParams' meeting your current security requirements. In case the
--  'EncryptedPass' was generated with different parameters, the function
--  returns an updated 'EncryptedPass', generated with the given
--  'ScryptParams'. The 'Salt' is kept from the given 'EncryptedPass'.
--
verifyPass
    :: ScryptParams
    -- ^ Parameters to use for updating the 'EncryptedPass'.
    -> Pass
    -- ^ The candidate 'Pass'.
    -> EncryptedPass
    -- ^ The 'EncryptedPass' to check against.
    -> (Bool, Maybe EncryptedPass)
    -- ^ Returns a pair of
    --
    --     * 'Bool' indicating verification success or failure.
    --
    --     * 'Just' a /new/ 'EncryptedPass' if the given 'ScryptParams' are
    --      different from those encapsulated in the /given/ 'EncryptedPass',
    --      otherwise 'Nothing'.
    --
verifyPass newParams candidate encrypted =
    maybe (False, Nothing) verify (separate encrypted)
  where
    verify (params,salt,hash) =
        let valid   = scrypt params salt candidate == hash
            newHash = scrypt newParams salt candidate
            newEncr = if not valid || params == newParams
                        then Nothing
                        else Just (combine newParams salt newHash)
        in (valid, newEncr)

-- |Check the 'Pass' against the 'EncryptedPass', using the 'ScryptParams'
--  encapsulated in the 'EncryptedPass'.
--
verifyPass' :: Pass -> EncryptedPass -> Bool
-- We never evaluate an eventual new 'EncryptedPass' from 'verifyPass', so it is
-- safe to pass 'undefined' to verifyPass.
verifyPass' pass encrypted = fst $ verifyPass undefined pass encrypted
