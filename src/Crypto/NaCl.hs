-- |
-- Module      : Crypto.NaCl
-- Copyright   : (c) Austin Seipp 2011-2013
-- License     : BSD3
--
-- Maintainer  : aseipp@pobox.com
-- Stability   : experimental
-- Portability : GHC (ScopedTypeVariables)
--
-- The Networking and Cryptography library.
--
-- This module is intended to be imported @qualified@ to avoid name
-- clashes with other cryptographic primitives, e.g.
--
-- > import qualified Crypto.NaCl as NaCl
module Crypto.NaCl
       ( -- * NaCl API
         -- ** Public-key cryptograpy
         -- *** Authenticated encryption: @'box'@
         -- $precomp-note
         Box.Box
       , box
       , boxOpen
         -- **** Precomputation interface
         -- $precomp
       , Box.NM
       , boxBeforeNM
       , boxAfterNM
       , boxOpenAfterNM

         -- *** Diffie-hellman: @'curve25519'@
       , Curve25519.Curve25519
       , curve25519

         -- *** Signatures: @'sign'@
       , Ed25519.Ed25519
       , sign
       , verify

         -- ** Secret-key cryptography
         -- *** Authenticated encryption: @'secretBox'@
       , SecretBox.SecretBox
       , secretBox
       , secretBoxOpen

         -- *** Encryption: @'stream'@
       , Stream.Stream
       , stream
       , streamEncrypt
       , streamDecrypt

         -- *** Authentication: @'auth'@
       , HMACSHA512.HMACSHA512
       , auth
       , authVerify

         -- *** One-time authentication: @'oneTimeAuth'@
       , Poly1305.Poly1305
       , oneTimeAuth
       , oneTimeAuthVerify

         -- ** Secure randomness: @'randombytes'@
       , Random.randombytes

         -- ** Low-level functions
         -- *** Hashing: @'hash'@
       , hash    -- :: ByteString -> ByteString

         -- * Extra utilities
         -- ** Secure password-based file encryption

         -- ** Secure password storage: @'Password.encryptPass'@
         -- $password-storage
         -- *** Types
       , Password.EncryptedPass(..)
       , Password.Pass(..)
         -- *** Parameters
         -- $params
       , Password.ScryptParams
       , Password.defaultParams
       , Password.scryptParams
         -- *** Encryption/verification
       , Password.encryptPass
       , Password.encryptPass'
       , Password.verifyPass
       , Password.verifyPass'

         -- ** Key-stretching: @'deriveKey'@
       , KDF.Salt(..)
       , KDF.newSalt
       , deriveKey

         -- * Keys
       , PublicKey(..) -- :: *
       , SecretKey(..) -- :: *
       ) where
import           Data.ByteString

import qualified Crypto.DH.Curve25519     as Curve25519
import qualified Crypto.Encrypt.Box       as Box
import qualified Crypto.Encrypt.SecretBox as SecretBox
import qualified Crypto.Encrypt.Stream    as Stream
import qualified Crypto.Hash.SHA          as SHA
import qualified Crypto.HMAC.SHA512       as HMACSHA512
import qualified Crypto.MAC.Poly1305      as Poly1305
import qualified Crypto.Sign.Ed25519      as Ed25519
import qualified Crypto.KDF.Scrypt        as KDF
import qualified Crypto.Password.Scrypt   as Password

import           Crypto.Key
import           Crypto.Nonce             as Nonce
import           System.Crypto.Random     as Random

--------------------------------------------------------------------------------
-- Public-key authenticated encryption

{- $precomp-note

There are two basic interfaces: a simple encryption/decryption
interface, and a 'precomputation interface' for
encryption/decryption. If you're going to send lots of messages to the
same receiver, you are /highly/ encouraged to use the precomputation
interface. In particular, the basic @'box'@ and @'boxOpen'@
functions perform Diffie-Hellman key-exchange upon every invocation,
which is very computationally expensive relative to the
encryption. Instead, use the precomputation interface, which will
compute the shared secret only once and share it amongst future calls.
-}

-- | The @'box'@ function encrypts and authenticates a message @m@
-- using a sender's @'SecretKey'@ @sk@, the receiver's @'PublicKey'@
-- @pk@, and a @'Nonce'@ @n@.
box :: Nonce Box.Box
    -- ^ Nonce
    -> ByteString
    -- ^ Message
    -> PublicKey Box.Box
    -- ^ Recievers @'PublicKey'@
    -> SecretKey Box.Box
    -- ^ Senders @'SecretKey'@
    -> ByteString
    -- ^ Ciphertext
box = Box.encrypt
{-# INLINE box #-}

-- | The @'boxOpen'@ function verifies and decrypts a ciphertext @c@
-- using the receiver's @'SecretKey'@ @sk@, the sender's @'PublicKey'@
-- @pk@ and a @'Nonce'@ @n@.
boxOpen :: Nonce Box.Box
        -- ^ Nonce
        -> ByteString
        -- ^ Input ciphertext
        -> PublicKey Box.Box
        -- ^ Senders @'PublicKey'@
        -> SecretKey Box.Box
        -- ^ Recievers @'SecretKey'@
        -> Maybe ByteString -- ^ Ciphertext
boxOpen = Box.decrypt
{-# INLINE boxOpen #-}

-- $precomp
--
-- If you send many messages to the same receiver, or receive many
-- messages from the same sender, you can gain speed increases by
-- instead using the following precomputation interface, which splits
-- the encryption and decryption steps into two parts.
--
-- For encryption, you first create an @'Box.NM'@ by using
-- @'boxBeforeNM'@, using the senders @'SecretKey'@, and receivers
-- @'PublicKey'@. You can then use @'boxAfterNM'@ to encrypt data.
--
-- For decryption, you first create an @'Box.NM'@ by using
-- @'boxBeforeNM'@, using the recievers @'SecretKey'@, and the senders
-- @'PublicKey'@. You can then use @'boxOpenAfterNM'@ to decrypt data.

-- | Creates an intermediate piece of @'Box.NM'@ data for
-- sending\/receiving messages to\/from the same person. The resulting
-- @'Box.NM'@ can be used for any number of messages between
-- the sender/receiver.
boxBeforeNM :: PublicKey Box.Box -- ^ Sender/receiver @'PublicKey'@
            -> SecretKey Box.Box -- ^ Sender/receiver @'SecretKey'@
            -> Box.NM            -- ^ Precomputation box
boxBeforeNM = Box.createNM
{-# INLINE boxBeforeNM #-}

-- | Encrypt data from a specific sender to a specific receiver with
-- some precomputed @'Box.NM'@ data.
boxAfterNM :: Box.NM -> Nonce Box.Box -> ByteString -> ByteString
boxAfterNM = Box.encryptNM
{-# INLINE boxAfterNM #-}

-- | Decrypt data from a specific sender for a specific receiver with
-- some precomputed @'Box.NM'@ data.
boxOpenAfterNM :: Box.NM -> Nonce Box.Box -> ByteString -> Maybe ByteString
boxOpenAfterNM = Box.decryptNM
{-# INLINE boxOpenAfterNM #-}

--------------------------------------------------------------------------------
-- Diffie-Hellman

-- | Compute the shared secret between two parties. Given two keys
-- @'curve25519' sk pk@ computes a shared secret between your secret
-- key and the second parties' public key.
--
-- Given the inverse pair of keys (that is, the second parties' secret
-- key and your public key) then @'curve25519' sk pk@ will compute the
-- same shared secret.
curve25519 :: SecretKey Curve25519.Curve25519 -- ^ Your @'SecretKey'@
           -> PublicKey Curve25519.Curve25519 -- ^ Other parties' @'PublicKey'@
           -> ByteString                      -- ^ Shared secret
curve25519 = Curve25519.curve25519
{-# INLINE curve25519 #-}

--------------------------------------------------------------------------------
-- Signatures

-- | Sign a message with a particular @'SecretKey'@.
sign :: SecretKey Ed25519.Ed25519
     -- ^ Signers @'SecretKey'@
     -> ByteString
     -- ^ Input message
     -> ByteString
     -- ^ Resulting signed message
sign = Ed25519.sign
{-# INLINE sign #-}

-- | Verifies a signed message against a @'PublicKey'@.
verify :: PublicKey Ed25519.Ed25519
       -- ^ Signers @'PublicKey'@
       -> ByteString
       -- ^ Signed message
       -> Bool
       -- ^ Verification check
verify = Ed25519.verify
{-# INLINE verify #-}

--------------------------------------------------------------------------------
-- Secret-key authenticated encryption

-- | The @'encrypt'@ function encrypts and authenticates a message @m@
-- using a secret @'SecretKey'@ @k@, and a @'Nonce'@ @n@.
--
-- This function produces ciphertext compatible with the NaCl
-- @crypto_secretbox@ function.
secretBox :: Nonce SecretBox.SecretBox
          -- ^ Nonce
          -> ByteString
          -- ^ Input
          -> SecretKey SecretBox.SecretBox
          -- ^ Shared @'SecretKey'@
          -> ByteString
          -- ^ Ciphertext
secretBox = SecretBox.encrypt
{-# INLINE secretBox #-}

-- | The @'decrypt'@ function verifies and decrypts a ciphertext @c@
-- using a secret @'Key'@ @k@, and a @'Nonce'@ @n@.
--
-- Like @'encrypt'@, @'decrypt'@ takes ciphertext that is compatible
-- with the NaCl C @crypto_secretbox@ and @crypto_secretbox_open@
-- functions.
secretBoxOpen :: Nonce SecretBox.SecretBox
              -- ^ Nonce
              -> ByteString
              -- ^ Input
              -> SecretKey SecretBox.SecretBox
              -- ^ Shared @'SecretKey'@
              -> Maybe ByteString
              -- ^ Ciphertext
secretBoxOpen = SecretBox.decrypt
{-# INLINE secretBoxOpen #-}

--------------------------------------------------------------------------------
-- Secret-key encryption

-- | Given a @'Nonce'@ @n@, size @s@ and @'Key'@ @k@, @'stream' n s k@
-- generates a cryptographic stream of length @s@.
stream :: Nonce Stream.Stream
       -- ^ Nonce
       -> Int
       -- ^ Size
       -> SecretKey Stream.Stream
       -- ^ Key
       -> ByteString
       -- ^ Resulting crypto stream
stream = Stream.stream
{-# INLINE stream #-}

-- | Given a @'Nonce'@ @n@, plaintext @p@ and @'Key'@ @k@,
-- @'streamEncrypt' n p k@ encrypts the message @p@ using @'Key'@ @k@
-- and returns the result.
--
-- @'streamEncrypt'@ guarantees the resulting ciphertext is the plaintext
-- bitwise XOR'd with the result of @'stream'@. As a result,
-- @'streamEncrypt'@ can also be used to decrypt messages.
streamEncrypt :: Nonce Stream.Stream
              -- ^ Nonce
              -> ByteString
              -- ^ Input plaintext
              -> SecretKey Stream.Stream
              -- ^ Key
              -> ByteString
              -- ^ Ciphertext
streamEncrypt = Stream.encrypt
{-# INLINE streamEncrypt #-}

-- | Simple alias for @'streamEncrypt'@.
streamDecrypt :: Nonce Stream.Stream
              -- ^ Nonce
              -> ByteString
              -- ^ Input plaintext
              -> SecretKey Stream.Stream
              -- ^ Key
              -> ByteString
              -- ^ Ciphertext
streamDecrypt = Stream.encrypt
{-# INLINE streamDecrypt #-}

--------------------------------------------------------------------------------
-- Authentication

-- | @'auth' k m@ authenticates a message @'m'@ using a @'SecretKey'@
-- @k@ and returns the authenticator, @'Auth'@.
auth :: SecretKey HMACSHA512.HMACSHA512
     -- ^ Secret key
     -> ByteString
     -- ^ Message
     -> HMACSHA512.Auth
     -- ^ Authenticator
auth = HMACSHA512.authenticate
{-# INLINE auth #-}

-- | @'authVerify' k a m@ verifies @a@ is the correct authenticator of
-- @m@ under a @'SecretKey'@ @k@.
authVerify :: SecretKey HMACSHA512.HMACSHA512
           -- ^ Secret key
           -> HMACSHA512.Auth
           -- ^ Authenticator returned via @'authenticate'@
           -> ByteString
           -- ^ Message
           -> Bool
           -- ^ Result: @'True'@ if verified, @'False'@ otherwise
authVerify = HMACSHA512.verify
{-# INLINE authVerify #-}

--------------------------------------------------------------------------------
-- One-time authentication

-- | @'oneTimeAuth' k m@ authenticates a message @'m'@ using a secret
-- @'SecretKey'@ @k@ and returns the authenticator, @'Poly1305.Auth'@.
oneTimeAuth :: SecretKey Poly1305.Poly1305
            -> ByteString
            -> Poly1305.Auth
oneTimeAuth = Poly1305.authenticate
{-# INLINE oneTimeAuth #-}

-- | @'oneTimeAuthVerify' k a m@ verifies @a@ is the correct
-- authenticator of @m@ under a @'SecretKey'@ @k@.
oneTimeAuthVerify :: SecretKey Poly1305.Poly1305
                  -> Poly1305.Auth
                  -> ByteString
                  -> Bool
oneTimeAuthVerify = Poly1305.verify
{-# INLINE oneTimeAuthVerify #-}

--------------------------------------------------------------------------------
-- Hashing

-- | SHA-512.
hash :: ByteString -> ByteString
hash = SHA.sha512
{-# INLINE hash #-}

--------------------------------------------------------------------------------
-- TODO: file encryption

--------------------------------------------------------------------------------
-- Password storage

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

--------------------------------------------------------------------------------
-- Key stretching

-- | Derive a strong key from a given @'ByteString'@. This can be used
-- to derive a secure encryption key from a password, for example.
--
-- The @'Salt'@ may be generated with @'KDF.newSalt'@, and may be
-- stored along with the encrypted buffer. When you need to decrypt
-- it, simply derive the same key from the users password using the
-- salt, and attempt to decrypt.
deriveKey :: Integer    -- ^ Size of resulting @'ByteString'@
          -> KDF.Salt   -- ^ A @'KDF.Salt'@
          -> ByteString -- ^ Input
          -> ByteString -- ^ Resulting key
deriveKey = KDF.stretch'
{-# INLINE deriveKey #-}
