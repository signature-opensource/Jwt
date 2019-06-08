﻿// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Provides authenticated encryption and decryption for AES CBC HMAC algorithm.
    /// </summary>
    internal sealed class AesCbcHmacEncryptor : AuthenticatedEncryptor
    {
        private readonly SymmetricSigner _signer;
        private readonly ObjectPool<Aes> _aesPool;
        private bool _disposed;

        public AesCbcHmacEncryptor(SymmetricJwk key, EncryptionAlgorithm encryptionAlgorithm)
            : base(key, encryptionAlgorithm)
        {
            if (encryptionAlgorithm.Category != EncryptionType.AesHmac)
            {
                Errors.ThrowNotSupportedEncryptionAlgorithm(encryptionAlgorithm);
            }

            if (key.KeySizeInBits < encryptionAlgorithm.RequiredKeySizeInBytes << 3)
            {
                Errors.ThrowEncryptionKeyTooSmall(key, encryptionAlgorithm, encryptionAlgorithm.RequiredKeySizeInBytes << 3, key.KeySizeInBits);
            }

            int keyLength = encryptionAlgorithm.RequiredKeySizeInBytes >> 1;

            var keyBytes = key.K;
            var aesKey = keyBytes.Slice(keyLength).ToArray();
            var hmacKey = SymmetricJwk.FromSpan(keyBytes.Slice(0, keyLength), false);

            _aesPool = new ObjectPool<Aes>(new AesPooledPolicy(aesKey));
            _signer = hmacKey.CreateSigner(encryptionAlgorithm.SignatureAlgorithm) as SymmetricSigner;
            if (_signer == null)
            {
                Errors.ThrowNotSupportedSignatureAlgorithm(encryptionAlgorithm.SignatureAlgorithm);
            }
        }

        /// <inheritdoc />
        public override int GetCiphertextSize(int plaintextSize)
        {
            return (plaintextSize + 16) & ~15;
        }

        /// <inheritdoc />
        public override int GetNonceSize()
        {
            return 16;
        }

        /// <inheritdoc />
        public override int GetBase64NonceSize()
        {
            return 22;
        }

        /// <inheritdoc />
        public override int GetTagSize()
        {
            return _signer.HashSizeInBytes;
        }

        /// <inheritdoc />
        public override int GetBase64TagSize()
        {
            return _signer.Base64HashSizeInBytes;
        }

        /// <inheritdoc />
        public override void Encrypt(
            ReadOnlySpan<byte> plaintext,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            Span<byte> ciphertext,
            Span<byte> authenticationTag)
        {
            if (plaintext.IsEmpty)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.plaintext);
            }

            if (associatedData.IsEmpty)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.associatedData);
            }

            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            byte[] arrayToReturnToPool = null;
            Aes aes = _aesPool.Get();
            try
            {
                aes.IV = nonce.ToArray();
                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    Transform(encryptor, plaintext, 0, plaintext.Length, ciphertext);
                }

                int macLength = associatedData.Length + nonce.Length + ciphertext.Length + sizeof(long);
                Span<byte> macBytes = macLength <= Constants.MaxStackallocBytes
                    ? stackalloc byte[macLength]
                    : (arrayToReturnToPool = ArrayPool<byte>.Shared.Rent(macLength)).AsSpan(0, macLength);

                associatedData.CopyTo(macBytes);
                nonce.CopyTo(macBytes.Slice(associatedData.Length));
                ciphertext.CopyTo(macBytes.Slice(associatedData.Length + nonce.Length));
                BinaryPrimitives.WriteInt64BigEndian(macBytes.Slice(associatedData.Length + nonce.Length + ciphertext.Length, sizeof(long)), associatedData.Length << 3);

                _signer.TrySign(macBytes, authenticationTag, out int writtenBytes);
                Debug.Assert(writtenBytes == authenticationTag.Length);
            }
            catch
            {
                ciphertext.Clear();
                throw;
            }
            finally
            {
                _aesPool.Return(aes);
                if (arrayToReturnToPool != null)
                {
                    ArrayPool<byte>.Shared.Return(arrayToReturnToPool);
                }
            }
        }

        /// <inheritdoc />
        public override bool TryDecrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> authenticationTag, Span<byte> plaintext, out int bytesWritten)
        {
            if (ciphertext.IsEmpty)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.ciphertext);
            }

            if (associatedData.IsEmpty)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.associatedData);
            }

            if (nonce.IsEmpty)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.nonce);
            }

            if (authenticationTag.IsEmpty)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.authenticationTag);
            }

            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            byte[] byteArrayToReturnToPool = null;
            int macLength = associatedData.Length + nonce.Length + ciphertext.Length + sizeof(long);
            Span<byte> macBytes = macLength <= Constants.MaxStackallocBytes
                                    ? stackalloc byte[macLength]
                                    : (byteArrayToReturnToPool = ArrayPool<byte>.Shared.Rent(macLength)).AsSpan(0, macLength);
            try
            {
                associatedData.CopyTo(macBytes);
                nonce.CopyTo(macBytes.Slice(associatedData.Length));
                ciphertext.CopyTo(macBytes.Slice(associatedData.Length + nonce.Length));
                BinaryPrimitives.WriteInt64BigEndian(macBytes.Slice(associatedData.Length + nonce.Length + ciphertext.Length), associatedData.Length * 8);
                if (!_signer.Verify(macBytes, authenticationTag))
                {
                    plaintext.Clear();
                    return Errors.TryWriteError(out bytesWritten);
                }

                Aes aes = _aesPool.Get();
                try
                {
                    aes.IV = nonce.ToArray();
                    using (var decryptor = aes.CreateDecryptor())
                    {
                        bytesWritten = Transform(decryptor, ciphertext, 0, ciphertext.Length, plaintext);
                    }

                    return bytesWritten <= ciphertext.Length;
                }
                finally
                {
                    _aesPool.Return(aes);
                }
            }
            catch
            {
                plaintext.Clear();
                return Errors.TryWriteError(out bytesWritten);
            }
            finally
            {
                if (byteArrayToReturnToPool != null)
                {
                    ArrayPool<byte>.Shared.Return(byteArrayToReturnToPool);
                }
            }
        }

        /// <inheritdoc />
        public override void Dispose()
        {
            if (!_disposed)
            {
                _signer.Dispose();
                _aesPool.Dispose();

                _disposed = true;
            }
        }

        private static unsafe int Transform(ICryptoTransform transform, ReadOnlySpan<byte> input, int inputOffset, int inputLength, Span<byte> output)
        {
            fixed (byte* buffer = output)
            {
                using (var messageStream = new UnmanagedMemoryStream(buffer, output.Length, output.Length, FileAccess.Write))
                using (CryptoStream cryptoStream = new CryptoStream(messageStream, transform, CryptoStreamMode.Write))
                {
#if !NETSTANDARD2_0
                    cryptoStream.Write(input.Slice(inputOffset, inputLength));
#else
                    cryptoStream.Write(input.ToArray(), inputOffset, inputLength);
#endif
                    cryptoStream.FlushFinalBlock();
                    return (int)messageStream.Position;
                }
            }
        }

        private sealed class AesPooledPolicy : PooledObjectFactory<Aes>
        {
            private readonly byte[] _key;

            public AesPooledPolicy(byte[] key)
            {
                _key = key;
            }

            public override Aes Create()
            {
                var aes = Aes.Create();
                aes.Key = _key;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                return aes;
            }
        }
    }
}
