﻿// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken
{
    /// <summary>
    /// Provides authenticated encryption and decryption.
    /// </summary>
    public abstract class AuthenticatedEncryptor : IDisposable
    {
        /// <inheritdoc />
        public abstract void Dispose();

        /// <summary>
        /// Encrypts the <paramref name="plaintext"/>.
        /// </summary>
        /// <param name="plaintext">The plaintext to encrypt.</param>
        /// <param name="nonce">An arbitrary value to be used only once.</param>
        /// <param name="associatedData">The associated data.</param>
        /// <param name="ciphertext">The resulting ciphertext.</param>
        /// <param name="authenticationTag">The resulting authentication tag.</param>
        public abstract void Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, Span<byte> ciphertext, Span<byte> authenticationTag);

        /// <summary>
        /// Gets the size of the resulting ciphertext.
        /// </summary>
        /// <param name="plaintextSize">The plaintext size.</param>
        public abstract int GetCiphertextSize(int plaintextSize);

        /// <summary>
        /// Gets the required size of the nonce.
        /// </summary>
        public abstract int GetNonceSize();

        /// <summary>
        /// Gets the size of the resulting authentication tag.
        /// </summary>
        public abstract int GetTagSize();

        /// <summary>
        /// Try to decrypt the <paramref name="ciphertext"/>. 
        /// </summary>
        /// <param name="ciphertext">The ciphertext to decrypt.</param>
        /// <param name="associatedData">The associated data used to encrypt.</param>
        /// <param name="nonce">The nonce used to encrypt.</param>
        /// <param name="authenticationTag">The authentication tag</param>
        /// <param name="plaintext">The resulting plaintext.</param>
        /// <param name="bytesWritten">The bytes written in the <paramref name="plaintext"/>.</param>
        /// <returns></returns>
        public abstract bool TryDecrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> authenticationTag, Span<byte> plaintext, out int bytesWritten);
    }
}