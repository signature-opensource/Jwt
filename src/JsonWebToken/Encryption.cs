﻿// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

namespace JsonWebToken
{
    internal static class Encryption
    {
        /// <summary>
        /// 'A128CBC-HS256'
        /// </summary>
        public const int Aes128CbcHmacSha256 = 14;

        /// <summary>
        /// 'A192CBC-HS384'
        /// </summary>
        public const int Aes192CbcHmacSha384 = 16; // Undefined in CWT

        /// <summary>
        /// 'A256CBC-HS512'
        /// </summary>
        public const int Aes256CbcHmacSha512 = 15;

#if NETCOREAPP3_0
        /// <summary>
        /// 'A128GCM'
        /// </summary>
        public const int Aes128Gcm = 1;

        /// <summary>
        /// 'A192GCM'
        /// </summary>
        public const int Aes192Gcm = 2;

        /// <summary>
        /// 'A256GCM'
        /// </summary>
        public const int Aes256Gcm = 3;
#endif
    }
}