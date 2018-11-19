﻿using Xunit;
using System;
using Newtonsoft.Json.Linq;
using System.Text;
using JsonWebToken.Internal;

namespace JsonWebToken.Tests
{
    public class EcKeyWrapTests
    {
        private readonly ECJwk _aliceKey = new ECJwk
        {
            Kty = "EC",
            Crv = "P-256",
            X = "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
            Y = "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
            D = "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo",
        };
        private readonly ECJwk _bobKey = new ECJwk
        {
            Kty = "EC",
            Crv = "P-256",
            X = "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            Y = "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            D = "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
        };

        [Fact]
        public void Wrap_Rfc7518_Appendix_C()
        {
            var kwp = new EcdhKeyWrapper(_bobKey, EncryptionAlgorithm.Aes128Gcm, KeyManagementAlgorithm.EcdhEs);
            byte[] wrappedKey = null;
            var header = new JObject
            {
                { HeaderParameters.Apu, Base64Url.Base64UrlEncode("Alice") },
                { HeaderParameters.Apv, Base64Url.Base64UrlEncode("Bob") }
            };

            var wrapped = kwp.TryWrapKey(_aliceKey, header, wrappedKey, out var cek, out var bytesWritten);
            Assert.True(wrapped);

            var expected = new byte[] { 86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26 };
            Assert.Equal(expected, cek.ToByteArray());
        }

        [Fact]
        public void Unwrap()
        {
            var kwp = new EcdhKeyWrapper(_bobKey, EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.EcdhEsAes128KW);
            byte[] wrappedKey = new byte[kwp.GetKeyWrapSize()];
            var header = new JObject
            {
                { HeaderParameters.Apu, Base64Url.Base64UrlEncode("Alice") },
                { HeaderParameters.Apv, Base64Url.Base64UrlEncode("Bob") }
            };

            var wrapped = kwp.TryWrapKey(_aliceKey, header, wrappedKey, out var cek, out var bytesWritten);

            var kwp2 = new EcdhKeyWrapper(_bobKey, EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.EcdhEsAes128KW);
            var jwtHeader = new JwtHeader
            {
                Apu = Base64Url.Base64UrlEncode("Alice"),
                Apv = Base64Url.Base64UrlEncode("Bob"),
                Epk = header[HeaderParameters.Epk].ToObject<ECJwk>()
            };

            byte[] unwrappedKey = new byte[kwp.GetKeyUnwrapSize(wrappedKey.Length)];
            var unwrapped = kwp2.TryUnwrapKey(wrappedKey, unwrappedKey, jwtHeader, out bytesWritten);

            Assert.True(unwrapped);
        }

        [Fact]
        public void Unwrap2()
        {
            var kwp = new EcdhKeyWrapper(_bobKey, EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.EcdhEsAes128KW);
            byte[] wrappedKey = new byte[kwp.GetKeyWrapSize()];
            var header = new JObject
            {
                { HeaderParameters.Apu, Base64Url.Base64UrlEncode("Alice") },
                { HeaderParameters.Apv, Base64Url.Base64UrlEncode("Bob") }
            };

            var wrapped = kwp.TryWrapKey(_aliceKey, header, wrappedKey, out var cek, out var bytesWritten);

            var kwp2 = new EcdhKeyWrapper(_bobKey, EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.EcdhEsAes128KW);
            var jwtHeader = new JwtHeader
            {
                Apu = Base64Url.Base64UrlEncode("Alice"),
                Apv = Base64Url.Base64UrlEncode("Bob"),
                Epk = header[HeaderParameters.Epk].ToObject<ECJwk>()
            };

            byte[] unwrappedKey = new byte[kwp.GetKeyUnwrapSize(wrappedKey.Length)];
            var unwrapped = kwp2.TryUnwrapKey(wrappedKey, unwrappedKey, jwtHeader, out bytesWritten);

            Assert.True(unwrapped);
        }
    }
}