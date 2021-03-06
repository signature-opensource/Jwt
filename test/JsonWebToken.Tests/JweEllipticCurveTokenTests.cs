﻿#if NETCOREAPP
using System.Collections.Generic;
using JsonWebToken.Cryptography;
using Xunit;

namespace JsonWebToken.Tests
{
    public class JweEllipticCurveTokenTests
    {
        private readonly ECJwk _bobKey = ECJwk.FromBase64Url
        (
            crv: EllipticalCurve.P256,
            x: "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            y: "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            d: "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
        );
        private readonly SymmetricJwk _signingKey = SymmetricJwk.GenerateKey(SignatureAlgorithm.HS256);

        [Theory]
        [MemberData(nameof(GetSupportedAlgorithm))]
        public void Encode_Decode(string enc, byte[] alg)
        {
            var writer = new JwtWriter();

            var descriptor = new JweDescriptor(_bobKey, (KeyManagementAlgorithm)alg, (EncryptionAlgorithm)enc)
            {
                Payload = new JwsDescriptor(_signingKey, SignatureAlgorithm.HS256)
                {
                    Payload = new JwtPayload
                    {
                        {"sub", "Alice" }
                    }
                }
            };

            var token = writer.WriteToken(descriptor);

            var policy = new TokenValidationPolicyBuilder()
                .RequireSignatureByDefault(_signingKey)
                .WithDecryptionKey(_bobKey)
                .Build();

            var result = Jwt.TryParse(token, policy, out var jwt);
            Assert.True(result);
            Assert.True(jwt.Payload.TryGetClaim("sub", out var sub));
            Assert.Equal("Alice", sub.GetString());
            jwt.Dispose();
        }

        public static IEnumerable<object[]> GetSupportedAlgorithm()
        {
            yield return new object[] { (string)EncryptionAlgorithm.A128CbcHS256, (byte[])KeyManagementAlgorithm.EcdhEs };
            yield return new object[] { (string)EncryptionAlgorithm.A192CbcHS384, (byte[])KeyManagementAlgorithm.EcdhEs };
            yield return new object[] { (string)EncryptionAlgorithm.A256CbcHS512, (byte[])KeyManagementAlgorithm.EcdhEs };
#if SUPPORT_ELLIPTIC_CURVE
            yield return new object[] { (string)EncryptionAlgorithm.A128CbcHS256, (byte[])KeyManagementAlgorithm.EcdhEsA128KW };
            yield return new object[] { (string)EncryptionAlgorithm.A128CbcHS256, (byte[])KeyManagementAlgorithm.EcdhEsA192KW };
            yield return new object[] { (string)EncryptionAlgorithm.A128CbcHS256, (byte[])KeyManagementAlgorithm.EcdhEsA256KW };
#endif
            yield break;
        }
    }
}
#endif