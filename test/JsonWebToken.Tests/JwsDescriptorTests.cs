using JsonWebToken.Cryptography;
using Xunit;

namespace JsonWebToken.Tests
{
    public class JwsDescriptorTests
    {
        [Fact]
        public void EncodeEmpty()
        {
            var descriptor = new JwsDescriptor(Jwk.None, SignatureAlgorithm.None);
            using (var bufferWriter = new PooledByteBufferWriter())
            {
                var context = new EncodingContext(bufferWriter, new LruJwtHeaderCache(), 60, true);
                descriptor.Encode(context);

                var result = Jwt.TryParse(bufferWriter.WrittenSpan, TokenValidationPolicy.NoValidation, out var jwt);
                Assert.True(result);
                Assert.NotNull(jwt);
                Assert.True(jwt.Payload.ContainsClaim("exp"));
                Assert.True(jwt.Payload.ContainsClaim("iat"));
                jwt.Dispose();
            }
        }

        [Fact]
        public void DescriptorPayload_is_a_standard_ReferenceObject()
        {
            var descriptor = new JwsDescriptor(Jwk.None, SignatureAlgorithm.None);

            var p1 = new JwtPayload { { "One", "Member" } };
            var p1Content = p1.ToString();
            descriptor.Payload = p1;

            var p2 = new JwtPayload { { "Something", "else" } };
            var p2Content = p2.ToString();
            descriptor.Payload = p2;

            Assert.Equal(p1Content, p1.ToString());
            Assert.Equal(p2Content, p2.ToString());
        }

        [Fact]
        public void DescriptorHandler_is_prefilled_from_ctor_but_can_be_initialized()
        {
            // Descriptor's header is preconfigured based on the ctor parameters.
            var descriptor = new JwsDescriptor(Jwk.None, SignatureAlgorithm.HS256);
            Assert.Equal(1, descriptor.Header.Count);
            Assert.True(descriptor.Header.ContainsKey( JwtHeaderParameterNames.Alg ));
            
            // This doesn't compile and this is fine: Header is in "append" mode!
            // descriptor.Header = new JwtHeader();

            // However, thanks to the C# 9 init feature, this works.
            var withInit = new JwsDescriptor(Jwk.None, SignatureAlgorithm.HS256)
            {
                Header = new JwtHeader { { "One", "Member" } }
            };
            Assert.Equal(2, withInit.Header.Count);
            Assert.True(withInit.Header.ContainsKey(JwtHeaderParameterNames.Alg));
            Assert.True(withInit.Header.ContainsKey(System.Text.Json.JsonEncodedText.Encode("One")));
        }

    }
}
