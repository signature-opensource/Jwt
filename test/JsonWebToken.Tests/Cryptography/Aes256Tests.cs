﻿using Xunit;

namespace JsonWebToken.Tests.Cryptography
{
    public class Aes256Tests : AesTests
    {
        [Theory]
        [InlineData("014730f80ac625fe84f026c60bfd547d", "5c9d844ed46f9885085e5d6a4f94c7d7")]
        [InlineData("0b24af36193ce4665f2825d7b4749c98", "a9ff75bd7cf6613d3731c77c3b6d0c04")]
        [InlineData("761c1fe41a18acf20d241650611d90f1", "623a52fcea5d443e48d9181ab32c7421")]
        [InlineData("8a560769d605868ad80d819bdba03771", "38f2c7ae10612415d27ca190d27da8b4")]
        [InlineData("91fbef2d15a97816060bee1feaa49afe", "1bc704f1bce135ceb810341b216d7abe")]
        public void GfsBoxKatv(string plaintext, string expectedCiphertext)
        {
            VerifyGfsBoxKat(plaintext.HexToByteArray(), expectedCiphertext.HexToByteArray(), "0000000000000000000000000000000000000000000000000000000000000000".HexToByteArray());
        }

        [Theory]
        [InlineData("c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558", "46f2fb342d6f0ab477476fc501242c5f")]
        [InlineData("28d46cffa158533194214a91e712fc2b45b518076675affd910edeca5f41ac64", "4bf3b0a69aeb6657794f2901b1440ad4")]
        [InlineData("c1cc358b449909a19436cfbb3f852ef8bcb5ed12ac7058325f56e6099aab1a1c", "352065272169abf9856843927d0674fd")]
        [InlineData("984ca75f4ee8d706f46c2d98c0bf4a45f5b00d791c2dfeb191b5ed8e420fd627", "4307456a9e67813b452e15fa8fffe398")]
        [InlineData("b43d08a447ac8609baadae4ff12918b9f68fc1653f1269222f123981ded7a92f", "4663446607354989477a5c6f0f007ef4")]
        [InlineData("1d85a181b54cde51f0e098095b2962fdc93b51fe9b88602b3f54130bf76a5bd9", "531c2c38344578b84d50b3c917bbb6e1")]
        [InlineData("dc0eba1f2232a7879ded34ed8428eeb8769b056bbaf8ad77cb65c3541430b4cf", "fc6aec906323480005c58e7e1ab004ad")]
        [InlineData("f8be9ba615c5a952cabbca24f68f8593039624d524c816acda2c9183bd917cb9", "a3944b95ca0b52043584ef02151926a8")]
        [InlineData("797f8b3d176dac5b7e34a2d539c4ef367a16f8635f6264737591c5c07bf57a3e", "a74289fe73a4c123ca189ea1e1b49ad5")]
        [InlineData("6838d40caf927749c13f0329d331f448e202c73ef52c5f73a37ca635d4c47707", "b91d4ea4488644b56cf0812fa7fcf5fc")]
        [InlineData("ccd1bc3c659cd3c59bc437484e3c5c724441da8d6e90ce556cd57d0752663bbc", "304f81ab61a80c2e743b94d5002a126b")]
        [InlineData("13428b5e4c005e0636dd338405d173ab135dec2a25c22c5df0722d69dcc43887", "649a71545378c783e368c9ade7114f6c")]
        [InlineData("07eb03a08d291d1b07408bf3512ab40c91097ac77461aad4bb859647f74f00ee", "47cb030da2ab051dfc6c4bf6910d12bb")]
        [InlineData("90143ae20cd78c5d8ebdd6cb9dc1762427a96c78c639bccc41a61424564eafe1", "798c7c005dee432b2c8ea5dfa381ecc3")]
        [InlineData("b7a5794d52737475d53d5a377200849be0260a67a2b22ced8bbef12882270d07", "637c31dc2591a07636f646b72daabbe7")]
        [InlineData("fca02f3d5011cfc5c1e23165d413a049d4526a991827424d896fe3435e0bf68e", "179a49c712154bbffbe6e7a84a18e220")]
        public void KeySboxKat(string key, string expectedCiphertext)
        {
            VerifyKeySboxKat(key.HexToByteArray(), expectedCiphertext.HexToByteArray());
        }

        [Theory]
        [InlineData("80000000000000000000000000000000", "ddc6bf790c15760d8d9aeb6f9a75fd4e")]
        [InlineData("c0000000000000000000000000000000", "0a6bdc6d4c1e6280301fd8e97ddbe601")]
        [InlineData("e0000000000000000000000000000000", "9b80eefb7ebe2d2b16247aa0efc72f5d")]
        [InlineData("f0000000000000000000000000000000", "7f2c5ece07a98d8bee13c51177395ff7")]
        [InlineData("f8000000000000000000000000000000", "7818d800dcf6f4be1e0e94f403d1e4c2")]
        [InlineData("fc000000000000000000000000000000", "e74cd1c92f0919c35a0324123d6177d3")]
        [InlineData("fe000000000000000000000000000000", "8092a4dcf2da7e77e93bdd371dfed82e")]
        [InlineData("ff000000000000000000000000000000", "49af6b372135acef10132e548f217b17")]
        [InlineData("ff800000000000000000000000000000", "8bcd40f94ebb63b9f7909676e667f1e7")]
        [InlineData("ffc00000000000000000000000000000", "fe1cffb83f45dcfb38b29be438dbd3ab")]
        [InlineData("ffe00000000000000000000000000000", "0dc58a8d886623705aec15cb1e70dc0e")]
        [InlineData("fff00000000000000000000000000000", "c218faa16056bd0774c3e8d79c35a5e4")]
        [InlineData("fff80000000000000000000000000000", "047bba83f7aa841731504e012208fc9e")]
        [InlineData("fffc0000000000000000000000000000", "dc8f0e4915fd81ba70a331310882f6da")]
        [InlineData("fffe0000000000000000000000000000", "1569859ea6b7206c30bf4fd0cbfac33c")]
        [InlineData("ffff0000000000000000000000000000", "300ade92f88f48fa2df730ec16ef44cd")]
        [InlineData("ffff8000000000000000000000000000", "1fe6cc3c05965dc08eb0590c95ac71d0")]
        [InlineData("ffffc000000000000000000000000000", "59e858eaaa97fec38111275b6cf5abc0")]
        [InlineData("ffffe000000000000000000000000000", "2239455e7afe3b0616100288cc5a723b")]
        [InlineData("fffff000000000000000000000000000", "3ee500c5c8d63479717163e55c5c4522")]
        [InlineData("fffff800000000000000000000000000", "d5e38bf15f16d90e3e214041d774daa8")]
        [InlineData("fffffc00000000000000000000000000", "b1f4066e6f4f187dfe5f2ad1b17819d0")]
        [InlineData("fffffe00000000000000000000000000", "6ef4cc4de49b11065d7af2909854794a")]
        [InlineData("ffffff00000000000000000000000000", "ac86bc606b6640c309e782f232bf367f")]
        [InlineData("ffffff80000000000000000000000000", "36aff0ef7bf3280772cf4cac80a0d2b2")]
        [InlineData("ffffffc0000000000000000000000000", "1f8eedea0f62a1406d58cfc3ecea72cf")]
        [InlineData("ffffffe0000000000000000000000000", "abf4154a3375a1d3e6b1d454438f95a6")]
        [InlineData("fffffff0000000000000000000000000", "96f96e9d607f6615fc192061ee648b07")]
        [InlineData("fffffff8000000000000000000000000", "cf37cdaaa0d2d536c71857634c792064")]
        [InlineData("fffffffc000000000000000000000000", "fbd6640c80245c2b805373f130703127")]
        [InlineData("fffffffe000000000000000000000000", "8d6a8afe55a6e481badae0d146f436db")]
        [InlineData("ffffffff000000000000000000000000", "6a4981f2915e3e68af6c22385dd06756")]
        [InlineData("ffffffff800000000000000000000000", "42a1136e5f8d8d21d3101998642d573b")]
        [InlineData("ffffffffc00000000000000000000000", "9b471596dc69ae1586cee6158b0b0181")]
        [InlineData("ffffffffe00000000000000000000000", "753665c4af1eff33aa8b628bf8741cfd")]
        [InlineData("fffffffff00000000000000000000000", "9a682acf40be01f5b2a4193c9a82404d")]
        [InlineData("fffffffff80000000000000000000000", "54fafe26e4287f17d1935f87eb9ade01")]
        [InlineData("fffffffffc0000000000000000000000", "49d541b2e74cfe73e6a8e8225f7bd449")]
        [InlineData("fffffffffe0000000000000000000000", "11a45530f624ff6f76a1b3826626ff7b")]
        [InlineData("ffffffffff0000000000000000000000", "f96b0c4a8bc6c86130289f60b43b8fba")]
        [InlineData("ffffffffff8000000000000000000000", "48c7d0e80834ebdc35b6735f76b46c8b")]
        [InlineData("ffffffffffc000000000000000000000", "2463531ab54d66955e73edc4cb8eaa45")]
        [InlineData("ffffffffffe000000000000000000000", "ac9bd8e2530469134b9d5b065d4f565b")]
        [InlineData("fffffffffff000000000000000000000", "3f5f9106d0e52f973d4890e6f37e8a00")]
        [InlineData("fffffffffff800000000000000000000", "20ebc86f1304d272e2e207e59db639f0")]
        [InlineData("fffffffffffc00000000000000000000", "e67ae6426bf9526c972cff072b52252c")]
        [InlineData("fffffffffffe00000000000000000000", "1a518dddaf9efa0d002cc58d107edfc8")]
        [InlineData("ffffffffffff00000000000000000000", "ead731af4d3a2fe3b34bed047942a49f")]
        [InlineData("ffffffffffff80000000000000000000", "b1d4efe40242f83e93b6c8d7efb5eae9")]
        [InlineData("ffffffffffffc0000000000000000000", "cd2b1fec11fd906c5c7630099443610a")]
        [InlineData("ffffffffffffe0000000000000000000", "a1853fe47fe29289d153161d06387d21")]
        [InlineData("fffffffffffff0000000000000000000", "4632154179a555c17ea604d0889fab14")]
        [InlineData("fffffffffffff8000000000000000000", "dd27cac6401a022e8f38f9f93e774417")]
        [InlineData("fffffffffffffc000000000000000000", "c090313eb98674f35f3123385fb95d4d")]
        [InlineData("fffffffffffffe000000000000000000", "cc3526262b92f02edce548f716b9f45c")]
        [InlineData("ffffffffffffff000000000000000000", "c0838d1a2b16a7c7f0dfcc433c399c33")]
        [InlineData("ffffffffffffff800000000000000000", "0d9ac756eb297695eed4d382eb126d26")]
        [InlineData("ffffffffffffffc00000000000000000", "56ede9dda3f6f141bff1757fa689c3e1")]
        [InlineData("ffffffffffffffe00000000000000000", "768f520efe0f23e61d3ec8ad9ce91774")]
        [InlineData("fffffffffffffff00000000000000000", "b1144ddfa75755213390e7c596660490")]
        [InlineData("fffffffffffffff80000000000000000", "1d7c0c4040b355b9d107a99325e3b050")]
        [InlineData("fffffffffffffffc0000000000000000", "d8e2bb1ae8ee3dcf5bf7d6c38da82a1a")]
        [InlineData("fffffffffffffffe0000000000000000", "faf82d178af25a9886a47e7f789b98d7")]
        [InlineData("ffffffffffffffff0000000000000000", "9b58dbfd77fe5aca9cfc190cd1b82d19")]
        [InlineData("ffffffffffffffff8000000000000000", "77f392089042e478ac16c0c86a0b5db5")]
        [InlineData("ffffffffffffffffc000000000000000", "19f08e3420ee69b477ca1420281c4782")]
        [InlineData("ffffffffffffffffe000000000000000", "a1b19beee4e117139f74b3c53fdcb875")]
        [InlineData("fffffffffffffffff000000000000000", "a37a5869b218a9f3a0868d19aea0ad6a")]
        [InlineData("fffffffffffffffff800000000000000", "bc3594e865bcd0261b13202731f33580")]
        [InlineData("fffffffffffffffffc00000000000000", "811441ce1d309eee7185e8c752c07557")]
        [InlineData("fffffffffffffffffe00000000000000", "959971ce4134190563518e700b9874d1")]
        [InlineData("ffffffffffffffffff00000000000000", "76b5614a042707c98e2132e2e805fe63")]
        [InlineData("ffffffffffffffffff80000000000000", "7d9fa6a57530d0f036fec31c230b0cc6")]
        [InlineData("ffffffffffffffffffc0000000000000", "964153a83bf6989a4ba80daa91c3e081")]
        [InlineData("ffffffffffffffffffe0000000000000", "a013014d4ce8054cf2591d06f6f2f176")]
        [InlineData("fffffffffffffffffff0000000000000", "d1c5f6399bf382502e385eee1474a869")]
        [InlineData("fffffffffffffffffff8000000000000", "0007e20b8298ec354f0f5fe7470f36bd")]
        [InlineData("fffffffffffffffffffc000000000000", "b95ba05b332da61ef63a2b31fcad9879")]
        [InlineData("fffffffffffffffffffe000000000000", "4620a49bd967491561669ab25dce45f4")]
        [InlineData("ffffffffffffffffffff000000000000", "12e71214ae8e04f0bb63d7425c6f14d5")]
        [InlineData("ffffffffffffffffffff800000000000", "4cc42fc1407b008fe350907c092e80ac")]
        [InlineData("ffffffffffffffffffffc00000000000", "08b244ce7cbc8ee97fbba808cb146fda")]
        [InlineData("ffffffffffffffffffffe00000000000", "39b333e8694f21546ad1edd9d87ed95b")]
        [InlineData("fffffffffffffffffffff00000000000", "3b271f8ab2e6e4a20ba8090f43ba78f3")]
        [InlineData("fffffffffffffffffffff80000000000", "9ad983f3bf651cd0393f0a73cccdea50")]
        [InlineData("fffffffffffffffffffffc0000000000", "8f476cbff75c1f725ce18e4bbcd19b32")]
        [InlineData("fffffffffffffffffffffe0000000000", "905b6267f1d6ab5320835a133f096f2a")]
        [InlineData("ffffffffffffffffffffff0000000000", "145b60d6d0193c23f4221848a892d61a")]
        [InlineData("ffffffffffffffffffffff8000000000", "55cfb3fb6d75cad0445bbc8dafa25b0f")]
        [InlineData("ffffffffffffffffffffffc000000000", "7b8e7098e357ef71237d46d8b075b0f5")]
        [InlineData("ffffffffffffffffffffffe000000000", "2bf27229901eb40f2df9d8398d1505ae")]
        [InlineData("fffffffffffffffffffffff000000000", "83a63402a77f9ad5c1e931a931ecd706")]
        [InlineData("fffffffffffffffffffffff800000000", "6f8ba6521152d31f2bada1843e26b973")]
        [InlineData("fffffffffffffffffffffffc00000000", "e5c3b8e30fd2d8e6239b17b44bd23bbd")]
        [InlineData("fffffffffffffffffffffffe00000000", "1ac1f7102c59933e8b2ddc3f14e94baa")]
        [InlineData("ffffffffffffffffffffffff00000000", "21d9ba49f276b45f11af8fc71a088e3d")]
        [InlineData("ffffffffffffffffffffffff80000000", "649f1cddc3792b4638635a392bc9bade")]
        [InlineData("ffffffffffffffffffffffffc0000000", "e2775e4b59c1bc2e31a2078c11b5a08c")]
        [InlineData("ffffffffffffffffffffffffe0000000", "2be1fae5048a25582a679ca10905eb80")]
        [InlineData("fffffffffffffffffffffffff0000000", "da86f292c6f41ea34fb2068df75ecc29")]
        [InlineData("fffffffffffffffffffffffff8000000", "220df19f85d69b1b562fa69a3c5beca5")]
        [InlineData("fffffffffffffffffffffffffc000000", "1f11d5d0355e0b556ccdb6c7f5083b4d")]
        [InlineData("fffffffffffffffffffffffffe000000", "62526b78be79cb384633c91f83b4151b")]
        [InlineData("ffffffffffffffffffffffffff000000", "90ddbcb950843592dd47bbef00fdc876")]
        [InlineData("ffffffffffffffffffffffffff800000", "2fd0e41c5b8402277354a7391d2618e2")]
        [InlineData("ffffffffffffffffffffffffffc00000", "3cdf13e72dee4c581bafec70b85f9660")]
        [InlineData("ffffffffffffffffffffffffffe00000", "afa2ffc137577092e2b654fa199d2c43")]
        [InlineData("fffffffffffffffffffffffffff00000", "8d683ee63e60d208e343ce48dbc44cac")]
        [InlineData("fffffffffffffffffffffffffff80000", "705a4ef8ba2133729c20185c3d3a4763")]
        [InlineData("fffffffffffffffffffffffffffc0000", "0861a861c3db4e94194211b77ed761b9")]
        [InlineData("fffffffffffffffffffffffffffe0000", "4b00c27e8b26da7eab9d3a88dec8b031")]
        [InlineData("ffffffffffffffffffffffffffff0000", "5f397bf03084820cc8810d52e5b666e9")]
        [InlineData("ffffffffffffffffffffffffffff8000", "63fafabb72c07bfbd3ddc9b1203104b8")]
        [InlineData("ffffffffffffffffffffffffffffc000", "683e2140585b18452dd4ffbb93c95df9")]
        [InlineData("ffffffffffffffffffffffffffffe000", "286894e48e537f8763b56707d7d155c8")]
        [InlineData("fffffffffffffffffffffffffffff000", "a423deabc173dcf7e2c4c53e77d37cd1")]
        [InlineData("fffffffffffffffffffffffffffff800", "eb8168313e1cfdfdb5e986d5429cf172")]
        [InlineData("fffffffffffffffffffffffffffffc00", "27127daafc9accd2fb334ec3eba52323")]
        [InlineData("fffffffffffffffffffffffffffffe00", "ee0715b96f72e3f7a22a5064fc592f4c")]
        [InlineData("ffffffffffffffffffffffffffffff00", "29ee526770f2a11dcfa989d1ce88830f")]
        [InlineData("ffffffffffffffffffffffffffffff80", "0493370e054b09871130fe49af730a5a")]
        [InlineData("ffffffffffffffffffffffffffffffc0", "9b7b940f6c509f9e44a4ee140448ee46")]
        [InlineData("ffffffffffffffffffffffffffffffe0", "2915be4a1ecfdcbe3e023811a12bb6c7")]
        [InlineData("fffffffffffffffffffffffffffffff0", "7240e524bc51d8c4d440b1be55d1062c")]
        [InlineData("fffffffffffffffffffffffffffffff8", "da63039d38cb4612b2dc36ba26684b93")]
        [InlineData("fffffffffffffffffffffffffffffffc", "0f59cb5a4b522e2ac56c1a64f558ad9a")]
        [InlineData("fffffffffffffffffffffffffffffffe", "7bfe9d876c6d63c1d035da8fe21c409d")]
        [InlineData("ffffffffffffffffffffffffffffffff", "acdace8078a32b1a182bfa4987ca1347")]
        public void KeyVarTxtKat(string plaintext, string expectedCiphertext)
        {
            VerifyVarTxtKat("0000000000000000000000000000000000000000000000000000000000000000".HexToByteArray(), plaintext.HexToByteArray(), "00000000000000000000000000000000".HexToByteArray(), expectedCiphertext.HexToByteArray());
        }

        [Fact]
        public void EmptySpan()
        {
            VerifyEmptySpan("0000000000000000000000000000000000000000000000000000000000000000".HexToByteArray(), "00000000000000000000000000000000".HexToByteArray());
        }

        private protected override AesDecryptor CreateDecryptor()
            => new AesCbcDecryptor(EncryptionAlgorithm.Aes256CbcHmacSha512);

        private protected override AesEncryptor CreateEncryptor()
            => new AesCbcEncryptor(EncryptionAlgorithm.Aes256CbcHmacSha512);
    }
}
