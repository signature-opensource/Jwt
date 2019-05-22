// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Security.Cryptography;
using System.Text;

namespace JsonWebToken
{
    /// <summary>
    /// Constants for JsonWebKey Elliptical Curve Types
    /// https://tools.ietf.org/html/rfc7518#section-6.2.1.1
    /// </summary>
    public readonly struct EllipticalCurve
    {
        /// <summary>
        /// 'P-256'.
        /// </summary>
        public static ReadOnlySpan<byte> P256Name => new byte[] { (byte)'P', (byte)'-', (byte)'2', (byte)'5', (byte)'6' };


        /// <summary>
        /// 'P-256'.
        /// </summary>
        public static EllipticalCurve P256 => new EllipticalCurve(ECCurve.NamedCurves.nistP256, P256Name.ToArray(), 256, 64);

        /// <summary>
        /// 'P-384'.
        /// </summary>
        public static ReadOnlySpan<byte> P384Name => new byte[] { (byte)'P', (byte)'-', (byte)'3', (byte)'8', (byte)'4' };

        /// <summary>
        /// 'P-384'.
        /// </summary>
        public static EllipticalCurve P384 => new EllipticalCurve(ECCurve.NamedCurves.nistP384, P384Name.ToArray(), 384, 96);

        /// <summary>
        /// 'P-521'.
        /// </summary>    
        public static ReadOnlySpan<byte> P521Name => new byte[] { (byte)'P', (byte)'-', (byte)'5', (byte)'2', (byte)'1' };

        /// <summary>
        /// 'P-521'.
        /// </summary>    
        public static EllipticalCurve P521 => new EllipticalCurve(ECCurve.NamedCurves.nistP521, P521Name.ToArray(), 521, 132);

        /// <summary>
        /// Initializes a new instance of the <see cref="EllipticalCurve"/> struct.
        /// </summary>
        /// <param name="namedCurve"></param>
        /// <param name="name"></param>
        /// <param name="keySizeInBits"></param>
        /// <param name="hashSize"></param>
        public EllipticalCurve(ECCurve namedCurve, byte[] name, int keySizeInBits, int hashSize)
        {
            KeySizeInBits = keySizeInBits;
            Name = name;
            CurveParameters = namedCurve;
            HashSize = hashSize;
        }

        /// <summary>
        /// The name of the curve.
        /// </summary>
        public readonly byte[] Name;

        /// <summary>
        /// The size of the key, in bits
        /// </summary>
        public readonly int KeySizeInBits;

        /// <summary>
        /// The parameters curve.
        /// </summary>
        public readonly ECCurve CurveParameters;

        /// <summary>
        /// The size of the resulting hash.
        /// </summary>
        public readonly int HashSize;

        /// <summary>
        /// Returns the <see cref="EllipticalCurve"/> corresponding to the <paramref name="crv"/>.
        /// </summary>
        /// <param name="crv"></param>
        /// <returns></returns>
        public static EllipticalCurve FromString(string crv)
        {
            switch (crv)
            {
                case "P-256":
                    return P256;
                case "P-384":
                    return P384;
                case "P-521":
                    return P521;
                default:
                    Errors.ThrowNotSupportedCurve(crv);
                    return default;
            }
        }

        /// <summary>
        /// Returns the <see cref="EllipticalCurve"/> corresponding to the <paramref name="crv"/>.
        /// </summary>
        /// <param name="crv"></param>
        /// <returns></returns>
        public static EllipticalCurve FromSpan(ReadOnlySpan<byte> crv)
        {
            if (crv.SequenceEqual(P256Name))
            {
                return P256;
            }
            else if (crv.SequenceEqual(P384Name))
            {
                return P384;
            }
            else if (crv.SequenceEqual(P521Name))
            {
                return P521;
            }

            Errors.ThrowNotSupportedCurve(Encoding.UTF8.GetString(crv.ToArray()));
            return default;
        }
    }
}