﻿// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Text;
#if NETCOREAPP3_0
using System.Text.Json;
#endif

namespace JsonWebToken
{
    /// <summary>
    /// Defines a signed JWT with a JSON payload.
    /// </summary>
    public partial class JwsDescriptor : JwtDescriptor<JwtObject>
    {
        private const byte dot = (byte)'.';
        private static readonly ReadOnlyDictionary<string, JwtTokenType[]> DefaultRequiredClaims = new ReadOnlyDictionary<string, JwtTokenType[]>(new Dictionary<string, JwtTokenType[]>());
        private static readonly string[] DefaultProhibitedClaims = Array.Empty<string>();
        private static readonly ReadOnlyDictionary<string, JwtTokenType[]> JwsRequiredHeaderParameters = new ReadOnlyDictionary<string, JwtTokenType[]>(
            new Dictionary<string, JwtTokenType[]>
            {
                { HeaderParameters.Alg, new [] { JwtTokenType.String } }
            });

        /// <summary>
        /// Initializes a new instance of <see cref="JwsDescriptor"/>.
        /// </summary>
        public JwsDescriptor()
            : base(new JwtObject(), new JwtObject())
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="JwsDescriptor"/>.
        /// </summary>
        public JwsDescriptor(JwtObject header, JwtObject payload)
            : base(header, payload)
        {
        }

        /// <summary>
        /// Gets the required claims of the <see cref="JwsDescriptor"/>.
        /// </summary>
        protected virtual ReadOnlyDictionary<string, JwtTokenType[]> RequiredClaims => DefaultRequiredClaims;

        /// <summary>
        /// gets the prohibited claims of the <see cref="JwsDescriptor"/>.
        /// </summary>
        protected virtual IReadOnlyList<string> ProhibitedClaims => DefaultProhibitedClaims;

        /// <summary>
        /// Gets the required header parameters of the <see cref="JwsDescriptor"/>. 
        /// </summary>
        protected override ReadOnlyDictionary<string, JwtTokenType[]> RequiredHeaderParameters => JwsRequiredHeaderParameters;

        /// <summary>
        /// Gets or sets the value of the 'sub' claim.
        /// </summary>
        public string Subject
        {
            get { return GetStringClaim(Claims.SubUtf8); }
            set { AddClaim(Claims.SubUtf8, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'jti' claim.
        /// </summary>
        public string JwtId
        {
            get { return GetStringClaim(Claims.JtiUtf8); }
            set { AddClaim(Claims.JtiUtf8, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'aud' claim.
        /// </summary>
        public string Audience
        {
            get { return Audiences?.FirstOrDefault(); }
            set { SetClaim(Claims.AudUtf8, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'aud' claim.
        /// </summary>
        public List<string> Audiences
        {
            get { return GetListClaims<string>(Claims.Aud); }
            set { SetClaim(Claims.AudUtf8, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'exp' claim.
        /// </summary>
        public DateTime? ExpirationTime
        {
            get { return GetDateTime(Claims.ExpUtf8); }
            set { AddClaim(Claims.ExpUtf8, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'iss' claim.
        /// </summary>
        public string Issuer
        {
            get { return GetStringClaim(Claims.IssUtf8); }
            set { AddClaim(Claims.IssUtf8, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'iat' claim.
        /// </summary>
        public DateTime? IssuedAt
        {
            get { return GetDateTime(Claims.IatUtf8); }
            set { AddClaim(Claims.IatUtf8, value); }
        }

        /// <summary>
        ///Gets or sets the value of the 'nbf' claim.
        /// </summary>
        public DateTime? NotBefore
        {
            get { return GetDateTime(Claims.NbfUtf8); }
            set { AddClaim(Claims.NbfUtf8, value); }
        }

        /// <summary>
        /// Adds a claim;
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public void AddClaim(byte[] utf8Name, string value)
        {
            // TODO: allow to add a value into an array
            Payload.Add(new JwtProperty(utf8Name, value));
        }

        /// <summary>
        /// Adds a claim;
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public void AddClaim(string name, string value)
        {
            AddClaim(Encoding.UTF8.GetBytes(name), value);
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public void AddClaim(byte[] utf8Name, bool? value)
        {
            if (value.HasValue)
            {
                Payload.Add(new JwtProperty(utf8Name, value.Value));
            }
            else
            {
                Payload.Add(new JwtProperty(utf8Name));
            }
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public void AddClaim(string name, bool? value)
        {
            AddClaim(Encoding.UTF8.GetBytes(name), value);
        }
        
        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public void AddClaim(byte[] utf8Name, DateTime? value)
        {
            if (value.HasValue)
            {
                Payload.Add(new JwtProperty(utf8Name, value.Value.ToEpochTime()));
            }
            else
            {
                Payload.Add(new JwtProperty(utf8Name));
            }
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public void AddClaim(string name, DateTime? value)
        {
            AddClaim(Encoding.UTF8.GetBytes(name), value);
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public void AddClaim(byte[] utf8Name, int value)
        {
            Payload.Add(new JwtProperty(utf8Name, value));
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public void AddClaim(string name, int value)
        {
            AddClaim(Encoding.UTF8.GetBytes(name), value);
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public void AddClaim(byte[] utf8Name, bool value)
        {
            Payload.Add(new JwtProperty(utf8Name, value));
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public void AddClaim(string name, bool value)
        {
            AddClaim(Encoding.UTF8.GetBytes(name), value);
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public void AddClaim(byte[] utf8Name, JwtObject value)
        {
            Payload.Add(new JwtProperty(utf8Name, value));
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public void AddClaim(string name, JwtObject value)
        {
            AddClaim(Encoding.UTF8.GetBytes(name), value);
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public void AddClaim(byte[] utf8Name, JwtProperty value)
        {
            JwtObject jwtObject;
            if (Payload.TryGetValue(utf8Name, out JwtProperty property) && property.Type == JwtTokenType.Object)
            {
                jwtObject = (JwtObject)property.Value;
            }
            else
            {
                jwtObject = new JwtObject();
                Payload.Add(new JwtProperty(utf8Name, jwtObject));
            }

            jwtObject.Add(value);
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public void AddClaim(string name, JwtProperty value)
        {
            AddClaim(Encoding.UTF8.GetBytes(name), value);
        }

        /// <summary>
        /// Gets a claim as <see cref="string"/>.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <returns></returns>
        protected string GetStringClaim(byte[] utf8Name)
        {
            if (Payload.TryGetValue(utf8Name, out JwtProperty value))
            {
                return (string)value.Value;
            }

            return null;
        }

        /// <summary>
        /// Gets a claim as <see cref="int"/>.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <returns></returns>
        protected int? GetInt32Claim(byte[] utf8Name)
        {
            if (Payload.TryGetValue(utf8Name, out JwtProperty value))
            {
                return (int)value.Value;
            }

            return null;
        }

        /// <summary>
        /// Gets a claim as <typeparamref name="TClaim"/>.
        /// </summary>
        /// <param name="claimType"></param>
        /// <returns></returns>
        protected TClaim? GetClaim<TClaim>(byte[] claimType) where TClaim : struct
        {
            if (Payload.TryGetValue(claimType, out JwtProperty value))
            {
                return (TClaim?)value.Value;
            }

            return null;
        }

        /// <summary>
        /// Gets a claim as <see cref="bool"/>.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <returns></returns>
        protected bool? GetBoolClaim(byte[] utf8Name)
        {
            if (Payload.TryGetValue(utf8Name, out JwtProperty value))
            {
                return (bool?)value.Value;
            }

            return null;
        }

        /// <summary>
        /// Gets a claim as a list of <see cref="string"/>.
        /// </summary>
        /// <param name="claimType"></param>
        /// <returns></returns>
        protected List<T> GetListClaims<T>(string claimType)
        {
            if (Payload.TryGetValue(claimType, out JwtProperty value))
            {
                if (value.Type == JwtTokenType.Array)
                {
                    return (List<T>)value.Value;
                }

                var list = new List<T> { (T)value.Value };
                return list;
            }

            return null;
        }

        /// <summary>
        /// Gets a claim as <see cref="JwtObject"/>.
        /// </summary>
        /// <param name="claimType"></param>
        /// <returns></returns>
        protected JwtObject GetClaim(byte[] claimType)
        {
            if (Payload.TryGetValue(claimType, out JwtProperty value) && value.Type == JwtTokenType.Object)
            {
                return (JwtObject)value.Value;
            }

            return null;
        }

        /// <summary>
        /// Sets a claim as <see cref="string"/>.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        protected void SetClaim(byte[] utf8Name, string value)
        {
            Payload.Add(new JwtProperty(utf8Name, value));
        }

        /// <summary>
        /// Gets a claim as a list of <see cref="string"/>.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        protected void SetClaim(byte[] utf8Name, List<string> value)
        {
            var list = new List<JwtValue>(value.Count);
            for (int i = 0; i < value.Count; i++)
            {
                list.Add(new JwtValue(value[i]));
            }

            Payload.Add(new JwtProperty(utf8Name, new JwtArray(list)));
        }

        /// <summary>
        /// Gets a claim as <see cref="DateTime"/>.
        /// </summary>
        /// <param name="claimType"></param>
        /// <returns></returns>
        protected DateTime? GetDateTime(byte[] claimType)
        {
            if (!Payload.TryGetValue(claimType, out JwtProperty dateValue) || dateValue.Type == JwtTokenType.Null)
            {
                return null;
            }

            return EpochTime.ToDateTime((long)dateValue.Value);
        }

        /// <inheritsdoc />
        public override byte[] Encode(EncodingContext context)
        {
            Signer signatureProvider = null;
            var alg = (SignatureAlgorithm)(Algorithm ?? Key?.Alg);
            if (Key != null)
            {
                signatureProvider = context.SignatureFactory.Create(Key, alg, willCreateSignatures: true);
                if (signatureProvider == null)
                {
                    Errors.ThrowNotSupportedSignatureAlgorithm(alg, Key);
                }
            }

            if (context.TokenLifetimeInMinutes != 0 || context.GenerateIssuedTime)
            {
                DateTime now = DateTime.UtcNow;
                if (context.GenerateIssuedTime && !Payload.ContainsKey(Claims.IatUtf8))
                {
                    AddClaim(Claims.IatUtf8, now);
                }

                if (context.TokenLifetimeInMinutes != 0 && !Payload.ContainsKey(Claims.ExpUtf8))
                {
                    AddClaim(Claims.ExpUtf8, now + TimeSpan.FromMinutes(context.TokenLifetimeInMinutes));
                }
            }

            var payloadJson = Serialize(Payload);
            int length = Base64Url.GetArraySizeRequiredToEncode((int)payloadJson.Length)
                       + (Key == null ? 0 : Base64Url.GetArraySizeRequiredToEncode(signatureProvider.HashSizeInBytes))
                       + (Constants.JwsSegmentCount - 1);
            ReadOnlySequence<byte> headerJson = default;
            var headerCache = context.HeaderCache;
            byte[] cachedHeader = null;
            if (headerCache != null && headerCache.TryGetHeader(Header, alg, out cachedHeader))
            {
                length += cachedHeader.Length;
            }
            else
            {
                headerJson = Serialize(Header);
                length += Base64Url.GetArraySizeRequiredToEncode((int)headerJson.Length);
            }

            byte[] bufferToReturn = new byte[length];
            var buffer = bufferToReturn.AsSpan();
            int headerBytesWritten;
            if (cachedHeader != null)
            {
                cachedHeader.CopyTo(buffer);
                headerBytesWritten = cachedHeader.Length;
            }
            else
            {
                TryEncodeUtf8ToBase64Url(headerJson, buffer, out headerBytesWritten);
                headerCache?.AddHeader(Header, alg, buffer.Slice(0, headerBytesWritten));
            }

            buffer[headerBytesWritten] = dot;
            TryEncodeUtf8ToBase64Url(payloadJson, buffer.Slice(headerBytesWritten + 1), out int payloadBytesWritten);
            buffer[payloadBytesWritten + headerBytesWritten + 1] = dot;
            int bytesWritten = 0;
            if (signatureProvider != null)
            {
                Span<byte> signature = stackalloc byte[signatureProvider.HashSizeInBytes];
                bool success = signatureProvider.TrySign(buffer.Slice(0, payloadBytesWritten + headerBytesWritten + 1), signature, out int signatureBytesWritten);
                Debug.Assert(success);
                Debug.Assert(signature.Length == signatureBytesWritten);

                bytesWritten = Base64Url.Base64UrlEncode(signature, buffer.Slice(payloadBytesWritten + headerBytesWritten + (Constants.JwsSegmentCount - 1)));
            }

            Debug.Assert(buffer.Length == payloadBytesWritten + headerBytesWritten + (Constants.JwsSegmentCount - 1) + bytesWritten);
            return bufferToReturn;
        }

        private static bool TryEncodeUtf8ToBase64Url(ReadOnlySequence<byte> input, Span<byte> destination, out int bytesWritten)
        {
            if (input.IsSingleSegment)
            {
                bytesWritten = Base64Url.Base64UrlEncode(input.First.Span, destination);
                return bytesWritten == destination.Length;
            }
            else
            {
                byte[] arrayToReturnToPool = null;
                try
                {
                    var encodedBytes = input.Length <= Constants.MaxStackallocBytes
                          ? stackalloc byte[(int)input.Length]
                          : (arrayToReturnToPool = ArrayPool<byte>.Shared.Rent((int)input.Length)).AsSpan(0, (int)input.Length);

                    input.CopyTo(encodedBytes);
                    bytesWritten = Base64Url.Base64UrlEncode(encodedBytes, destination);
                    return bytesWritten == destination.Length;
                }
                finally
                {
                    if (arrayToReturnToPool != null)
                    {
                        ArrayPool<byte>.Shared.Return(arrayToReturnToPool);
                    }
                }
            }

        }

        /// <inheritsdoc />
        public override void Validate()
        {
            for (int i = 0; i < ProhibitedClaims.Count; i++)
            {
                if (Payload.ContainsKey(Encoding.UTF8.GetBytes(ProhibitedClaims[i])))
                {
                    Errors.ThrowClaimIsProhibited(ProhibitedClaims[i]);
                }
            }

            foreach (var claim in RequiredClaims)
            {
                if (!Payload.TryGetValue(claim.Key, out JwtProperty token) || token.Type == JwtTokenType.Null)
                {
                    Errors.ThrowClaimIsRequired(claim.Key);
                }

                bool claimFound = false;
                for (int i = 0; i < claim.Value.Length; i++)
                {
                    if (token.Type == claim.Value[i])
                    {
                        claimFound = true;
                        break;
                    }
                }

                if (!claimFound)
                {
                    Errors.ThrowClaimMustBeOfType(claim);
                }
            }

            base.Validate();
        }
    }
}