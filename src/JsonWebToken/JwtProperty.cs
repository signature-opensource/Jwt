﻿// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Buffers;

namespace JsonWebToken
{

    [DebuggerDisplay("{DebuggerDisplay(),nq}")]
    public readonly struct JwtProperty
    {
        public bool IsEmpty => Utf8Name.IsEmpty;

        public readonly JwtTokenType Type;

        public readonly ReadOnlyMemory<byte> Utf8Name;

        public readonly object Value;

        public JwtProperty(byte[] utf8Name, JwtArray value)
        {
            Type = JwtTokenType.Array;
            Utf8Name = utf8Name;
            Value = value;
        }

        public JwtProperty(byte[] utf8Name, JwtObject value)
        {
            Type = JwtTokenType.Object;
            Utf8Name = utf8Name;
            Value = value ?? throw new ArgumentNullException(nameof(value));
        }

        public JwtProperty(byte[] utf8Name, string value)
        {
            Type = JwtTokenType.String;
            Utf8Name = utf8Name;
            Value = value ?? throw new ArgumentNullException(nameof(value));
        }

        public JwtProperty(byte[] utf8Name, byte[] value)
        {
            Type = JwtTokenType.Utf8String;
            Utf8Name = utf8Name;
            Value = value;
        }

        public JwtProperty(byte[] utf8Name, long value)
        {
            Type = JwtTokenType.Integer;
            Utf8Name = utf8Name;
            Value = value;
        }

        public JwtProperty(byte[] utf8Name, int value)
        {
            Type = JwtTokenType.Integer;
            Utf8Name = utf8Name;
            Value = value;
        }

        public JwtProperty(byte[] utf8Name, double value)
        {
            Type = JwtTokenType.Float;
            Utf8Name = utf8Name;
            Value = value;
        }

        public JwtProperty(byte[] utf8Name, float value)
        {
            Type = JwtTokenType.Float;
            Utf8Name = utf8Name;
            Value = value;
        }

        public JwtProperty(byte[] utf8Name, bool value)
        {
            Type = JwtTokenType.Boolean;
            Utf8Name = utf8Name;
            Value = value;
        }

        public JwtProperty(byte[] utf8Name)
        {
            Type = JwtTokenType.Null;
            Utf8Name = utf8Name;
            Value = null;
        }

        internal void WriteTo(ref Utf8JsonWriter writer)
        {
            switch (Type)
            {
                case JwtTokenType.Object:
                    ((JwtObject)Value).WriteTo(ref writer, Utf8Name.Span);
                    break;
                case JwtTokenType.Array:
                    ((JwtArray)Value).WriteTo(ref writer, Utf8Name.Span);
                    break;
                case JwtTokenType.Integer:
                    writer.WriteNumber(Utf8Name.Span, (long)Value);
                    break;
                case JwtTokenType.Float:
                    writer.WriteNumber(Utf8Name.Span, (double)Value);
                    break;
                case JwtTokenType.String:
                    writer.WriteString(Utf8Name.Span, (string)Value, false);
                    break;
                case JwtTokenType.Utf8String:
                    writer.WriteString(Utf8Name.Span, (byte[])Value, false);
                    break;
                case JwtTokenType.Boolean:
                    writer.WriteBoolean(Utf8Name.Span, (bool)Value);
                    break;
                case JwtTokenType.Null:
                    writer.WriteNull(Utf8Name.Span);
                    break;
                default:
                    throw new JsonWriterException($"The type {Type} is not supported.");
            }
        }

        /// <inheritsdoc />
        public override int GetHashCode()
        {
            return Utf8Name.GetHashCode();
        }

        /// <inheritsdoc />
        public override bool Equals(object obj)
        {
            if (obj is null)
            {
                return false;
            }

            if (obj is ReadOnlyMemory<byte> rom)
            {
                return Utf8Name.Equals(rom);
            }

            return false;
        }

        private string DebuggerDisplay()
        {
            var bufferWriter = new BufferWriter();
            {
                Utf8JsonWriter writer = new Utf8JsonWriter(bufferWriter, new JsonWriterState(new JsonWriterOptions { Indented = true }));

                writer.WriteStartObject();
                WriteTo(ref writer);
                writer.WriteEndObject();
                writer.Flush();

                var input = bufferWriter.GetSequence();
                if (input.IsSingleSegment)
                {
                    return Encoding.UTF8.GetString(input.First.Span.ToArray());
                }
                else
                {
                    var encodedBytes = new byte[(int)input.Length];

                    input.CopyTo(encodedBytes);
                    return Encoding.UTF8.GetString(encodedBytes);
                }
            }
        }
    }
}