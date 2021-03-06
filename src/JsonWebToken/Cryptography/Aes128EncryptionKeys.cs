﻿// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if SUPPORT_SIMD
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace JsonWebToken.Cryptography
{
    internal readonly struct Aes128EncryptionKeys
    {
        private const int Count = 11;

        public readonly Vector128<byte> Key0;
        public readonly Vector128<byte> Key1;
        public readonly Vector128<byte> Key2;
        public readonly Vector128<byte> Key3;
        public readonly Vector128<byte> Key4;
        public readonly Vector128<byte> Key5;
        public readonly Vector128<byte> Key6;
        public readonly Vector128<byte> Key7;
        public readonly Vector128<byte> Key8;
        public readonly Vector128<byte> Key9;
        public readonly Vector128<byte> Key10;

        public Aes128EncryptionKeys(ReadOnlySpan<byte> key)
        {
            if (key.Length < 16)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(EncryptionAlgorithm.A128CbcHS256, 128, key.Length * 8);
            }

            Key0 = Unsafe.ReadUnaligned<Vector128<byte>>(ref MemoryMarshal.GetReference(key));
            Key1 = KeyGenAssist(Key0, 0x01);
            Key2 = KeyGenAssist(Key1, 0x02);
            Key3 = KeyGenAssist(Key2, 0x04);
            Key4 = KeyGenAssist(Key3, 0x08);
            Key5 = KeyGenAssist(Key4, 0x10);
            Key6 = KeyGenAssist(Key5, 0x20);
            Key7 = KeyGenAssist(Key6, 0x40);
            Key8 = KeyGenAssist(Key7, 0x80);
            Key9 = KeyGenAssist(Key8, 0x1B);
            Key10 = KeyGenAssist(Key9, 0x36);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> KeyGenAssist(Vector128<byte> key, byte control)
        {
            var keyGened = Aes.KeygenAssist(key, control);
            keyGened = Sse2.Shuffle(keyGened.AsInt32(), 0xFF).AsByte();
            key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 4));
            key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 4));
            key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 4));
            return Sse2.Xor(key, keyGened);
        }

        public void Clear()
        {
            ref byte that = ref Unsafe.As<Aes128EncryptionKeys, byte>(ref Unsafe.AsRef(this));
            Unsafe.InitBlock(ref that, 0, Count * 16);
        }
    }
}
#endif