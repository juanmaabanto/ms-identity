using System;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace Sofisoft.Accounts.Identity.API.Utils
{
    public static class PasswordHasher
    {
        public static string HashPassword(string password)
        {
            int iterCount = 1;
            int numBytesRequested = 256 / 8;
            int saltSize = 128 / 8;
            var prf = KeyDerivationPrf.HMACSHA256;
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            byte[] salt = new byte[saltSize];
            rng.GetBytes(salt);
            byte[] subkey = KeyDerivation.Pbkdf2(password, salt, prf, iterCount, numBytesRequested);
            var outputBytes = new byte[13 + salt.Length + subkey.Length];

            outputBytes[0] = 0x01;
            WriteNetworkByteOrder(outputBytes, 1, (uint)prf);
            WriteNetworkByteOrder(outputBytes, 5, (uint)iterCount);
            WriteNetworkByteOrder(outputBytes, 9, (uint)saltSize);
            Buffer.BlockCopy(salt, 0, outputBytes, 13, salt.Length);
            Buffer.BlockCopy(subkey, 0, outputBytes, 13 + saltSize, subkey.Length);

            return Convert.ToBase64String(outputBytes);
        }

        public static bool VerifyHashedPassword(string hashedPassword, string providedPassword)
        {
            if (hashedPassword == null)
            {
                throw new ArgumentNullException(nameof(hashedPassword));
            }

            if (providedPassword == null)
            {
                throw new ArgumentNullException(nameof(providedPassword));
            }

            byte[] decodedHashedPassword = Convert.FromBase64String(hashedPassword);

            if (decodedHashedPassword.Length == 0)
            {
                return false;
            }

            if(decodedHashedPassword[0] == 0x01)
            {
                int iterCount = default(int);

                try
                {
                    KeyDerivationPrf prf = (KeyDerivationPrf)ReadNetworkByteOrder(decodedHashedPassword, 1);
                    int saltLength = (int)ReadNetworkByteOrder(decodedHashedPassword, 9);

                    iterCount = (int)ReadNetworkByteOrder(decodedHashedPassword, 5);

                    if (saltLength < 128 / 8)
                    {
                        return false;
                    }

                    byte[] salt = new byte[saltLength];
                    Buffer.BlockCopy(decodedHashedPassword, 13, salt, 0, salt.Length);

                    int subkeyLength = decodedHashedPassword.Length - 13 - salt.Length;
                    if (subkeyLength < 128 / 8)
                    {
                        return false;
                    }
                    byte[] expectedSubkey = new byte[subkeyLength];
                    Buffer.BlockCopy(decodedHashedPassword, 13 + salt.Length, expectedSubkey, 0, expectedSubkey.Length);

                    byte[] actualSubkey = KeyDerivation.Pbkdf2(providedPassword, salt, prf, iterCount, subkeyLength);
                    return ByteArraysEqual(actualSubkey, expectedSubkey);
                }
                catch (Exception)
                {
                    return false;
                }
                
            }
            else
            {
                return false;
            }
        }

        private static bool ByteArraysEqual(byte[] a, byte[] b)
        {
            if (a == null && b == null)
            {
                return true;
            }
            if (a == null || b == null || a.Length != b.Length)
            {
                return false;
            }
            var areSame = true;
            for (var i = 0; i < a.Length; i++)
            {
                areSame &= (a[i] == b[i]);
            }
            return areSame;
        }

        private static uint ReadNetworkByteOrder(byte[] buffer, int offset)
        {
            return ((uint)(buffer[offset + 0]) << 24)
                | ((uint)(buffer[offset + 1]) << 16)
                | ((uint)(buffer[offset + 2]) << 8)
                | ((uint)(buffer[offset + 3]));
        }

        private static void WriteNetworkByteOrder(byte[] buffer, int offset, uint value)
        {
            buffer[offset + 0] = (byte)(value >> 24);
            buffer[offset + 1] = (byte)(value >> 16);
            buffer[offset + 2] = (byte)(value >> 8);
            buffer[offset + 3] = (byte)(value >> 0);
        }
    }
}