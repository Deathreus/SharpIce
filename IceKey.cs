// Purpose: C# implementation of the ICE encryption algorithm. Based on the C++ implementation by Valve.
//			Taken from public domain code, as written by Matthew Kwan - July 1996
//			http://www.darkside.com.au/ice/

namespace SharpIce
{
    public class IceKey
    {
        /* The S-boxes */
        private static readonly ulong[,] ICESBox = new ulong[4, 1024];
        private static bool SBoxesInitialized = false;


        /* Modulo values for the S-boxes */
        private static readonly uint[,] ICESMod = new uint[4, 4]{
                        {333, 313, 505, 369},
                        {379, 375, 319, 391},
                        {361, 445, 451, 397},
                        {397, 425, 395, 505}};

        /* XOR values for the S-boxes */
        private static readonly uint[,] ICEXOR = new uint[4, 4]{
                        {0x83, 0x85, 0x9b, 0xcd},
                        {0xcc, 0xa7, 0xad, 0x41},
                        {0x4b, 0x2e, 0xd4, 0x33},
                        {0xea, 0xcb, 0x2e, 0x04}};

        /* Permutation values for the P-box */
        private static readonly ulong[] ICEPBox = new ulong[32]{
                        0x00000001, 0x00000080, 0x00000400, 0x00002000,
                        0x00080000, 0x00200000, 0x01000000, 0x40000000,
                        0x00000008, 0x00000020, 0x00000100, 0x00004000,
                        0x00010000, 0x00800000, 0x04000000, 0x20000000,
                        0x00000004, 0x00000010, 0x00000200, 0x00008000,
                        0x00020000, 0x00400000, 0x08000000, 0x10000000,
                        0x00000002, 0x00000040, 0x00000800, 0x00001000,
                        0x00040000, 0x00100000, 0x02000000, 0x80000000};

        /* The key rotation schedule */
        private static readonly int[][] ICEKeyRotation = new int[2][]{
                        new int[8]{0, 1, 2, 3, 2, 1, 3, 0},
                        new int[8]{1, 3, 2, 0, 3, 1, 0, 2}};
        /*
         * 8-bit Galois Field multiplication of a by b, modulo m.
         * Just like arithmetic multiplication, except that additions and
         * subtractions are replaced by XOR.
         */
        private uint GaloisFieldMult(uint a, uint b, uint mod)
        {
            uint res = 0;

            while (b > 0)
            {
                if ((b & 1) != 0)
                    res ^= a;

                a <<= 1;
                b >>= 1;

                if (a >= 256)
                    a ^= mod;
            }

            return res;
        }
        /*
         * Galois Field exponentiation.
         * Raise the base to the power of 7, modulo m.
         */
        private ulong GaloisFieldExp7(uint @base, uint mod)
        {
            if (@base == 0)
                return 0;

            uint x = GaloisFieldMult(@base, @base, mod);
            x = GaloisFieldMult(@base, x, mod);
            x = GaloisFieldMult(x, x, mod);
            return GaloisFieldMult(@base, x, mod);
        }
        /*
         * Carry out the ICE 32-bit P-box permutation.
         */
        private ulong ICEPerm32(ulong exp)
        {
            ulong res = 0;
            int pbox = 0;

            while (exp > 0)
            {
                if ((exp & 1) > 0)
                    res |= ICEPBox[pbox];

                pbox++;
                exp >>= 1;
            }

            return res;
        }
        /*
         * The single round ICE f function.
         */
        private ulong ICEFormulate(ulong perm, IceSubKey subKey)
        {
            ulong tl, tr;       /* Expanded 40-bit values */
            ulong al, ar;       /* Salted expanded 40-bit values */

            /* Left half expansion */
            tl = ((perm >> 16) & 0x3FF) | (((perm >> 14) | (perm << 18)) & 0xFFC00);

            /* Right half expansion */
            tr = (perm & 0x3FF) | ((perm << 2) & 0xFFC00);

            /* Perform the salt permutation */
            // al = (tr & sk->val[2]) | (tl & ~sk->val[2]);
            // ar = (tl & sk->val[2]) | (tr & ~sk->val[2]);
            al = subKey.Val[2] & (tl ^ tr);
            ar = al ^ tr;
            al ^= tl;

            al ^= subKey.Val[0];   /* XOR with the subkey */
            ar ^= subKey.Val[1];

            /* S-box lookup and permutation */
            return ICESBox[0, (al >> 10)] | ICESBox[1, (al & 0x3FF)] | ICESBox[2, (ar >> 10)] | ICESBox[3, (ar & 0x3FF)];
        }
        /*
         * Initialise the ICE S-boxes.
         * This only has to be done once.
         */
        private void IceSBoxesInit()
        {
            for (int i = 0; i < 1024; i++)
            {
                int column = (i >> 1) & 0xFF;
                int row = (i & 0x1) | ((i & 0x200) >> 8);
                ulong exp;

                exp = GaloisFieldExp7((uint)column ^ ICEXOR[0, row], ICESMod[0, row]) << 24;
                ICESBox[0, i] = ICEPerm32(exp);

                exp = GaloisFieldExp7((uint)column ^ ICEXOR[1, row], ICESMod[1, row]) << 16;
                ICESBox[1, i] = ICEPerm32(exp);

                exp = GaloisFieldExp7((uint)column ^ ICEXOR[2, row], ICESMod[2, row]) << 8;
                ICESBox[2, i] = ICEPerm32(exp);

                exp = GaloisFieldExp7((uint)column ^ ICEXOR[3, row], ICESMod[3, row]);
                ICESBox[3, i] = ICEPerm32(exp);
            }
        }
        /*
         * Set 8 rounds [n, n+7] of the key schedule of an ICE key.
         */
        private void ScheduleBuild(ushort[] keyBuild, int n, int[] keyRotations)
        {
            for (int i = 0; i < 8; i++)
            {
                int keyRotation = keyRotations[i];
                IceSubKey subKeys = _keysched[n + i];

                for (int j = 0; j < 3; j++)
                    subKeys.Val[j] = 0;

                for (int j = 0; j < 15; j++)
                {
                    ref ulong currSubKey = ref subKeys.Val[j % 3];

                    for (int k = 0; k < 4; k++)
                    {
                        ref ushort currKeyBuild = ref keyBuild[(keyRotation + k) & 3];
                        int bit = currKeyBuild & 1;

                        currSubKey = (currSubKey << 1) | (uint)bit;
                        currKeyBuild = (ushort)((currKeyBuild >> 1) | ((bit ^ 1) << 15));
                    }
                }
            }
        }

        internal class IceSubKey
        {
            public ulong[] Val = new ulong[3];
        }

        public IceKey(int nBlocks)
        {
            if (!SBoxesInitialized)
            {
                IceSBoxesInit();
                SBoxesInitialized = true;
            }

            if (nBlocks < 1)
            {
                Size = 1;
                Rounds = 8;
            }
            else
            {
                Size = nBlocks;
                Rounds = nBlocks * 16;
            }

            _keysched = new IceSubKey[Rounds];
            for (int i = 0; i < Rounds; i++)
                _keysched[i] = new IceSubKey();
        }
        /// <summary>
        /// Set the key schedule of an ICE key.
        /// </summary>
        /// <param name="key">An n length string of characters where n=Size*8</param>
        public IceKey Set(string key)
        {
            ushort[] keyBuild = new ushort[4];
            if (Size == 1)
            {
                for (int i = 0; i < 4; i++)
                    keyBuild[3 - i] = (ushort)((key[i * 2] << 8) | key[i * 2 + 1]);

                ScheduleBuild(keyBuild, 0, ICEKeyRotation[0]);
                return this;
            }

            for (int i = 0; i < Size; i++)
            {
                for (int j = 0; j < 4; j++)
                    keyBuild[3 - j] = (ushort)((key[i * 8 + j * 2] << 8) | key[i * 8 + j * 2 + 1]);

                ScheduleBuild(keyBuild, i * 8, ICEKeyRotation[0]);
                ScheduleBuild(keyBuild, Rounds - 8 - i * 8, ICEKeyRotation[1]);
            }

            return this;
        }
        /// <summary>
        /// Encrypt a block of 8 bytes of data with the given ICE key.
        /// </summary>
        /// <param name="plaintext"></param>
        /// <param name="ciphertext"></param>
        public void Encrypt(byte[] plaintext, out byte[] ciphertext)
        {
            ulong leftBits = ((ulong)plaintext[0] << 24) | ((ulong)plaintext[1] << 16) | ((ulong)plaintext[2]) << 8 | plaintext[3];
            ulong rightBits = ((ulong)plaintext[4] << 24) | ((ulong)plaintext[5] << 16) | ((ulong)plaintext[6] << 8) | plaintext[7];

            for (int i = 0; i < Rounds; i += 2)
            {
                leftBits ^= ICEFormulate(rightBits, _keysched[i]);
                rightBits ^= ICEFormulate(leftBits, _keysched[i + 1]);
            }

            ciphertext = new byte[BlockSize];
            for (int i = 0; i < 4; i++)
            {
                ciphertext[3 - i] = (byte)(rightBits & 0xFF);
                ciphertext[7 - i] = (byte)(leftBits & 0xFF);

                rightBits >>= 8;
                leftBits >>= 8;
            }
        }
        /// <summary>
        /// Decrypt a block of 8 bytes of data with the given ICE key.
        /// </summary>
        /// <param name="ciphertext"></param>
        /// <param name="plaintext"></param>
        public void Decrypt(byte[] ciphertext, out byte[] plaintext)
        {
            ulong leftBits = ((ulong)ciphertext[0] << 24) | ((ulong)ciphertext[1] << 16) | ((ulong)ciphertext[2] << 8) | ciphertext[3];
            ulong rightBits = ((ulong)ciphertext[4] << 24) | ((ulong)ciphertext[5] << 16) | ((ulong)ciphertext[6] << 8) | ciphertext[7];

            for (int i = Rounds - 1; i > 0; i -= 2)
            {
                leftBits ^= ICEFormulate(rightBits, _keysched[i]);
                rightBits ^= ICEFormulate(leftBits, _keysched[i - 1]);
            }

            plaintext = new byte[BlockSize];
            for (int i = 0; i < 4; i++)
            {
                plaintext[3 - i] = (byte)(rightBits & 0xFF);
                plaintext[7 - i] = (byte)(leftBits & 0xFF);

                rightBits >>= 8;
                leftBits >>= 8;
            }
        }
        /// <summary>
        /// Return the key size, in bytes.
        /// </summary>
        public int KeySize => Size * 8;
        /// <summary>
        /// Return the block size, in bytes.
        /// </summary>
        public int BlockSize => 8;

        private int Size { get; set; }
        private int Rounds { get; set; }

        private readonly IceSubKey[] _keysched;
    }
}
