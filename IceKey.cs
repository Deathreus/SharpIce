// Purpose: C# implementation of the ICE encryption algorithm. Based on the C++ implementation by Valve.
//			Taken from public domain code, as written by Matthew Kwan - July 1996
//			http://www.darkside.com.au/ice/

using System.Linq;

namespace SharpIce
{
	public class IceKey
	{
		/* The S-boxes */
		static ulong[,] ice_sbox = new ulong[4,1024];
		static bool ice_sboxes_initialised = false;


		/* Modulo values for the S-boxes */
		static uint[,] ice_smod = new uint[4,4]{
						{333, 313, 505, 369},
						{379, 375, 319, 391},
						{361, 445, 451, 397},
						{397, 425, 395, 505}};

		/* XOR values for the S-boxes */
		static uint[,] ice_sxor = new uint[4,4]{
						{0x83, 0x85, 0x9b, 0xcd},
						{0xcc, 0xa7, 0xad, 0x41},
						{0x4b, 0x2e, 0xd4, 0x33},
						{0xea, 0xcb, 0x2e, 0x04}};

		/* Permutation values for the P-box */
		static ulong[] ice_pbox = new ulong[32]{
						0x00000001, 0x00000080, 0x00000400, 0x00002000,
						0x00080000, 0x00200000, 0x01000000, 0x40000000,
						0x00000008, 0x00000020, 0x00000100, 0x00004000,
						0x00010000, 0x00800000, 0x04000000, 0x20000000,
						0x00000004, 0x00000010, 0x00000200, 0x00008000,
						0x00020000, 0x00400000, 0x08000000, 0x10000000,
						0x00000002, 0x00000040, 0x00000800, 0x00001000,
						0x00040000, 0x00100000, 0x02000000, 0x80000000};

		/* The key rotation schedule */
		static int[][] ice_keyrot = new int[2][]{
						new int[8]{0, 1, 2, 3, 2, 1, 3, 0},
						new int[8]{1, 3, 2, 0, 3, 1, 0, 2}};
		/*
		 * 8-bit Galois Field multiplication of a by b, modulo m.
		 * Just like arithmetic multiplication, except that additions and
		 * subtractions are replaced by XOR.
		 */
		private uint gf_mult(uint a, uint b, uint m)
		{
			uint res = 0;

			while (b > 0)
			{
				if ((b & 1) != 0)
					res ^= a;

				a <<= 1;
				b >>= 1;

				if (a >= 256)
					a ^= m;
			}

			return res;
		}
		/*
		 * Galois Field exponentiation.
		 * Raise the base to the power of 7, modulo m.
		 */
		private ulong gf_exp7(uint b, uint m)
		{
			uint x;

			if (b == 0)
				return 0;

			x = gf_mult(b, b, m);
			x = gf_mult(b, x, m);
			x = gf_mult(x, x, m);
			return gf_mult(b, x, m);
		}
		/*
		 * Carry out the ICE 32-bit P-box permutation.
		 */
		private ulong ice_perm32(ulong x)
		{
			ulong res = 0;
			int pbox = 0;

			while (x > 0)
			{
				if ((x & 1) > 0)
					res |= ice_pbox[pbox];

				pbox++;
				x >>= 1;
			}

			return res;
		}
		/*
		 * The single round ICE f function.
		 */
		private ulong ice_f(ulong p, IceSubKey isk)
		{
			ulong tl, tr;       /* Expanded 40-bit values */
			ulong al, ar;       /* Salted expanded 40-bit values */

							/* Left half expansion */
			tl = ((p >> 16) & 0x3FF) | (((p >> 14) | (p << 18)) & 0xFFC00);

							/* Right half expansion */
			tr = (p & 0x3FF) | ((p << 2) & 0xFFC00);

							/* Perform the salt permutation */
			// al = (tr & sk->val[2]) | (tl & ~sk->val[2]);
			// ar = (tl & sk->val[2]) | (tr & ~sk->val[2]);
			al = isk.Val[2] & (tl ^ tr);
			ar = al ^ tr;
			al ^= tl;

			al ^= isk.Val[0];	/* XOR with the subkey */
			ar ^= isk.Val[1];

							/* S-box lookup and permutation */
			return ice_sbox[0,(al >> 10)] | ice_sbox[1,(al & 0x3FF)] | ice_sbox[2,(ar >> 10)] | ice_sbox[3,(ar & 0x3FF)];
		}
		/*
		 * Initialise the ICE S-boxes.
		 * This only has to be done once.
		 */
		private void ice_sboxes_init()
		{
			for (int i = 0; i < 1024; i++)
			{
				int col = (i >> 1) & 0xFF;
				int row = (i & 0x1) | ((i & 0x200) >> 8);
				ulong x;

				x = gf_exp7((uint)col ^ ice_sxor[0,row], ice_smod[0,row]) << 24;
				ice_sbox[0,i] = ice_perm32(x);

				x = gf_exp7((uint)col ^ ice_sxor[1,row], ice_smod[1,row]) << 16;
				ice_sbox[1,i] = ice_perm32(x);

				x = gf_exp7((uint)col ^ ice_sxor[2,row], ice_smod[2,row]) << 8;
				ice_sbox[2,i] = ice_perm32(x);

				x = gf_exp7((uint)col ^ ice_sxor[3,row], ice_smod[3,row]);
				ice_sbox[3,i] = ice_perm32(x);
			}
		}
		/*
		 * Set 8 rounds [n, n+7] of the key schedule of an ICE key.
		 */
		private void scheduleBuild(ushort[] kb, int n, int[] keyrot)
		{
			for (int i = 0; i < 8; i++)
			{
				int kr = keyrot[i];
				ref IceSubKey isk = ref _keysched[n + i];

				for (int j = 0; j < 3; j++)
					isk.Val[j] = 0;

				for (int j = 0; j < 15; j++)
				{
					ref ulong curr_sk = ref isk.Val[j % 3];

					for (int k = 0; k < 4; k++)
					{
						ref ushort curr_kb = ref kb[(kr + k) & 3];
						int bit = curr_kb & 1;

						curr_sk = (curr_sk << 1) | (uint)bit;
						curr_kb = (ushort)((curr_kb >> 1) | ((bit ^ 1) << 15));
					}
				}
			}
		}

		internal class IceSubKey
		{
			public ulong[] Val = new ulong[3];
		}

		public IceKey(int n)
		{
			if (!ice_sboxes_initialised)
			{
				ice_sboxes_init();
				ice_sboxes_initialised = true;
			}

			if (n < 1)
			{
				Size = 1;
				Rounds = 8;
			}
			else
			{
				Size = n;
				Rounds = n * 16;
			}

			_keysched = new IceSubKey[Rounds];
			for (int i = 0; i < Rounds; i++)
				_keysched[i] = new IceSubKey();
		}
		/// <summary>
		/// Set the key schedule of an ICE key.
		/// </summary>
		/// <param name="key">An n length string of characters where n=Size*8</param>
		public void Set(string key)
		{
			if (Rounds == 8)
			{
				ushort[] kb = new ushort[4];

				for (int i = 0; i < 4; i++)
					kb[3 - i] = (ushort)((key[i * 2] << 8) | key[i * 2 + 1]);

				scheduleBuild(kb, 0, ice_keyrot[0]);
				return;
			}

			for (int i = 0; i < Size; i++)
			{
				ushort[] kb = new ushort[4];

				for (int j = 0; j < 4; j++)
					kb[3 - j] = (ushort)((key[i * 8 + j * 2] << 8) | key[i * 8 + j * 2 + 1]);

				scheduleBuild(kb, i * 8, ice_keyrot[0]);
				scheduleBuild(kb, Rounds - 8 - i * 8, ice_keyrot[1]);
			}
		}
		/// <summary>
		/// Encrypt a block of 8 bytes of data with the given ICE key.
		/// </summary>
		/// <param name="plaintext"></param>
		/// <param name="ciphertext"></param>
		public void Encrypt(byte[] plaintext, ref byte[] ciphertext)
		{
			ulong l, r;

			l = (((ulong)plaintext[0]) << 24) | (((ulong)plaintext[1]) << 16) | (((ulong)plaintext[2]) << 8) | plaintext[3];
			r = (((ulong)plaintext[4]) << 24) | (((ulong)plaintext[5]) << 16) | (((ulong)plaintext[6]) << 8) | plaintext[7];

			for (int i = 0; i < Rounds; i += 2)
			{
				l ^= ice_f(r, _keysched[i]);
				r ^= ice_f(l, _keysched[i + 1]);
			}
			
			for (int i = 0; i < 4; i++)
			{
				ciphertext[3 - i] = (byte)(r & 0xFF);
				ciphertext[7 - i] = (byte)(l & 0xFF);

				r >>= 8;
				l >>= 8;
			}
		}
		/// <summary>
		/// Decrypt a block of 8 bytes of data with the given ICE key.
		/// </summary>
		/// <param name="ciphertext"></param>
		/// <param name="plaintext"></param>
		public void Decrypt(byte[] ciphertext, ref byte[] plaintext)
		{
			ulong l, r;

			l = (((ulong)ciphertext[0]) << 24) | (((ulong)ciphertext[1]) << 16) | (((ulong)ciphertext[2]) << 8) | ciphertext[3];
			r = (((ulong)ciphertext[4]) << 24) | (((ulong)ciphertext[5]) << 16) | (((ulong)ciphertext[6]) << 8) | ciphertext[7];

			for (int i = Rounds - 1; i > 0; i -= 2)
			{
				l ^= ice_f(r, _keysched[i]);
				r ^= ice_f(l, _keysched[i - 1]);
			}
			
			for (int i = 0; i < 4; i++)
			{
				plaintext[3 - i] = (byte)(r & 0xFF);
				plaintext[7 - i] = (byte)(l & 0xFF);

				r >>= 8;
				l >>= 8;
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
