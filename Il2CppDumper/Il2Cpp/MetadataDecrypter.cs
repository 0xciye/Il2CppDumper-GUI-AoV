using System;

namespace Il2CppDumper
{
    public static class MetadataDecrypter
    {
        private const uint ObfuscatedMagic = 0xEAB11BAF;
        private const uint StandardMagic = 0xFAB11BAF;
        private const uint XorKey = 0xA8C72D;

        private struct DecodeField
        {
            public int OutEven { get; }
            public int OutOdd { get; }

            public DecodeField(int outEven, int outOdd)
            {
                OutEven = outEven;
                OutOdd = outOdd;
            }
        }

        private static readonly DecodeField[] GroupOutFields = new DecodeField[]
        {
            new DecodeField(4, 5),
            new DecodeField(8, 9),
            new DecodeField(12, 13),
            new DecodeField(16, 17),
            new DecodeField(20, 21),
            new DecodeField(6, 7),
            new DecodeField(10, 11),
            new DecodeField(14, 15),
            new DecodeField(18, 19),
            new DecodeField(22, 23),
            new DecodeField(2, 3),
            new DecodeField(48, 49),
            new DecodeField(46, 47),
            new DecodeField(44, 45),
            new DecodeField(42, 43),
            new DecodeField(24, 25),
            new DecodeField(28, 29),
            new DecodeField(32, 33),
            new DecodeField(36, 37),
            new DecodeField(40, 41),
            new DecodeField(26, 27),
            new DecodeField(30, 31),
            new DecodeField(34, 35),
            new DecodeField(38, 39)
        };

        public static void Decrypt(byte[] data)
        {
            if (data == null || data.Length < 256)
            {
                return;
            }

            uint[] header = new uint[64];
            for (int i = 0; i < 64; i++)
            {
                header[i] = BitConverter.ToUInt32(data, i * 4);
            }

            if (header[0] != ObfuscatedMagic)
            {
                return;
            }

            uint[] input = new uint[64];
            Array.Copy(header, input, 64);

            uint[] output = new uint[64];
            output[0] = input[0];
            output[1] = input[1];
            for (int i = 50; i < 64; i++)
            {
                output[i] = input[i];
            }

            for (int g = 0; g < 24; g++)
            {
                int outEven = GroupOutFields[g].OutEven;
                int outOdd = GroupOutFields[g].OutOdd;
                int inEven = 2 + (2 * g);
                int inOdd = 3 + (2 * g);

                uint even = XorKey + (uint)g;
                uint odd = XorKey + (uint)(2 * g);

                uint subEven = (uint)(3 * g);
                uint subOdd = (uint)(7 * g);

                output[outEven] = (input[inEven] - subEven) ^ even;
                output[outOdd] = (input[inOdd] - subOdd) ^ odd;
            }

            for (int i = 0; i < 64; i++)
            {
                uint val = output[i];
                if (i == 0)
                {
                    val = StandardMagic;
                }
                byte[] bytes = BitConverter.GetBytes(val);
                Buffer.BlockCopy(bytes, 0, data, i * 4, 4);
            }
        }
    }
}
