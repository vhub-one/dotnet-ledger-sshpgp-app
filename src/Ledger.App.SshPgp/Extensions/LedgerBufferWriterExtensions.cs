using Common.Buffers.Extensions;
using System.Buffers;

namespace Ledger.App.SshPgp.Extensions
{
    public static class LedgerBufferWriterExtensions
    {
        private const char MASTER = 'm';
        private const char DELIMITER = '/';
        private const char FLAG_1 = 'h';
        private const char FLAG_2 = '\'';

        public static void WriteKeyPath(this IBufferWriter<byte> writer, ReadOnlySpan<char> keyPath)
        {
            var keyWriter = new ArrayBufferWriter<byte>();

            keyWriter.WriteKeyPathIndices(keyPath);

            var keySize = keyWriter.WrittenCount / 4;

            writer.Write((byte)keySize);
            writer.Write(keyWriter.WrittenSpan);
        }

        public static void WriteKeyPathIndices(this IBufferWriter<byte> keyPathWriter, ReadOnlySpan<char> keyPath)
        {
            if (keyPath[0] == MASTER)
            {
                // Skip master key segment
                keyPath = keyPath[1..];
            }

            if (keyPath[0] == DELIMITER)
            {
                // Skip first delimiter
                keyPath = keyPath[1..];
            }

            if (keyPath.Length == 0)
            {
                return;
            }

            while (true)
            {
                var delimiterIndex = keyPath.IndexOf(DELIMITER);

                if (delimiterIndex < 0)
                {
                    delimiterIndex = keyPath.Length;
                }

                if (delimiterIndex == 0)
                {
                    throw new FormatException();
                }

                var segment = keyPath[..delimiterIndex];
                var segmentValid = TryParseSegment(segment, out var index);

                if (segmentValid == false)
                {
                    throw new FormatException();
                }

                keyPathWriter.WriteUInt32BigEndian(index);

                var keyPathNextSegment = delimiterIndex + 1;

                if (keyPathNextSegment < keyPath.Length)
                {
                    keyPath = keyPath[keyPathNextSegment..];
                }
                else
                {
                    break;
                }
            }
        }

        private static bool TryParseSegment(ReadOnlySpan<char> indexSpan, out uint index)
        {
            if (indexSpan.Length == 0)
            {
                index = 0u;
                return false;
            }

            var hardened = indexSpan[^1] == FLAG_1 || indexSpan[^1] == FLAG_2;

            if (hardened)
            {
                indexSpan = indexSpan[..^1];
            }

            var indexParsed = uint.TryParse(indexSpan, out index);

            if (indexParsed == false)
            {
                return false;
            }

            if (hardened)
            {
                if (index >= 0x80000000u)
                {
                    index = 0u;
                    return false;
                }

                index |= 0x80000000u;
                return true;
            }

            return true;
        }
    }
}