using Common.Buffers;
using Common.Buffers.Extensions;
using Ssh.Dsa;
using Ssh.Extensions;
using System.Buffers;
using System.Formats.Asn1;

namespace Ledger.App.SshPgp.Extensions
{
    public static class LedgerBufferReaderExtensions
    {
        public static EcP256Key ReadEcP256Key(this IBufferReader<byte> reader)
        {
            var qLength = reader.Read();
            var q = reader.Read(qLength);

            return new EcP256Key
            {
                Q = q
            };
        }

        public static EcP256Signature ReadEcP256Signature(this IBufferReader<byte> reader)
        {
            var envelope = reader.ReadAll();

            var oddParity = (envelope.Span[0] & 0x01) == 0x01;

            if (oddParity)
            {
                var envelopeCopy = envelope.ToArray();

                // For some reasone ssh app breaks asn format and sets first bit into 1 in case of ec odd parity
                envelopeCopy[0] &= 0xFE;
                envelope = envelopeCopy;
            }

            var envelopeReader = new AsnReader(envelope, AsnEncodingRules.DER);

            var sequenceReaderTag = envelopeReader.PeekTag();
            var sequenceReader = envelopeReader.ReadSequence(sequenceReaderTag);

            var r = sequenceReader.ReadIntegerBytes();
            var s = sequenceReader.ReadIntegerBytes();

            var buffer = new ArrayBufferWriter<byte>();

            buffer.WriteMpInt(r.Span);
            buffer.WriteMpInt(s.Span);

            return new EcP256Signature
            {
                SignatureBlob = buffer.WrittenMemory
            };
        }

        public static Ed25519Key ReadEd25519Key(this IBufferReader<byte> reader)
        {
            var envolopeLength = reader.Read();

            var envolope = reader.Read(envolopeLength);
            var envolopeReader = MemoryBufferReader.Create(envolope);

            var tag = envolopeReader.Read();

            if (tag != (byte)UniversalTagNumber.OctetString)
            {
                throw new FormatException();
            }

            var x = envolopeReader.Read(32);
            var y = envolopeReader.Read(32);

            var yCopy = y.ToArray();

            var xLowestBit = x.Span[31] & 1;

            if (xLowestBit != 0)
            {
                // Replace highest bit
                yCopy[0] |= 1 << 7;
            }

            Array.Reverse(yCopy);

            return new Ed25519Key
            {
                A = yCopy
            };
        }

        public static Ed25519Signature ReadEd25519Signature(this IBufferReader<byte> reader)
        {
            return new Ed25519Signature
            {
                SignatureBlob = reader.Read(64)
            };
        }
    }
}
