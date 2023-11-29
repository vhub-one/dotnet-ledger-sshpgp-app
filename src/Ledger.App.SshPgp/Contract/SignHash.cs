using Ledger.App.SshPgp.Extensions;
using System.Buffers;

namespace Ledger.App.SshPgp.Contract
{
    internal class SignHash
    {
        public string KeyPath { get; set; }
        public ReadOnlyMemory<byte> Hash { get; set; }

        public void WriteTo(IBufferWriter<byte> writer)
        {
            writer.WriteKeyPath(KeyPath);
            writer.Write(Hash.Span);
        }
    }
}