using Ledger.App.SshPgp.Extensions;
using System.Buffers;

namespace Ledger.App.SshPgp.Contract
{
    internal class SignData
    {
        public string KeyPath { get; set; }
        public ReadOnlyMemory<byte> Challenge { get; set; }

        public void WriteTo(IBufferWriter<byte> writer)
        {
            writer.WriteKeyPath(KeyPath);
            writer.Write(Challenge.Span);
        }
    }
}