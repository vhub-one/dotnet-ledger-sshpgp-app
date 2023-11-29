using System.Buffers;
using Ledger.App.SshPgp.Extensions;

namespace Ledger.App.SshPgp.Contract
{
    internal class PublicKeyData
    {
        public string KeyPath { get; set; }

        public void WriteTo(IBufferWriter<byte> writer)
        {
            writer.WriteKeyPath(KeyPath);
        }
    }
}