using Common.Buffers;
using Common.Buffers.Extensions;
using Ledger.App.SshPgp.Contract;
using Ledger.App.SshPgp.Extensions;
using Ledger.Contract;
using Ssh;
using System.Buffers;

namespace Ledger.App.SshPgp
{
    public class LedgerSshPgpAppClient
    {
        private const byte CLA = 0x80;

        #region GET PUBLIC KEY
        private const byte GET_PUB_KEY_INS = 0x02;
        private const byte GET_PUB_KEY_P1 = 0x00;
        private const byte GET_PUB_KEY_P2_P256V1 = 0x01;
        private const byte GET_PUB_KEY_P2_C25519 = 0x02;
        #endregion

        #region SIGN BLOB
        private const byte SIGN_INS = 0x04;
        private const byte SIGN_P1_FIRST_CHUNK = 0x00;
        private const byte SIGN_P1_SUBSEQUENT_CHUNK = 0x01;
        private const byte SIGN_P1_LAST_CHUNK_MASK = 0x80;
        private const byte SIGN_P2_P256V1 = 0x01;
        private const byte SIGN_P2_C25519 = 0x02;
        // private const byte SIGN_P2_RETURN_PUB_KEY_MASK = 0x80;
        #endregion

        #region SIGN DIRECT HASH
        private const byte SIGN_DIRECT_HASH_INS = 0x08;
        private const byte SIGN_DIRECT_HASH_P1 = 0x00;
        private const byte SIGN_DIRECT_HASH_P2_P256V1 = 0x01;
        private const byte SIGN_DIRECT_HASH_P2_C25519 = 0x02;
        #endregion

        private const uint SW_OK = 0x9000;
        private const uint SW_CANCEL = 0x6985;
        private const uint SW_APP_NOT_RUNNING = 0x6E01;
        private const uint SW_DEVICE_LOCKED = 0x5515;

        private readonly ILedgerDeviceChannel _transport;

        public LedgerSshPgpAppClient(ILedgerDeviceChannel transport)
        {
            _transport = transport;
        }

        public async ValueTask<SshSignature> SignDataAsync(string keyPath, SshKeyCurve keyCurve, ReadOnlyMemory<byte> challenge, CancellationToken token)
        {
            var response = default(LedgerResponse);

            // Serialize payload
            var signDataWriter = new ArrayBufferWriter<byte>();
            var signData = new SignData
            {
                KeyPath = keyPath,
                Challenge = challenge
            };

            signData.WriteTo(signDataWriter);

            // Get payload chunks
            var signDataChunks = signDataWriter.WrittenMemory.Chunk(LedgerRequest.DATA_LIMIT);

            // Go through all chunks
            foreach (var chunk in signDataChunks)
            {
                byte signP1;
                byte signP2;

                // Build apdu command
                if (chunk.IsFirst)
                {
                    signP1 = SIGN_P1_FIRST_CHUNK;
                }
                else
                {
                    signP1 = SIGN_P1_SUBSEQUENT_CHUNK;
                }

                if (chunk.IsLast)
                {
                    signP1 |= SIGN_P1_LAST_CHUNK_MASK;
                }

                if (keyCurve == SshKeyCurve.P256V1)
                {
                    signP2 = SIGN_P2_P256V1;
                }
                else
                {
                    signP2 = SIGN_P2_C25519;
                }

                // if (includePubKey)
                // {
                //     signP2 |= SIGN_P2_RETURN_PUB_KEY_MASK;
                // }

                var request = new LedgerRequest
                {
                    InstructionClass = CLA,
                    Instruction = SIGN_INS,
                    Param1 = signP1,
                    Param2 = signP2,
                    Data = chunk.Data
                };

                // Parse response
                response = await ExchangeAsync(request, token);

                // Verify response
                VerifyStatusWord(response);
            }

            var signatureReader = MemoryBufferReader.Create(response.Data);

            if (keyCurve == SshKeyCurve.C25519)
            {
                return signatureReader.ReadEd25519Signature();
            }
            if (keyCurve == SshKeyCurve.P256V1)
            {
                return signatureReader.ReadEcP256Signature();
            }

            throw new LedgerSshPgpAppException("Key curve is not supported");
        }

        public async ValueTask<SshSignature> SignDirectHashAsync(string keyPath, SshKeyCurve keyCurve, ReadOnlyMemory<byte> hash, CancellationToken token = default)
        {
            // Serialize payload
            var signHashWriter = new ArrayBufferWriter<byte>();
            var signHash = new SignHash
            {
                KeyPath = keyPath,
                Hash = hash
            };

            signHash.WriteTo(signHashWriter);

            // Build apdu command
            var request = new LedgerRequest
            {
                InstructionClass = CLA,
                Instruction = SIGN_DIRECT_HASH_INS,
                Param1 = SIGN_DIRECT_HASH_P1,
                Data = signHashWriter.WrittenMemory
            };

            if (keyCurve == SshKeyCurve.P256V1)
            {
                request.Param2 = SIGN_DIRECT_HASH_P2_P256V1;
            }
            else
            {
                request.Param2 = SIGN_DIRECT_HASH_P2_C25519;
            }

            // Proceed request
            var response = await ExchangeAsync(request, token);

            // Verify response
            VerifyStatusWord(response);

            var signatureReader = MemoryBufferReader.Create(response.Data);

            if (keyCurve == SshKeyCurve.C25519)
            {
                return signatureReader.ReadEd25519Signature();
            }
            if (keyCurve == SshKeyCurve.P256V1)
            {
                return signatureReader.ReadEcP256Signature();
            }

            throw new LedgerSshPgpAppException("Key curve is not supported");
        }

        public async ValueTask<SshKey> GetPublicKeyAsync(string keyPath, SshKeyCurve keyCurve, CancellationToken token = default)
        {
            // Serialize payload
            var publicKeyDataWriter = new ArrayBufferWriter<byte>();
            var publicKeyData = new PublicKeyData
            {
                KeyPath = keyPath
            };

            publicKeyData.WriteTo(publicKeyDataWriter);

            // Build apdu command
            var request = new LedgerRequest
            {
                InstructionClass = CLA,
                Instruction = GET_PUB_KEY_INS,
                Param1 = GET_PUB_KEY_P1,
                Data = publicKeyDataWriter.WrittenMemory
            };

            if (keyCurve == SshKeyCurve.P256V1)
            {
                request.Param2 = GET_PUB_KEY_P2_P256V1;
            }
            else
            {
                request.Param2 = GET_PUB_KEY_P2_C25519;
            }

            // Proceed request
            var response = await ExchangeAsync(request, token);

            // Verify response
            VerifyStatusWord(response);

            var keyReader = MemoryBufferReader.Create(response.Data);

            if (keyCurve == SshKeyCurve.C25519)
            {
                return keyReader.ReadEd25519Key();
            }
            if (keyCurve == SshKeyCurve.P256V1)
            {
                return keyReader.ReadEcP256Key();
            }

            throw new LedgerSshPgpAppException("Key curve is not supported");
        }

        private async ValueTask<LedgerResponse> ExchangeAsync(LedgerRequest request, CancellationToken token)
        {
            var requestWriter = new ArrayBufferWriter<byte>();

            // Serialize request
            request.WriteTo(requestWriter);

            // Proceed request
            var responseData = await _transport.ExchangeAsync(requestWriter.WrittenMemory, token);

            // Parse response
            var responseDataReader = MemoryBufferReader.Create(responseData);
            var response = LedgerResponse.ReadFrom(
                responseDataReader
            );

            return response;
        }

        private void VerifyStatusWord(LedgerResponse response)
        {
            if (response == null)
            {
                throw new LedgerSshPgpAppException("Ledger device returned bad result");
            }
            if (response.SW == SW_CANCEL)
            {
                throw new LedgerSshPgpAppCancelledException();
            }
            if (response.SW == SW_APP_NOT_RUNNING)
            {
                throw new LedgerSshPgpAppStoppedException();
            }
            if (response.SW == SW_DEVICE_LOCKED)
            {
                throw new LedgerSshPgpAppStoppedException();
            }
            if (response.SW != SW_OK)
            {
                throw new LedgerSshPgpAppException($"Ledger device returned bad status word")
                {
                    Data =
                    {
                        { "SW", response.SW }
                    }
                };
            }
        }
    }
}