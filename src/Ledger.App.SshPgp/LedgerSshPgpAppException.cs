
namespace Ledger.App.SshPgp
{
    public class LedgerSshPgpAppException : Exception
    {
        public LedgerSshPgpAppException(string message, Exception ex = null)
            : base(message, ex)
        {
        }
    }

    public class LedgerSshPgpAppCancelledException : LedgerSshPgpAppException
    {
        public LedgerSshPgpAppCancelledException()
            : base("Operation cancelled by user")
        {

        }
    }

    public class LedgerSshPgpAppStoppedException : LedgerSshPgpAppException
    {
        public LedgerSshPgpAppStoppedException()
            : base("Ssh app is not running")
        {

        }
    }
}