using System;
using KeePassLib;
using KeePassLib.Security;

namespace HaveIBeenPwnedPlugin
{
    internal sealed class EntryCheckContext
    {
        private readonly PwDatabase _database;
        private readonly PwGroup _rootGroup;
        private readonly PwEntry _entry;
        private readonly ProtectedString _password;

        internal EntryCheckContext(PwDatabase database, PwEntry entry)
        {
            _database = database;
            _rootGroup = database?.RootGroup;
            _entry = entry ?? throw new ArgumentNullException(nameof(entry));
            _password = entry.Strings.GetSafe(PwDefs.PasswordField);
        }

        internal bool IsCurrent(PwDatabase activeDatabase)
        {
            return _database != null && _database.IsOpen && ReferenceEquals(_database, activeDatabase) &&
                _rootGroup != null && ReferenceEquals(_rootGroup, _database.RootGroup) &&
                ReferenceEquals(_rootGroup.FindEntry(_entry.Uuid, true), _entry) &&
                ReferenceEquals(_password, _entry.Strings.GetSafe(PwDefs.PasswordField));
        }
    }
}
