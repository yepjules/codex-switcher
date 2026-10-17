import { useEffect, useState } from "react";
import { isValidNewPassphrase } from "../lib/platform";

interface BackupPassphraseModalProps {
  mode: "export" | "import";
  isOpen: boolean;
  onSubmit: (passphrase: string) => void;
  onClose: () => void;
}

export function BackupPassphraseModal({
  mode,
  isOpen,
  onSubmit,
  onClose,
}: BackupPassphraseModalProps) {
  const [passphrase, setPassphrase] = useState("");
  const [confirm, setConfirm] = useState("");

  useEffect(() => {
    if (!isOpen) {
      setPassphrase("");
      setConfirm("");
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const isExport = mode === "export";
  const tooShort = isExport && passphrase.length > 0 && !isValidNewPassphrase(passphrase);
  const mismatch = isExport && confirm.length > 0 && confirm !== passphrase;
  const canSubmit = isExport
    ? isValidNewPassphrase(passphrase) && passphrase === confirm
    : true;

  const submit = () => {
    if (!canSubmit) return;
    onSubmit(passphrase);
  };

  const inputClassName =
    "w-full rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 px-3 py-2 text-sm text-gray-900 dark:text-gray-100";

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
      <form
        role="dialog"
        aria-modal="true"
        aria-labelledby="backup-passphrase-title"
        onSubmit={(event) => {
          event.preventDefault();
          submit();
        }}
        className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-2xl w-full max-w-md mx-4 shadow-xl"
      >
        <div className="p-5 border-b border-gray-100 dark:border-gray-800">
          <h2
            id="backup-passphrase-title"
            className="text-lg font-semibold text-gray-900 dark:text-gray-100"
          >
            {isExport ? "Protect Backup with a Passphrase" : "Enter Backup Passphrase"}
          </h2>
        </div>
        <div className="p-5 space-y-3">
          <label
            htmlFor="backup-passphrase"
            className="block text-sm font-medium text-gray-900 dark:text-gray-100"
          >
            Passphrase
          </label>
          <input
            id="backup-passphrase"
            type="password"
            autoFocus
            autoComplete={isExport ? "new-password" : "current-password"}
            value={passphrase}
            onChange={(event) => setPassphrase(event.target.value)}
            className={inputClassName}
          />
          {isExport ? (
            <>
              <label
                htmlFor="backup-passphrase-confirm"
                className="block text-sm font-medium text-gray-900 dark:text-gray-100"
              >
                Confirm passphrase
              </label>
              <input
                id="backup-passphrase-confirm"
                type="password"
                autoComplete="new-password"
                value={confirm}
                onChange={(event) => setConfirm(event.target.value)}
                className={inputClassName}
              />
              <p className="text-xs text-gray-500 dark:text-gray-400">
                At least 12 characters. You will need this passphrase to restore the backup.
              </p>
              {tooShort && (
                <p role="alert" className="text-sm text-red-600 dark:text-red-300">
                  Passphrase must be at least 12 characters
                </p>
              )}
              {mismatch && (
                <p role="alert" className="text-sm text-red-600 dark:text-red-300">
                  Passphrases do not match
                </p>
              )}
            </>
          ) : (
            <p className="text-xs text-gray-500 dark:text-gray-400">
              Leave blank for backups made before this version
            </p>
          )}
        </div>
        <div className="flex justify-end gap-2 p-5 border-t border-gray-100 dark:border-gray-800">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-sm font-medium rounded-lg bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-200"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={!canSubmit}
            className="px-4 py-2 text-sm font-medium rounded-lg bg-gray-900 text-white dark:bg-gray-100 dark:text-gray-900 disabled:opacity-50"
          >
            {isExport ? "Export" : "Import"}
          </button>
        </div>
      </form>
    </div>
  );
}
