# Android audit cache checks

Host tests cover the encrypted archive and repository with disposable keys and simulated storage.
The Android Keystore and AtomicFile adapter has not run on a real device.
Run these checks on a supported Pixel with Android 17 while the user is present.

- Create a cache for a synthetic Mac/account. Confirm a hardware-backed, non-exportable AES-256 key and a ciphertext-only file under backup-excluded private storage.
- Read history without an extra biometric prompt. Confirm background metadata persistence while the screen is locked after first unlock.
- Restart the app and reboot. Confirm the same cache key and signed evidence remain available after the Android user unlocks.
- Open the same cache twice. The second owner must fail while the first holds the file lock. Closing the first must allow another owner.
- Interrupt writes before sync, before replacement and after replacement. Reload must return the old or new complete archive, never a partially accepted proof set.
- Inject a write failure after replacement. The live repository must stop writing until reopen; reload must preserve any committed proof.
- Alter ciphertext, the IV and the header separately. Loading must fail without rewriting the file or regenerating the key.
- Use another Mac/account or authority key. The original file must remain intact when decryption fails.
- Remove the disposable cache key while retaining the file. Loading must fail visibly and preserve ciphertext. Do not run this against real history.
- Fill the configured archive and evidence budgets. Show the failure without eviction or pruning. Retention policy still requires the user's choice.
- Confirm backup/transfer exclusion and verify that raw command text, credentials and UI captures never enter the archive or diagnostics.

These checks do not establish protection against a rooted phone or restoration of an older complete encrypted archive. A cache never authorizes an action, rewrites Mac history or replaces independent trust recovery.

## Cache ownership across local opens

The audit cache and enrollment archive use `ExclusiveFileOwner`. It reserves the canonical lock path before opening any channel, then retains the OS lock until close. A rejected local open therefore cannot close a competing channel and accidentally release the original process-wide lock. Failed acquisition releases the reservation. Repeated close cannot release a replacement owner.

A disposable JDK 21 probe on macOS reproduced the original hazard: a second process acquired the lock after a rejected second channel closed, while the original `FileLock.isValid` still returned true. JVM regression tests now check cross-process exclusion before and after a rejected second open, release after close, canonical paths, and acquisition failure. This evidence does not prove Android filesystem behavior; the Pixel check remains pending.
