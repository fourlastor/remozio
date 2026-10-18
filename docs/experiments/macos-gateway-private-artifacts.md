# Mac gateway credential publication

This step publishes retained push credentials for their dedicated service accounts.
The Root setup host keeps the source material private and preserves its established keys.
It does not activate push or change the foreground runtime.

```mermaid
flowchart LR
    A["Protected pending setup"] --> B["Restore Root private material"]
    B --> C["Check every existing destination"]
    C --> D["Publish provider and receipt records for gateway"]
    C --> E["Publish wake key for transport"]
    D --> F["Validate all retained records"]
    E --> F
    F --> G["Later journal preparation and activation"]
```

## File custody

All three files use mode `0600` under the Root-owned metadata directory.
The parent directory permits traversal. Each private file permits access only to its owner.

| File | Owner | Purpose |
| --- | --- | --- |
| `gateway-provider.json` | Gateway account | Contact the configured FCM project |
| `gateway-receipt-key.cbor` | Gateway account | Sign gateway receipts |
| `transport-wake-key.cbor` | Transport account | Authenticate a transport wake |

The native entry requires Root identity and validates the retained service account records.
The caller must authenticate the administrator, verify the signed release, and retain a pending setup transition before allowing creation.
No administrator endpoint invokes this publisher yet.

## Recovery

| Mode or interruption | Result |
| --- | --- |
| Prepare an unactivated account | Create missing files from the retained material |
| Retry after partial publication | Validate existing files and publish the missing subset |
| Validate retained files | Require all files; create none |
| Conflicting bytes, ownership, permissions or links | Refuse without replacing files or repairing permissions |
| Earlier file changes during publication | Refuse during final validation |

The publisher checks every existing destination before creating a sibling.
An interrupted operation can leave a valid subset. A retry preserves those bytes and file identities.
It never generates keys or replaces the Root-private source material.

## Validation boundary

Owned fixtures exercise the real file publisher with disposable keys and synthetic provider data.
They cover interrupted subsets, retained file identity, missing files, changed scope, unsafe permissions, links and changed earlier records.
They also check that foreground setup records remain unchanged.

These fixtures do not prove ownership transfer from Root to separate service accounts.
Native service isolation, installed code admission and installed coexistence remain runtime gates.
No provider request or hardware test runs in this step.
The full local gate and exact-head CI review remain required after promotion.

The next steps prepare the service journal, retain setup progress, and connect native activation and app settings.
Normal gateway startup must continue to require an existing journal.

[The component record](evidence/2026-10-18-macos-gateway-private-artifacts.json) covers source commit `3fb459e`.
The full local gate passed 2565 core tests and 804 Kotlin/Android reports.
Assembly and lint passed with no new lint issues. The record identifies the explicit native skip and the validation limits.
