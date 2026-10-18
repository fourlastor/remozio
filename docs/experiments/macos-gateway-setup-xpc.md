# Gateway setup interface

Version 6 adds the Gateway setup action to the authenticated app setup channel.
The action contains bounded provider choices, service settings and explicit file-custody consent.
Descriptions redact the provider inputs. The decoder rejects unknown fields and unsupported versions.
The client uses a separate bounded setup timeout and preserves the version 1 through 5 actions.

The native endpoint imports administrator authorization inside the exported invocation before asynchronous work starts.
The operation then uses the asynchronous owner reservation. Its own writer phases carry that live reservation.
Competing machine operations remain excluded until the backend settles.
A separate reply reservation keeps shutdown waiting through response encoding and the reply callback.
Client cancellation does not discard owned Root work.

The release declaration adds setup version 6 and preparation schema 9.
Normal app controls, later activation actions and settings transitions follow separately.
Completing initial setup does not apply new choices to an already completed account.

The local gate checks the owned software controls, both app builds and their signed format declarations.
The selector experiment also checks 73 synthetic cases against a temporary ordinary-user XPC service and confirms its removal.
Ad-hoc identifiers and injected administrator checks do not prove Developer ID peers, Root UID admission or actual administrator authorization.
No installed Remozio service, provider delivery, physical device or frozen recovery artifact is used.
