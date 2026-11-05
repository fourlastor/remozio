# Audit upgrade app channel

`AuditUpgradeSetupChannel` connects the app to the maintenance endpoint of the setup daemon.
`MacAccountSetupConnection.openAuditUpgrade` builds it from the verified installed release.
The factory checks protected placement, signed component identities, release capabilities and enabled setup status.
Opening a channel does not register or start services.
The app controls that use this channel are a separate change.

## Authentication and scope

The channel accepts only maintenance handshake version 11.
It verifies the Root peer before it reads a preauthorized external form, after it reads the form,
and before every send and reply.
The handshake carries no data. The channel verifies the peer on its reply.
The authorization reader must not request interactive rights.
The app must obtain administrator approval separately.

A progress read pins the full Mac, account, installation, release and initialization scope.
A caller can also bind the connection to an expected scope when it opens the channel.
A later scope change closes the connection and requires a new review.
The channel checks the caller process and the real and effective account IDs.
It rejects oversized, malformed and inappropriate progress states.

## Mutations and recovery

Each connection allows one mutation result. Then it closes.
This prevents reuse while the server finishes cleanup after its reply.
A busy call cannot replace an active continuation or export another authorization form.
The first mutation reserves the connection before it reads the authorization form, and the reservation is never cleared.
The channel does not use the pending reply as its only guard. The actor clears that reply before the suspended mutation resumes.
Without the reservation, a call queued in that gap could read another form and send a second mutation.
While the reservation is set, another mutation or a progress read reports a busy call and sends nothing.
Timeout, cancellation, disconnection and malformed replies close the transport.
They never repeat a mutation.

After any mutation error that follows the authorization reader, the outcome is unknown.
The caller must open a fresh channel and read the kept progress.
The channel never retries on its own.
A new mutation needs an explicit action after the caller has reviewed the updated scope.

## Refused and lost reads

The daemon refuses new handshakes and progress reads while maintenance holds it for another connection.
It answers zero to the handshake, or no progress to the read, and closes the connection.
It can also reject the connection before the handshake, or answer too late.

The channel reports each of these cases as `AuditUpgradeSetupChannelError.progressUnavailable`.
This error means that the state is unknown. It never means that no upgrade ran or that none is running.
The caller must try again later on a fresh channel.

Local errors keep their own meaning.
A wrong account, a local busy call, cancellation, an explicit close, a scope change and a malformed reply are not reported as unavailable progress.
A non-zero version other than 11 is reported as an unsupported version.
A peer check that fails inside the native driver reaches the channel as a failed reply.
The channel cannot tell this case apart from a dropped connection, so a read reports it as unavailable progress.
It never returns data in that case.

## What progress means

The stages keep three facts apart.
`metadataCommitted` means that the cutover metadata is saved.
`registrationObserved` lists the services whose launchd registration was confirmed.
Neither stage says that a service is running or healthy.
A saved metadata commit does not prove service registration either.
The channel does not verify service health.

## Compatibility

The app and setup release components declare local setup versions 1 to 11.
Both also declare progress codec version 1.
Other components do not declare the progress codec.
Before it opens the channel, the app factory checks these declarations and the cutover capabilities in the installed release.
Older setup clients keep their original selectors and handshakes.
The maintenance interface does not accept an older handshake as a fallback.

## Verification limits

Logical channel fixtures cover peer and account changes, full scope changes, request bounds,
cancellation, late replies, timeouts, busy calls, calls queued as a mutation reply arrives, recovery without replay,
and refused, dropped or expired reads.
An anonymous Foundation XPC fixture runs the real channel against the combined exported interface.
It covers authorization import on the exported invocation, an owned cutover and fresh recovery reads.
A second anonymous XPC fixture reads from other connections while a cutover runs.
Both reads report unavailable progress. The cutover still finishes.
These fixtures use ordinary-user accounts and fake rights.

These checks do not qualify native administrator rights, accepted Root signatures or installed launchd behaviour.
The native factory in `MacAccountSetupConnection` was not run here.
The complete local gate and fresh signed bundle inspection remain required before a push.
Installed integration tests remain separate work.
