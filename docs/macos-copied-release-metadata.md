# Copied release metadata policy

The protected preparer creates new objects and copies logical file contents, executable mode selection and bounded internal links.
It does not preserve source ACLs, file flags or extended attributes.

Every copied file, directory and link must have zero file flags.
The copied tree permits only the `com.apple.provenance` attribute.
The policy ignores its value and grants it no authority.
The OS can attach this metadata to newly created objects.

The verifier reads attribute names through each retained object descriptor.
The inventory includes compression attributes and permits at most 8,192 name bytes and 64 distinct names.
It rejects unreadable, malformed, excessive or unexpected inventories.
A link descriptor refers to the link itself, without following its target.

Source compression is acceptable when copying produces the same logical contents in an uncompressed output.
Source resource forks and custom metadata are not preserved.
A release that requires those values is unsupported by this copying contract.
The copied bundle must pass the existing strict signature check, manifest equality, component hash equality and generation floor checks.

This policy does not replace notarization or authorize activation.
Root ownership, external rollback protection, durable preparation recovery, compatibility and startup health remain separate installation requirements.

## Validation

The standalone draft passed ordinary-owner file, directory, link, flag and attribute controls.
All 51 focused copy and placement tests passed, including six new metadata tests.
The actual signed SDK copy and its compressed resource passed all five native controls.
The original SDK remained unchanged and the owned fixtures were removed.
The standalone controls do not prove Root isolation or production installation.
