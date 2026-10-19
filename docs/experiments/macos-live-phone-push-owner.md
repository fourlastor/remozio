# Live phone push on the existing authority owner

The Root capability can install optional phone-push support after foreground startup. It preserves the journal owner, clock, enrolled phones and request deadlines. The publisher can install that same provider on its existing gateway connection.

The owner must authenticate the current protected scope before and after installation. A concurrent installation refuses. A late verification failure keeps the provider unavailable and allows an exact retry. A different provider or commit cannot replace an installed capability through this entry.

The journal enables its bounded gateway policy without replacing the request coordinator. Existing registrations and pending requests remain intact. Publication orders prior controls before later phone registrations and retains probe history on a matching retry.

These are in-process primitives. Native protected extension loading, activation and the visible app follow separately. No installed service, credential or physical phone is used. Local evidence records the native and portable gates; CI must pass before merge.
