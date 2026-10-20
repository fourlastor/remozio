# Configure push delivery in the Mac app

The Settings window opens one focused push setup sheet. Refresh reads saved progress without starting an operation or requesting administrator rights.
The sheet exposes provider import, explicit custody consent, storage preparation, activation and live settings changes.
Advanced delivery and wake fields remain available. They never extend an approval request’s expiry.

A pending change restores its saved selection and locks the fields until an explicit resume succeeds.
An uncertain reply requires Refresh. It does not trigger an automatic retry or replace the saved revision.
A cancelled administrator prompt clears the busy state without reporting a failed mutation.

An older enrollment can show its saved configuration and restore its service. It cannot request unsupported live settings changes.
The capability flag comes from protected progress. Refusing a live change does not replace its identity or pairing.

The new sheet uses the app’s existing native SwiftUI controls, system text styles and sheet layout.
Its footer adapts to narrower widths and keeps Close available during work. Disabled and failed states use explanatory text.
Existing account setup text points to Settings instead of claiming push is always unconfigured.

Controller and form fixtures test explicit actions, cancellation, uncertain replies, pending selections and legacy restoration.
Offscreen native renders cover light, dark, pending, legacy, expanded limits and narrow-width states.
Inspection confirmed the adaptive footer and explicit recovery actions. These disposable models make no native setup calls.
The actual Debug and Release app builds also passed. Keyboard navigation and installed authorization remain interactive checks.
Provider credential continuity, installed administrator consent and physical push delivery remain unproven.

Advanced groups remain expandable for inspection during a pending or unsupported settings change. Their fields stay read-only.
Refresh preserves edits only within the same retained account and foreground scope. A different scope selects its own saved values.
