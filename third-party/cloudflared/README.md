# Bundled connector input

The app build uses the official [cloudflared 2026.10.2 arm64 release](https://github.com/cloudflare/cloudflared/releases/tag/2026.10.2).
`pin.json` fixes the archive, executable and upstream license hashes. No downloaded executable is tracked in Git.

The build verifies the input before signing its copy with the app's signing identity.
The release manifest records the signed executable as a transport tool dependency. This declaration grants no service or approval authority.
The cache is local to `.build/vendor/cloudflared`. A corrupt cache fails validation.

The connector runs only after protected runtime configuration and transport admission exist.
Its lifetime, release activity lock and token-file validation require separate runtime integration.
The pinned upstream license is in `LICENSE`.
