# Android release artifacts

The release build produces an optimized standalone APK for `dev.sebastiano.remozio.android`. It remains unsigned until the release owner signs it. CI assembles this variant to catch R8 and resource-shrinking failures; it never receives a signing key or publishes a release.

## Build and sign

Use JDK 21 and Android SDK build tools 37.0.0. Supply the version name and version code explicitly:

```sh
./gradlew :android-app:assembleRelease \
  -PremozioVersionName=0.2.0 \
  -PremozioVersionCode=2
```

The output is `android/app/build/outputs/apk/release/android-app-release-unsigned.apk`. Version names use the updater's semantic-version format without a leading `v`. Codes must be positive and at most 2100000000. Increase both semantic precedence and version code for each update. CI defaults remain the current development version; these defaults are not release allocation.

Sign with the retained production identity. Do not use a debug key or create a fresh identity for each version. Keep the keystore outside the checkout. The SDK supports password input through environment variable names, without putting the values in command arguments:

```sh
"$ANDROID_HOME/build-tools/37.0.0/apksigner" sign \
  --ks /secure/path/remozio.jks --ks-key-alias remozio \
  --ks-pass env:REMOZIO_STORE_PASSWORD --key-pass env:REMOZIO_KEY_PASSWORD \
  --out /release-work/remozio-signed.apk \
  android/app/build/outputs/apk/release/android-app-release-unsigned.apk
```

Provision those variables through the release owner's secret facility. Do not paste secret values into scripts or logs. The project does not provision this identity or its backup. The preparation tool accepts a single retained signer; signer rotation needs its own reviewed release procedure.

## Verify and prepare

Obtain the expected certificate SHA-256 fingerprint independently from the retained signing identity. Do not derive the expected value from an untrusted downloaded APK.

```sh
python3 scripts/prepare-android-release.py \
  --apk /release-work/remozio-signed.apk \
  --output /release-work/v0.2.0 \
  --version 0.2.0 --code 2 \
  --signer-sha256 "$REMOZIO_SIGNER_SHA256"
```

The destination must not exist, and its parent must exist. The tool copies the APK into temporary staging before checking it. SDK tools verify package/version/SDK metadata, absence of debug/test/split flags, the APK signature, the expected certificate, and alignment. The 256 MiB bound matches the updater. Failed verification removes staging and creates no release directory. A failed output operation removes the newly created directory; existing destinations are never overwritten.

Success creates `remozio-android.apk`, `SHA256SUMS`, and `release.json`. The JSON records version, size, package, certificate fingerprint, and file digest. These are release evidence, not a substitute for APK signature verification. Nothing uploads automatically. Publish the prepared APK under the matching GitHub release tag only after the interactive release checks pass. Do not change APK bytes after signing.

## Validation boundary

An optimized `0.2.0-beta.1` / code `2` build passed with build tools 37.0.0. A disposable RSA identity signed it with APK Signature Scheme v3. Preparation accepted the result and rejected both a different expected certificate and a byte-tampered copy. All temporary keys and outputs were removed. No production key, device, or GitHub release was used.

Python tests cover version policy, metadata rejection, signer parsing, staging ownership, output collision, and cleanup. CI builds both debug and release variants. Pixel installation, forward updates, pairing/data preservation, actual production signing, and public release delivery remain interactive release gates. A successful build does not establish bit-for-bit reproducibility across build hosts.

SDK references: [APK signing](https://developer.android.com/tools/apksigner) and [alignment](https://developer.android.com/tools/zipalign).
