#!/usr/bin/env python3
"""Opt-in Developer ID and arm64 controls for owned Sparkle fixtures."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys

from sparkle_sdk_fixture import SDKFixtureSigner, SigningConfig, entitlement_controls

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--identity', required=True, help='Public SHA-1 certificate fingerprint; no implicit identity selection')
    parser.add_argument('--team', required=True, help='Expected trusted Developer ID Team, supplied independently of the fixture')
    parser.add_argument('--entitlement-controls', action='store_true', help='Measure only four no-argument helper controls; no installer starts')
    args = parser.parse_args()
    if os.getuid() == 0 or os.getuid() != os.geteuid():
        raise ValueError('Only an ordinary account can run these controls')
    config = SigningConfig(args.identity, args.team)
    spec = importlib.util.spec_from_file_location('sparkle_boundary_fixture', HERE / 'run-sparkle-boundary-experiment.py')
    boundary = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = boundary
    spec.loader.exec_module(boundary)
    products = Path(boundary.command('/usr/bin/swift', 'build', '--package-path', boundary.PACKAGE, '--show-bin-path').decode().strip())
    framework = (products / 'Sparkle.framework').resolve()
    original = boundary.digest(framework)
    signer = SDKFixtureSigner(boundary, config)
    try:
        if args.entitlement_controls:
            entitlement_controls(boundary, config, products)
        else:
            for mode in ['held-release', 'host-exit', 'staging']:
                boundary.control(products, mode, bundle_factory=signer.bundle)
    finally:
        if boundary.digest(framework) != original:
            raise RuntimeError('The original built SDK changed')
    print(json.dumps({'event': 'signed-arm64-controls-passed', 'controls': 4 if args.entitlement_controls else 3,
                      'entitlementControlsOnly': args.entitlement_controls,
                      'strictDeveloperIDRequirementsVerified': True, 'hardenedRuntimeVerified': True,
                      'fixtureEntitlementsVerified': True, 'allCodeArm64': True,
                      'originalSDKPreserved': True, 'notarizationTested': False,
                      'protectedInstallationTested': False}), flush=True)


if __name__ == '__main__':
    main()
