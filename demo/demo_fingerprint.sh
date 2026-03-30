#!/bin/bash
set -e
echo "============================================"
echo "  Scenario 6: Fingerprint Verification"
echo "============================================"
echo ""

echo "Public key fingerprints for alice:"
python client.py fingerprint --name alice
echo ""

echo "Public key fingerprints for bob:"
python client.py fingerprint --name bob
echo ""

echo "============================================"
echo "  Verification Protocol:"
echo ""
echo "  1. Alice and Bob generate keypairs locally."
echo "  2. They meet in person (or call each other)"
echo "     and read their fingerprints aloud."
echo "  3. Each party verifies the fingerprint"
echo "     matches the public key file they received."
echo "  4. Only after verification do they proceed"
echo "     with channel initialization."
echo ""
echo "  If an attacker substituted a public key"
echo "  during exchange, the fingerprints would"
echo "  NOT match, and the attack would be detected."
echo "============================================"
