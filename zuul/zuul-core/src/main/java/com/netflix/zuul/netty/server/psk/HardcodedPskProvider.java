/*
 * PoC-only: accepts any PSK identity and returns a fixed 32-byte zero key.
 * This matches the POC_PSK constant used by the launcher's TLS 1.2 client.
 * Do not use outside of this proof-of-concept.
 */
package com.netflix.zuul.netty.server.psk;

import java.util.Arrays;

public class HardcodedPskProvider implements ExternalTlsPskProvider {

    /** 32 zero bytes — must match POC_PSK in launcher/app.py */
    private static final byte[] POC_PSK = new byte[32];

    @Override
    public byte[] provide(byte[] clientPskIdentity, byte[] clientRandom) {
        return Arrays.copyOf(POC_PSK, POC_PSK.length);
    }
}
