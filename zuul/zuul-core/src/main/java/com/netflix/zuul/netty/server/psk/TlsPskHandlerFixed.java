/*
 * REMEDIATION: Fixed version of TlsPskHandler
 * 
 * Critical Changes:
 * 1. Do NOT extract and release buffer early
 * 2. Respect buffer's readableBytes(), arrayOffset(), and readerIndex()
 * 3. Release buffer AFTER encryption completes
 */

package com.netflix.zuul.netty.server.psk;

import com.netflix.spectator.api.Registry;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.util.AttributeKey;
import io.netty.util.ReferenceCountUtil;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Set;
import javax.net.ssl.SSLSession;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.ProtocolName;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;

/**
 * FIXED: TlsPskHandler that properly handles buffer lifecycle and respects buffer bounds
 */
public class TlsPskHandlerFixed extends ChannelDuplexHandler {

    public static final Map<Integer, String> SUPPORTED_TLS_PSK_CIPHER_SUITE_MAP = Map.of(
            CipherSuite.TLS_AES_128_GCM_SHA256,
            "TLS_AES_128_GCM_SHA256",
            CipherSuite.TLS_AES_256_GCM_SHA384,
            "TLS_AES_256_GCM_SHA384");
    public static final AttributeKey<ClientPSKIdentityInfo> CLIENT_PSK_IDENTITY_ATTRIBUTE_KEY =
            AttributeKey.newInstance("_client_psk_identity_info");
    public static final SecureRandom secureRandom = new SecureRandom();

    private final Registry registry;
    private final ExternalTlsPskProvider externalTlsPskProvider;
    private final Set<ProtocolName> supportedApplicationProtocols;
    private final TlsPskServerProtocol tlsPskServerProtocol;

    private ZuulPskServer tlsPskServer;

    public TlsPskHandlerFixed(
            Registry registry,
            ExternalTlsPskProvider externalTlsPskProvider,
            Set<ProtocolName> supportedApplicationProtocols) {
        super();
        this.registry = registry;
        this.externalTlsPskProvider = externalTlsPskProvider;
        this.supportedApplicationProtocols = supportedApplicationProtocols;
        this.tlsPskServerProtocol = new TlsPskServerProtocol();
    }

    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
        if (!(msg instanceof ByteBuf byteBufMsg)) {
            ReferenceCountUtil.safeRelease(msg);
            promise.setFailure(
                    new IllegalStateException("Failed to write message on the channel. Message is not a ByteBuf"));
            return;
        }
        
        try {
            // FIX 1: Get the actual readable bytes, not the full capacity
            int length = byteBufMsg.readableBytes();
            byte[] appDataBytes;
            int offset;
            
            if (byteBufMsg.hasArray()) {
                // FIX 2: Respect buffer boundaries - use array offset + reader index
                appDataBytes = byteBufMsg.array();
                offset = byteBufMsg.arrayOffset() + byteBufMsg.readerIndex();
            } else {
                // For direct buffers, copy only readable bytes
                appDataBytes = new byte[length];
                byteBufMsg.readBytes(appDataBytes);
                offset = 0;
            }
            
            // FIX 3: Pass only readable bytes and proper offset to encryption
            tlsPskServerProtocol.writeApplicationData(appDataBytes, offset, length);
            
            int availableOutputBytes = tlsPskServerProtocol.getAvailableOutputBytes();
            if (availableOutputBytes != 0) {
                byte[] outputBytes = new byte[availableOutputBytes];
                tlsPskServerProtocol.readOutput(outputBytes, 0, availableOutputBytes);
                ctx.writeAndFlush(Unpooled.wrappedBuffer(outputBytes), promise)
                        .addListener(ChannelFutureListener.FIRE_EXCEPTION_ON_FAILURE);
            }
        } finally {
            // FIX 4: Release buffer AFTER encryption completes, in finally block
            ReferenceCountUtil.safeRelease(byteBufMsg);
        }
    }

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) {
        ctx.pipeline().addBefore(ctx.name(), "tls_psk_handler", new TlsPskDecoder(tlsPskServerProtocol));
    }

    @Override
    public void channelRegistered(ChannelHandlerContext ctx) throws Exception {
        tlsPskServer = new ZuulPskServer(
                new JcaTlsCryptoProvider().create(secureRandom),
                registry,
                externalTlsPskProvider,
                ctx,
                supportedApplicationProtocols);
        tlsPskServerProtocol.accept(tlsPskServer);
        super.channelRegistered(ctx);
    }

    public String getApplicationProtocol() {
        return tlsPskServer != null ? tlsPskServer.getApplicationProtocol() : null;
    }

    public SSLSession getSession() {
        return tlsPskServerProtocol != null ? tlsPskServerProtocol.getSSLSession() : null;
    }
}
