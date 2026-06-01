/*
 * Copyright 2018 Netflix, Inc.
 *
 *      Licensed under the Apache License, Version 2.0 (the "License");
 *      you may not use this file except in compliance with the License.
 *      You may obtain a copy of the License at
 *
 *          http://www.apache.org/licenses/LICENSE-2.0
 *
 *      Unless required by applicable law or agreed to in writing, software
 *      distributed under the License is distributed on an "AS IS" BASIS,
 *      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *      See the License for the specific language governing permissions and
 *      limitations under the License.
 */

package com.netflix.zuul.sample;

import com.netflix.appinfo.ApplicationInfoManager;
import com.netflix.config.DynamicIntProperty;
import com.netflix.discovery.EurekaClient;
import com.netflix.netty.common.accesslog.AccessLogPublisher;
import com.netflix.netty.common.channel.config.ChannelConfig;
import com.netflix.netty.common.channel.config.CommonChannelConfigKeys;
import com.netflix.netty.common.metrics.EventLoopGroupMetrics;
import com.netflix.netty.common.proxyprotocol.StripUntrustedProxyHeadersHandler;
import com.netflix.netty.common.ssl.ServerSslConfig;
import com.netflix.netty.common.status.ServerStatusManager;
import com.netflix.spectator.api.Registry;
import com.netflix.zuul.FilterLoader;
import com.netflix.zuul.FilterUsageNotifier;
import com.netflix.zuul.RequestCompleteHandler;
import com.netflix.zuul.context.SessionContextDecorator;
import com.netflix.zuul.netty.server.BaseServerStartup;
import com.netflix.zuul.netty.server.DefaultEventLoopConfig;
import com.netflix.zuul.netty.server.DirectMemoryMonitor;
import com.netflix.zuul.netty.server.Http1MutualSslChannelInitializer;
import com.netflix.zuul.netty.server.NamedSocketAddress;
import com.netflix.zuul.netty.server.SocketAddressProperty;
import com.netflix.zuul.netty.server.ZuulDependencyKeys;
import com.netflix.zuul.netty.server.ZuulServerChannelInitializer;
import com.netflix.zuul.netty.server.http2.Http2SslChannelInitializer;
import com.netflix.zuul.netty.server.push.PushConnectionRegistry;
import com.netflix.zuul.netty.server.psk.HardcodedPskProvider;
import com.netflix.zuul.netty.server.psk.TlsPskHandler;
import com.netflix.zuul.netty.ssl.BaseSslContextFactory;
import com.netflix.zuul.sample.push.SamplePushMessageSenderInitializer;
import com.netflix.zuul.sample.push.SampleSSEPushChannelInitializer;
import com.netflix.zuul.sample.push.SampleWebSocketPushChannelInitializer;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.group.ChannelGroup;
import io.netty.handler.ssl.ClientAuth;
import java.io.File;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Sample Server Startup — extended with a PSK listener on port 7002 to
 * demonstrate the TlsPskHandler Use-After-Free and buffer over-read.
 */
public class SampleServerStartup extends BaseServerStartup {

    enum ServerType {
        HTTP,
        HTTP2,
        HTTP_MUTUAL_TLS,
        WEBSOCKET,
        SSE,
        PSK   // ← added for PoC
    }

    private static final String[] WWW_PROTOCOLS = new String[] {"TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1", "SSLv3"};
    // Change to PSK to expose the vulnerable listener
    private static final ServerType SERVER_TYPE = ServerType.PSK;
    private final PushConnectionRegistry pushConnectionRegistry;
    private final SamplePushMessageSenderInitializer pushSenderInitializer;

    public SampleServerStartup(
            ServerStatusManager serverStatusManager,
            FilterLoader filterLoader,
            SessionContextDecorator sessionCtxDecorator,
            FilterUsageNotifier usageNotifier,
            RequestCompleteHandler reqCompleteHandler,
            Registry registry,
            DirectMemoryMonitor directMemoryMonitor,
            EventLoopGroupMetrics eventLoopGroupMetrics,
            EurekaClient discoveryClient,
            ApplicationInfoManager applicationInfoManager,
            AccessLogPublisher accessLogPublisher,
            PushConnectionRegistry pushConnectionRegistry,
            SamplePushMessageSenderInitializer pushSenderInitializer) {
        super(
                serverStatusManager,
                filterLoader,
                sessionCtxDecorator,
                usageNotifier,
                reqCompleteHandler,
                registry,
                directMemoryMonitor,
                eventLoopGroupMetrics,
                new DefaultEventLoopConfig(),
                discoveryClient,
                applicationInfoManager,
                accessLogPublisher);
        this.pushConnectionRegistry = pushConnectionRegistry;
        this.pushSenderInitializer = pushSenderInitializer;
    }

    @Override
    protected Map<NamedSocketAddress, ChannelInitializer<?>> chooseAddrsAndChannels(ChannelGroup clientChannels) {
        Map<NamedSocketAddress, ChannelInitializer<?>> addrsToChannels = new HashMap<>();
        SocketAddress sockAddr;
        String metricId;
        {
            int port = new DynamicIntProperty("zuul.server.port.main", 7001).get();
            sockAddr = new SocketAddressProperty("zuul.server.addr.main", "=" + port).getValue();
            if (sockAddr instanceof InetSocketAddress inetSocketAddress) {
                metricId = String.valueOf(inetSocketAddress.getPort());
            } else {
                metricId = sockAddr.toString();
            }
        }

        SocketAddress pushSockAddr;
        {
            int pushPort = new DynamicIntProperty("zuul.server.port.http.push", 7008).get();
            pushSockAddr = new SocketAddressProperty("zuul.server.addr.http.push", "=" + pushPort).getValue();
        }

        // PSK listener address — port 7002
        SocketAddress pskSockAddr;
        {
            int pskPort = new DynamicIntProperty("zuul.server.port.psk", 7002).get();
            pskSockAddr = new SocketAddressProperty("zuul.server.addr.psk", "=" + pskPort).getValue();
        }

        String mainListenAddressName = "main";
        ServerSslConfig sslConfig;
        ChannelConfig channelConfig = defaultChannelConfig(mainListenAddressName);
        ChannelConfig channelDependencies = defaultChannelDependencies(mainListenAddressName);

        switch (SERVER_TYPE) {
            case HTTP -> {
                channelConfig.set(
                        CommonChannelConfigKeys.allowProxyHeadersWhen,
                        StripUntrustedProxyHeadersHandler.AllowWhen.NEVER);
                channelConfig.set(CommonChannelConfigKeys.preferProxyProtocolForClientIp, false);
                channelConfig.set(CommonChannelConfigKeys.isSSlFromIntermediary, false);
                channelConfig.set(CommonChannelConfigKeys.withProxyProtocol, false);

                addrsToChannels.put(
                        new NamedSocketAddress("http", sockAddr),
                        new ZuulServerChannelInitializer(metricId, channelConfig, channelDependencies, clientChannels));
                logAddrConfigured(sockAddr);
            }

            case HTTP2 -> {
                sslConfig = ServerSslConfig.builder()
                        .protocols(WWW_PROTOCOLS)
                        .ciphers(ServerSslConfig.getDefaultCiphers())
                        .certChainFile(loadFromResources("server.cert"))
                        .keyFile(loadFromResources("server.key"))
                        .build();

                channelConfig.set(
                        CommonChannelConfigKeys.allowProxyHeadersWhen,
                        StripUntrustedProxyHeadersHandler.AllowWhen.NEVER);
                channelConfig.set(CommonChannelConfigKeys.preferProxyProtocolForClientIp, true);
                channelConfig.set(CommonChannelConfigKeys.isSSlFromIntermediary, false);
                channelConfig.set(CommonChannelConfigKeys.serverSslConfig, sslConfig);
                channelConfig.set(
                        CommonChannelConfigKeys.sslContextFactory, new BaseSslContextFactory(registry, sslConfig));

                addHttp2DefaultConfig(channelConfig, mainListenAddressName);

                addrsToChannels.put(
                        new NamedSocketAddress("http2", sockAddr),
                        new Http2SslChannelInitializer(metricId, channelConfig, channelDependencies, clientChannels));
                logAddrConfigured(sockAddr, sslConfig);
            }

            case HTTP_MUTUAL_TLS -> {
                sslConfig = ServerSslConfig.builder()
                        .protocols(WWW_PROTOCOLS)
                        .ciphers(ServerSslConfig.getDefaultCiphers())
                        .certChainFile(loadFromResources("server.cert"))
                        .keyFile(loadFromResources("server.key"))
                        .clientAuth(ClientAuth.REQUIRE)
                        .clientAuthTrustStoreFile(loadFromResources("truststore.jks"))
                        .clientAuthTrustStorePasswordFile(loadFromResources("truststore.key"))
                        .build();

                channelConfig.set(
                        CommonChannelConfigKeys.allowProxyHeadersWhen,
                        StripUntrustedProxyHeadersHandler.AllowWhen.NEVER);
                channelConfig.set(CommonChannelConfigKeys.preferProxyProtocolForClientIp, true);
                channelConfig.set(CommonChannelConfigKeys.isSSlFromIntermediary, false);
                channelConfig.set(CommonChannelConfigKeys.withProxyProtocol, true);
                channelConfig.set(CommonChannelConfigKeys.serverSslConfig, sslConfig);
                channelConfig.set(
                        CommonChannelConfigKeys.sslContextFactory, new BaseSslContextFactory(registry, sslConfig));

                addrsToChannels.put(
                        new NamedSocketAddress("http_mtls", sockAddr),
                        new Http1MutualSslChannelInitializer(
                                metricId, channelConfig, channelDependencies, clientChannels));
                logAddrConfigured(sockAddr, sslConfig);
            }

            case WEBSOCKET -> {
                channelConfig.set(
                        CommonChannelConfigKeys.allowProxyHeadersWhen,
                        StripUntrustedProxyHeadersHandler.AllowWhen.NEVER);
                channelConfig.set(CommonChannelConfigKeys.preferProxyProtocolForClientIp, true);
                channelConfig.set(CommonChannelConfigKeys.isSSlFromIntermediary, false);
                channelConfig.set(CommonChannelConfigKeys.withProxyProtocol, true);

                channelDependencies.set(ZuulDependencyKeys.pushConnectionRegistry, pushConnectionRegistry);

                addrsToChannels.put(
                        new NamedSocketAddress("websocket", sockAddr),
                        new SampleWebSocketPushChannelInitializer(
                                metricId, channelConfig, channelDependencies, clientChannels));
                logAddrConfigured(sockAddr);

                addrsToChannels.put(new NamedSocketAddress("http.push", pushSockAddr), pushSenderInitializer);
                logAddrConfigured(pushSockAddr);
            }

            case SSE -> {
                channelConfig.set(
                        CommonChannelConfigKeys.allowProxyHeadersWhen,
                        StripUntrustedProxyHeadersHandler.AllowWhen.NEVER);
                channelConfig.set(CommonChannelConfigKeys.preferProxyProtocolForClientIp, true);
                channelConfig.set(CommonChannelConfigKeys.isSSlFromIntermediary, false);
                channelConfig.set(CommonChannelConfigKeys.withProxyProtocol, true);

                channelDependencies.set(ZuulDependencyKeys.pushConnectionRegistry, pushConnectionRegistry);

                addrsToChannels.put(
                        new NamedSocketAddress("sse", sockAddr),
                        new SampleSSEPushChannelInitializer(
                                metricId, channelConfig, channelDependencies, clientChannels));
                logAddrConfigured(sockAddr);

                addrsToChannels.put(new NamedSocketAddress("http.push", pushSockAddr), pushSenderInitializer);
                logAddrConfigured(pushSockAddr);
            }

            // ── PSK listener — exposes the vulnerable TlsPskHandler ──────────────
            case PSK -> {
                // Plain HTTP on port 7001 so the backend/healthcheck path still works
                channelConfig.set(
                        CommonChannelConfigKeys.allowProxyHeadersWhen,
                        StripUntrustedProxyHeadersHandler.AllowWhen.NEVER);
                channelConfig.set(CommonChannelConfigKeys.preferProxyProtocolForClientIp, false);
                channelConfig.set(CommonChannelConfigKeys.isSSlFromIntermediary, false);
                channelConfig.set(CommonChannelConfigKeys.withProxyProtocol, false);

                addrsToChannels.put(
                        new NamedSocketAddress("http", sockAddr),
                        new ZuulServerChannelInitializer(metricId, channelConfig, channelDependencies, clientChannels));
                logAddrConfigured(sockAddr);

                // PSK listener on port 7002 — wraps the same HTTP pipeline under TLS-PSK
                // using the vulnerable TlsPskHandler
                HardcodedPskProvider pskProvider = new HardcodedPskProvider();
                addrsToChannels.put(
                        new NamedSocketAddress("psk", pskSockAddr),
                        new ChannelInitializer<Channel>() {
                            @Override
                            protected void initChannel(Channel ch) {
                                ChannelPipeline p = ch.pipeline();
                                // TlsPskHandler installs TlsPskDecoder via handlerAdded,
                                // then decrypts inbound and (buggy) encrypts outbound
                                p.addLast(new TlsPskHandler(registry, pskProvider, Set.of()));
                                // After PSK decryption, treat the channel as plain HTTP
                                ChannelConfig pskChannelConfig = defaultChannelConfig("psk");
                                ChannelConfig pskChannelDeps   = defaultChannelDependencies("psk");
                                pskChannelConfig.set(
                                        CommonChannelConfigKeys.allowProxyHeadersWhen,
                                        StripUntrustedProxyHeadersHandler.AllowWhen.NEVER);
                                pskChannelConfig.set(CommonChannelConfigKeys.preferProxyProtocolForClientIp, false);
                                pskChannelConfig.set(CommonChannelConfigKeys.isSSlFromIntermediary, false);
                                pskChannelConfig.set(CommonChannelConfigKeys.withProxyProtocol, false);
                                new ZuulServerChannelInitializer(
                                        "7002", pskChannelConfig, pskChannelDeps, clientChannels)
                                        .initChannel(ch);
                            }
                        });
                logAddrConfigured(pskSockAddr);
            }
        }

        return Collections.unmodifiableMap(addrsToChannels);
    }

    private File loadFromResources(String s) {
        return new File(ClassLoader.getSystemResource("ssl/" + s).getFile());
    }
}
