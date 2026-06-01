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
import com.netflix.zuul.netty.ssl.BaseSslContextFactory;
import com.netflix.zuul.netty.server.psk.HardcodedPskProvider;
import com.netflix.zuul.netty.server.psk.TlsPskHandler;
import com.netflix.zuul.sample.push.SamplePushMessageSenderInitializer;
import com.netflix.zuul.sample.push.SampleSSEPushChannelInitializer;
import com.netflix.zuul.sample.push.SampleWebSocketPushChannelInitializer;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
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
 * Sample Server Startup - class that configures the Netty server startup settings
 *
 * Author: Arthur Gonigberg
 * Date: November 20, 2017
 */
public class SampleServerStartup extends BaseServerStartup {

    enum ServerType {
        HTTP,
        HTTP2,
        HTTP_MUTUAL_TLS,
        WEBSOCKET,
        SSE,
        PSK
    }

    private static final String[] WWW_PROTOCOLS = new String[] {"TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1", "SSLv3"};
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

            case PSK -> {
                // Plain HTTP on port 7001 — /healthcheck routing and the Zuul filter
                // chain work normally here. This listener is used to verify routing works
                // before hitting the PSK path.
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

                // PSK listener on 7002.
                // TlsPskHandler sits first in the pipeline. On inbound it hands off
                // decrypted bytes to ZuulServerChannelInitializer's HTTP pipeline.
                // On outbound (TlsPskHandler.write) the bug fires:
                //   TlsPskUtils.getAppDataBytesAndRelease returns byteBufMsg.array()
                //   (full heap pool chunk, not readableBytes) and frees it before use.
                ChannelConfig pskCfg = defaultChannelConfig("psk");
                ChannelConfig pskDeps = defaultChannelDependencies("psk");
                pskCfg.set(CommonChannelConfigKeys.allowProxyHeadersWhen,
                        StripUntrustedProxyHeadersHandler.AllowWhen.NEVER);
                pskCfg.set(CommonChannelConfigKeys.preferProxyProtocolForClientIp, false);
                pskCfg.set(CommonChannelConfigKeys.isSSlFromIntermediary, false);
                pskCfg.set(CommonChannelConfigKeys.withProxyProtocol, false);

                ZuulServerChannelInitializer httpInit =
                        new ZuulServerChannelInitializer("7002", pskCfg, pskDeps, clientChannels);
                HardcodedPskProvider pskProvider = new HardcodedPskProvider();

                addrsToChannels.put(
                        new NamedSocketAddress("psk", pskSockAddr),
                        new ChannelInitializer<Channel>() {
                            @Override
                            protected void initChannel(Channel ch) throws Exception {
                                ch.pipeline().addLast(new TlsPskHandler(registry, pskProvider, Set.of()));
                                httpInit.initChannel(ch);
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