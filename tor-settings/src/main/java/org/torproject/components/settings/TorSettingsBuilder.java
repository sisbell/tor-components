package org.torproject.components.settings;/*
Copyright (c) Microsoft Open Technologies, Inc.
All Rights Reserved
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED,
INCLUDING WITHOUT LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A PARTICULAR PURPOSE,
MERCHANTABLITY OR NON-INFRINGEMENT.

See the Apache 2 License for the specific language governing permissions and limitations under the License.
*/

import java.io.*;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

public final class TorSettingsBuilder {

    private final TorSettings settings;

    private File controlPortFile;

    private File cookieAuthFile;

    private File geoIpFile;

    private File geoIpV6File;

    private File nameserverFile;

    private InputStream bridgesStream;

    private StringBuffer buffer = new StringBuffer();

    public TorSettingsBuilder(TorSettings torSettings, InputStream bridgesStream, TorConfigFiles configFiles) {
        this.settings = torSettings;
        this.bridgesStream = bridgesStream;
        if (configFiles != null) {
            this.controlPortFile = configFiles.getControlPortFile();
            this.cookieAuthFile = configFiles.getCookieAuthFile();
            this.geoIpFile = configFiles.getGeoIpFile();
            this.geoIpV6File = configFiles.getGeoIpV6File();
            this.nameserverFile = configFiles.getNameserverFile();
        }
    }

    /**
     * Updates the tor config for all methods annotated with SettingsConfig
     */
    public TorSettingsBuilder updateTorConfig() throws Exception {
        for (Method method : getClass().getMethods()) {
            for (Annotation annotation : method.getAnnotations()) {
                if (annotation instanceof SettingsConfig) {
                    method.invoke(this);
                    break;
                }
            }
        }
        return this;
    }

    private static boolean isNullOrEmpty(String value) {
        return value == null || value.isEmpty();
    }

    private static boolean isLocalPortOpen(int port) {
        Socket socket = null;
        try {
            socket = new Socket();
            socket.connect(new InetSocketAddress("127.0.0.1", port), 500);
            return true;
        } catch (Exception e) {
            return false;
        } finally {
            if (socket != null) {
                try {
                    socket.close();
                } catch (Exception ee) {
                }
            }
        }
    }

    public String asString() {
        return buffer.toString();
    }

    public TorSettingsBuilder automapHostsOnResolve() {
        return writeTrueProperty("AutomapHostsOnResolve");
    }

    @SettingsConfig
    public TorSettingsBuilder automapHostsOnResolveFromSettings() {
        return settings.isAutomapHostsOnResolve() ? automapHostsOnResolve() : this;
    }

    public TorSettingsBuilder bridge(String type, String config) {
        if (!isNullOrEmpty(type) && !isNullOrEmpty(config)) {
            buffer.append("Bridge ").append(type).append(' ').append(config).append('\n');
        }
        return this;
    }

    public TorSettingsBuilder bridgeCustom(String config) {
        if (!isNullOrEmpty(config)) {
            writeLine("Bridge", config);
        }
        return this;
    }

    @SettingsConfig
    public TorSettingsBuilder bridgesFromSettings() {
        try {
            addBridgesFromResources();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return this;
    }

    public TorSettingsBuilder configurePluggableTransportsFromSettings(File pluggableTransportClient) throws IOException {
        List<String> supportedBridges = settings.getListOfSupportedBridges();
        if (pluggableTransportClient == null || supportedBridges == null || supportedBridges.isEmpty()) {
            return this;
        }

        if (!pluggableTransportClient.exists()) {
            throw new IOException("Bridge binary does not exist: " + pluggableTransportClient
                    .getCanonicalPath());
        }

        if (!pluggableTransportClient.canExecute()) {
            throw new IOException("Bridge binary is not executable: " + pluggableTransportClient
                    .getCanonicalPath());
        }

        if (supportedBridges.contains("obfs3") || supportedBridges.contains("obfs4")) {
            transportPluginObfs(pluggableTransportClient.getCanonicalPath());
        }
        if (supportedBridges.contains("meek")) {
            transportPluginMeek(pluggableTransportClient.getCanonicalPath());
        }
        return this;
    }

    public TorSettingsBuilder cookieAuthentication() {
        if (cookieAuthFile != null) {
            return writeTrueProperty("CookieAuthentication")
                    .writeLine("CookieAuthFile", cookieAuthFile.getAbsolutePath());
        }
        return this;
    }

    @SettingsConfig
    public TorSettingsBuilder cookieAuthenticationFromSettings() {
        return settings.hasCookieAuthentication() ? cookieAuthentication() : this;
    }

    public TorSettingsBuilder connectionPadding() {
        return writeTrueProperty("ConnectionPadding");
    }

    @SettingsConfig
    public TorSettingsBuilder connectionPaddingFromSettings() {
        return settings.hasConnectionPadding() ? connectionPadding() : this;
    }

    public TorSettingsBuilder controlPortWriteToFile(String controlPortFile) {
        return writeLine("ControlPortWriteToFile", controlPortFile).writeLine("ControlPort auto");
    }

    @SettingsConfig
    public TorSettingsBuilder controlPortWriteToFileFromConfig() {
        if (controlPortFile != null) {
            return controlPortWriteToFile(controlPortFile.getAbsolutePath());
        }
        return this;
    }

    public TorSettingsBuilder debugLogs() {
        writeLine("Log debug syslog");
        writeLine("Log info syslog");
        return writeFalseProperty("SafeLogging");
    }

    @SettingsConfig
    public TorSettingsBuilder debugLogsFromSettings() {
        return settings.hasDebugLogs() ? debugLogs() : this;
    }

    public TorSettingsBuilder disableNetwork() {
        return writeTrueProperty("DisableNetwork");
    }

    @SettingsConfig
    public TorSettingsBuilder disableNetworkFromSettings() {
        return settings.disableNetwork() ? disableNetwork() : this;
    }

    public TorSettingsBuilder dnsPort(String dnsPort) {
        return writeLine("DNSPort", dnsPort);
    }

    @SettingsConfig
    public TorSettingsBuilder dnsPortFromSettings() {
        return dnsPort(settings.dnsPort());
    }

    public TorSettingsBuilder dontUseBridges() {
        return writeFalseProperty("UseBridges");
    }

    public TorSettingsBuilder dormantCanceledByStartup() {
        buffer.append("DormantCanceledByStartup 1\n");
        return this;
    }

    @SettingsConfig
    public TorSettingsBuilder dormantCanceledByStartupFromSettings() {
        if (settings.hasDormantCanceledByStartup()) {
            dormantCanceledByStartup();
        }
        return this;
    }

    public TorSettingsBuilder entryNodes(String entryNodes) {
        if (!isNullOrEmpty(entryNodes))
            writeLine("EntryNodes", entryNodes);
        return this;
    }

    public TorSettingsBuilder excludeNodes(String excludeNodes) {
        if (!isNullOrEmpty(excludeNodes))
            writeLine("ExcludeNodes", excludeNodes);
        return this;
    }

    public TorSettingsBuilder exitNodes(String exitNodes) {
        if (!isNullOrEmpty(exitNodes))
            writeLine("ExitNodes", exitNodes);
        return this;
    }

    public TorSettingsBuilder geoIpFile(String path) {
        if (!isNullOrEmpty(path))
            writeLine("GeoIPFile", path);
        return this;
    }

    public TorSettingsBuilder geoIpV6File(String path) {
        if (!isNullOrEmpty(path))
            writeLine("GeoIPv6File", path);
        return this;
    }

    public TorSettingsBuilder httpTunnelPort(int port, String isolationFlags) {
        buffer.append("HTTPTunnelPort ").append(port);
        if (!isNullOrEmpty(isolationFlags)) {
            buffer.append(" ").append(isolationFlags);
        }
        buffer.append('\n');
        return this;
    }

    @SettingsConfig
    public TorSettingsBuilder httpTunnelPortFromSettings() {
        return httpTunnelPort(settings.getHttpTunnelPort(),
                settings.hasIsolationAddressFlagForTunnel() ? "IsolateDestAddr" : null);
    }

    public TorSettingsBuilder makeNonExitRelay(String dnsFile, int orPort, String nickname) {
        writeLine("ServerDNSResolvConfFile", dnsFile);
        writeLine("ORPort", String.valueOf(orPort));
        writeLine("Nickname", nickname);
        return writeLine("ExitPolicy reject *:*");
    }

    /**
     * Sets the entry/exit/exclude nodes
     */
    @SettingsConfig
    public TorSettingsBuilder nodesFromSettings() {
        entryNodes(settings.getEntryNodes()).exitNodes(settings.getExitNodes())
                .excludeNodes(settings.getExcludeNodes());
        return this;
    }

    /**
     * Adds non exit relay to builder. This method uses a default google nameserver.
     */
    @SettingsConfig
    public TorSettingsBuilder nonExitRelayFromSettings() {
        if (nameserverFile != null && !settings.hasReachableAddress() && !settings.hasBridges() && settings.isRelay()) {
            try {
                makeNonExitRelay(nameserverFile.getCanonicalPath(), settings.getRelayPort(), settings
                        .getRelayNickname());
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return this;
    }

    public TorSettingsBuilder proxyOnAllInterfaces() {
        return writeLine("SocksListenAddress 0.0.0.0");
    }

    @SettingsConfig
    public TorSettingsBuilder proxyOnAllInterfacesFromSettings() {
        return settings.hasOpenProxyOnAllInterfaces() ? proxyOnAllInterfaces() : this;
    }

    /**
     * Set socks5 proxy with no authentication. This can be set if yo uare using a VPN.
     */
    public TorSettingsBuilder proxySocks5(String host, String port) {
        buffer.append("socks5Proxy ").append(host).append(':').append(port).append('\n');
        return this;
    }

    @SettingsConfig
    public TorSettingsBuilder proxySocks5FromSettings() {
        return (settings.useSocks5() && !settings.hasBridges()) ? proxySocks5(settings
                        .getProxySocks5Host(),
                settings.getProxySocks5ServerPort()) : this;
    }

    /**
     * Sets proxyWithAuthentication information. If proxyType, proxyHost or proxyPort is empty,
     * then this method does nothing.
     */
    public TorSettingsBuilder proxyWithAuthentication(String proxyType, String proxyHost, String
            proxyPort, String proxyUser, String proxyPass) {
        if (!isNullOrEmpty(proxyType) && !isNullOrEmpty(proxyHost) && !isNullOrEmpty(proxyPort)) {
            buffer.append(proxyType).append("Proxy ").append(proxyHost).append(':').append
                    (proxyPort).append('\n');

            if (proxyUser != null && proxyPass != null) {
                if (proxyType.equalsIgnoreCase("socks5")) {
                    writeLine("Socks5ProxyUsername", proxyUser);
                    writeLine("Socks5ProxyPassword", proxyPass);
                } else {
                    buffer.append(proxyType).append("ProxyAuthenticator ").append(proxyUser)
                            .append(':').append(proxyPort).append('\n');
                }
            } else if (proxyPass != null) {
                buffer.append(proxyType).append("ProxyAuthenticator ").append(proxyUser)
                        .append(':').append(proxyPort).append('\n');
            }
        }
        return this;
    }

    @SettingsConfig
    public TorSettingsBuilder proxyWithAuthenticationFromSettings() {
        return (!settings.useSocks5() && !settings.hasBridges()) ? proxyWithAuthentication
                (settings.getProxyType(), settings.getProxyHost(),
                        settings.getProxyPort(), settings.getProxyUser(), settings
                                .getProxyPassword()) :
                this;
    }

    public TorSettingsBuilder reachableAddressPorts(String reachableAddressesPorts) {
        if (!isNullOrEmpty(reachableAddressesPorts))
            writeLine("ReachableAddresses", reachableAddressesPorts);
        return this;
    }

    @SettingsConfig
    public TorSettingsBuilder reachableAddressesFromSettings() {
        return settings.hasReachableAddress() ? reachableAddressPorts(settings
                .getReachableAddressPorts()) : this;

    }

    public TorSettingsBuilder reducedConnectionPadding() {
        return writeTrueProperty("ReducedConnectionPadding");
    }

    @SettingsConfig
    public TorSettingsBuilder reducedConnectionPaddingFromSettings() {
        return settings.hasReducedConnectionPadding() ? reducedConnectionPadding() : this;
    }

    public void reset() {
        buffer = new StringBuffer();
    }

    @SettingsConfig
    public TorSettingsBuilder runAsDaemonFromSettings() {
        return settings.runAsDaemon() ? runAsDaemon() : this;
    }

    public TorSettingsBuilder runAsDaemon() {
        return writeTrueProperty("RunAsDaemon");
    }

    public TorSettingsBuilder safeSocksDisable() {
        return writeFalseProperty("SafeSocks");
    }

    public TorSettingsBuilder safeSocksEnable() {
        return writeTrueProperty("SafeSocks");
    }

    @SettingsConfig
    public TorSettingsBuilder safeSocksFromSettings() {
        return !settings.hasSafeSocks() ? safeSocksDisable() : safeSocksEnable();
    }

    public TorSettingsBuilder setGeoIpFiles() throws IOException {
        if (geoIpFile != null && geoIpFile.exists()) {
            geoIpFile(geoIpFile.getCanonicalPath());
        }
        if (geoIpV6File != null && geoIpV6File.exists()) {
            geoIpV6File(geoIpV6File.getCanonicalPath());
        }
        return this;
    }

    public TorSettingsBuilder socksPort(String socksPort, String isolationFlag) {
        if (isNullOrEmpty(socksPort)) {
            return this;
        }
        buffer.append("SOCKSPort ").append(socksPort);
        if (!isNullOrEmpty(isolationFlag)) {
            buffer.append(" ").append(isolationFlag);
        }
        buffer.append(" KeepAliveIsolateSOCKSAuth");
        buffer.append(" IPv6Traffic");
        buffer.append(" PreferIPv6");

        buffer.append('\n');
        return this;
    }

    @SettingsConfig
    public TorSettingsBuilder socksPortFromSettings() {
        String socksPort = settings.getSocksPort();
        if (socksPort.indexOf(':') != -1) {
            socksPort = socksPort.split(":")[1];
        }

        if (!socksPort.equalsIgnoreCase("auto") && isLocalPortOpen(Integer.parseInt(socksPort))) {
            socksPort = "auto";
        }
        return socksPort(socksPort, settings.hasIsolationAddressFlagForTunnel() ?
                "IsolateDestAddr" : null);
    }

    public TorSettingsBuilder strictNodesDisable() {
        return writeFalseProperty("StrictNodes");
    }

    public TorSettingsBuilder strictNodesEnable() {
        return writeTrueProperty("StrictNodes");
    }

    @SettingsConfig
    public TorSettingsBuilder strictNodesFromSettings() {
        return settings.hasStrictNodes() ? strictNodesEnable() : strictNodesDisable();
    }

    public TorSettingsBuilder testSocksDisable() {
        return writeFalseProperty("TestSocks");
    }

    public TorSettingsBuilder testSocksEnable() {
        return writeTrueProperty("TestSocks");
    }

    @SettingsConfig
    public TorSettingsBuilder testSocksFromSettings() {
        return !settings.hasTestSocks() ? testSocksDisable() : this;
    }

    @SettingsConfig
    public TorSettingsBuilder torrcCustomFromSettings() throws UnsupportedEncodingException {
        return settings.getCustomTorrc() != null ?
                writeLine(new String(settings.getCustomTorrc().getBytes("US-ASCII"))) : this;
    }

    public TorSettingsBuilder transPort(String transPort) {
        if (!isNullOrEmpty(transPort))
            writeLine("TransPort", transPort);
        return this;
    }

    @SettingsConfig
    public TorSettingsBuilder transPortFromSettings() {
        return transPort(settings.transPort());
    }

    public TorSettingsBuilder transportPluginMeek(String clientPath) {
        return writeLine("ClientTransportPlugin meek_lite exec", clientPath);
    }

    public TorSettingsBuilder transportPluginObfs(String clientPath) {
        return writeLine("ClientTransportPlugin obfs3 exec", clientPath)
                .writeLine("ClientTransportPlugin obfs4 exec", clientPath);
    }

    public TorSettingsBuilder useBridges() {
        return writeTrueProperty("UseBridges");
    }

    @SettingsConfig
    public TorSettingsBuilder useBridgesFromSettings() {
        return settings.hasBridges() ? useBridges() : this;
    }

    public TorSettingsBuilder virtualAddressNetwork(String address) {
        if (!isNullOrEmpty(address))
            writeLine("VirtualAddrNetwork", address);
        return this;
    }

    @SettingsConfig
    public TorSettingsBuilder virtualAddressNetworkFromSettings() {
        return virtualAddressNetwork(settings.getVirtualAddressNetwork());
    }

    public TorSettingsBuilder writeAddress(String fieldName, String address, Integer port, String flags) {
        if (isNullOrEmpty(address) && port == null) {
            return this;
        }
        buffer.append(fieldName).append(" ");
        if (!isNullOrEmpty(address)) {
            buffer.append(address).append(":");
        }
        if (port != null && port >= 0) {
            buffer.append(port);
        } else {
            buffer.append("auto");
        }
        if (!isNullOrEmpty(flags)) {
            buffer.append(" ").append(flags);
        }
        buffer.append('\n');
        return this;
    }

    public TorSettingsBuilder writeFalseProperty(String name) {
        buffer.append(name).append(" 0").append('\n');
        return this;
    }

    public TorSettingsBuilder writeLine(String value) {
        if (!isNullOrEmpty(value)) buffer.append(value).append("\n");
        return this;
    }

    public TorSettingsBuilder writeLine(String value, String value2) {
        return writeLine(value + " " + value2);
    }

    public TorSettingsBuilder writeTrueProperty(String name) {
        buffer.append(name).append(" 1").append('\n');
        return this;
    }

    /**
     * Adds bridges from a resource stream. This relies on the TorInstaller to know how to obtain this stream.
     * These entries may be type-specified like:
     *
     * <code>
     * obfs3 169.229.59.74:31493 AF9F66B7B04F8FF6F32D455F05135250A16543C9
     * </code>
     * <p>
     * Or it may just be a custom entry like
     *
     * <code>
     * 69.163.45.129:443 9F090DE98CA6F67DEEB1F87EFE7C1BFD884E6E2F
     * </code>
     */
    TorSettingsBuilder addBridgesFromResources() throws IOException {
        if (settings.hasBridges()) {
            InputStream bridgesStream = this.bridgesStream;
            int formatType = bridgesStream.read();
            if (formatType == 0) {
                addBridges(bridgesStream);
            } else {
                addCustomBridges(bridgesStream);
            }
        }
        return this;
    }

    /**
     * Add bridges from bridges.txt file.
     */
    private void addBridges(InputStream input) {
        if (input == null) {
            return;
        }
        List<Bridge> bridges = readBridgesFromStream(input);
        for (Bridge b : bridges) {
            bridge(b.type, b.config);
        }
    }

    /**
     * Add custom bridges defined by the user. These will have a bridgeType of 'custom' as the first field.
     */
    private void addCustomBridges(InputStream input) {
        if (input == null) {
            return;
        }
        List<Bridge> bridges = readCustomBridgesFromStream(input);
        for (Bridge b : bridges) {
            if (b.type.equals("custom")) {
                bridgeCustom(b.config);
            }
        }
    }

    private static List<Bridge> readBridgesFromStream(InputStream input) {
        List<Bridge> bridges = new ArrayList<>();
        try {
            BufferedReader br = new BufferedReader(new InputStreamReader(input, "UTF-8"));
            for (String line = br.readLine(); line != null; line = br.readLine()) {
                String[] tokens = line.split("\\s+", 2);
                if (tokens.length != 2) {
                    continue;//bad entry
                }
                bridges.add(new Bridge(tokens[0], tokens[1]));
            }
            br.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return bridges;
    }

    private static List<Bridge> readCustomBridgesFromStream(InputStream input) {
        List<Bridge> bridges = new ArrayList<>();
        try {
            BufferedReader br = new BufferedReader(new InputStreamReader(input, "UTF-8"));
            for (String line = br.readLine(); line != null; line = br.readLine()) {
                if (line.isEmpty()) {
                    continue;
                }
                bridges.add(new Bridge("custom", line));
            }
            br.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return bridges;
    }

    private static class Bridge {
        final String type;
        final String config;

        public Bridge(String type, String config) {
            this.type = type;
            this.config = config;
        }
    }
}
