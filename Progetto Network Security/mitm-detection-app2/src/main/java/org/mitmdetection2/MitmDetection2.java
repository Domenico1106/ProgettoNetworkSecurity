/*
 * Copyright 2014-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.mitmdetection2;



import com.google.common.collect.Sets;

import org.onlab.packet.ARP;
import org.onlab.packet.BasePacket;
import org.onlab.packet.DHCP;
import org.onlab.packet.DHCP6;
import org.onlab.packet.Data;
import org.onlab.packet.EthType;
import org.onlab.packet.Ethernet;
import org.onlab.packet.ICMP;
import org.onlab.packet.ICMP6;
import org.onlab.packet.IPacket;
import org.onlab.packet.IPv4;
import org.onlab.packet.IPv6;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip6Address;
import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;
import org.onlab.packet.UDP;
import org.onlab.packet.VlanId;
import org.onlab.packet.dhcp.Dhcp6ClientIdOption;
import org.onlab.packet.dhcp.Dhcp6IaAddressOption;
import org.onlab.packet.dhcp.Dhcp6IaNaOption;
import org.onlab.packet.dhcp.Dhcp6IaTaOption;
import org.onlab.packet.dhcp.Dhcp6RelayOption;
import org.onlab.packet.ipv6.IExtensionHeader;
import org.onlab.packet.ndp.NeighborAdvertisement;
import org.onlab.packet.ndp.NeighborSolicitation;
import org.onlab.packet.ndp.RouterAdvertisement;
import org.onlab.packet.ndp.RouterSolicitation;
import org.onlab.util.PredictableExecutor;
import org.onlab.util.Tools;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.HostLocation;
import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.config.basics.BasicHostConfig;
import org.onosproject.net.config.basics.HostLearningConfig;
import org.onosproject.net.config.basics.SubjectFactories;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.*;
import org.onosproject.net.flow.criteria.Criteria;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.host.*;
import org.onosproject.net.intf.InterfaceService;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.provider.AbstractProvider;
import org.onosproject.net.provider.ProviderId;
import org.onosproject.net.topology.Topology;
import org.onosproject.net.topology.TopologyService;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.stream.Stream;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static java.util.concurrent.Executors.newSingleThreadScheduledExecutor;
import static org.onlab.util.Tools.groupedThreads;
import static org.mitmdetection2.OsgiPropertyConstants.*;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * Provider which uses an OpenFlow controller to detect network end-station
 * hosts.
 */
@Component(immediate = true, service = HostProvider.class,
        property = {
                HOST_REMOVAL_ENABLED + ":Boolean=" + HOST_REMOVAL_ENABLED_DEFAULT,
                REQUEST_ARP + ":Boolean=" + REQUEST_ARP_DEFAULT,
                REQUEST_NDP + ":Boolean=" + REQUEST_NDP_DEFAULT,
                REQUEST_NDP_RS_RA + ":Boolean=" + REQUEST_NDP_RS_RA_DEFAULT,
                USE_DHCP + ":Boolean=" + USE_DHCP_DEFAULT,
                USE_DHCP6 + ":Boolean=" + USE_DHCP6_DEFAULT,
                REQUEST_INTERCEPTS_ENABLED + ":Boolean=" + REQUEST_INTERCEPTS_ENABLED_DEFAULT,
                MULTIHOMING_ENABLED + ":Boolean=" + MULTIHOMING_ENABLED_DEFAULT,
        })
public class MitmDetection2 extends AbstractProvider implements HostProvider {


    private final String CHIAVE_PUBBLICA_CONTROLLER = "3059301306072a8648ce3d020106082a8648ce3d0301070342000433ae2f4a166047facff332272a48f95f96beb95cea4d47f72bed72125274136369c6c8d354e9d89a4f1143323837a3ce3a5e5a186c226a0ef14ee7437fb2f087";
    private final String CHIAVE_PRIVATA_CONTROLLER = "3041020100301306072a8648ce3d020106082a8648ce3d03010704273025020101042002061c49b00604ac5d92d90d280e24d8646829ead22a657fd5686a146e1012c9";


    private static final String AES_ALGO = "AES/GCM/NoPadding";
    private static final byte[] ASSOCIATED_DATA = "probing".getBytes();
    private static final String PLAIN_TEXT = "pr0b1ng";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int GCM_IV_LENGTH = 12;

    private static final long INITIAL_DELAY = 10; 
    private static final long PERIOD = 20; 

    ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    Runnable hostProbing = new HostProbing();
    
    private Map<HostId, SecretKey> chiavi_segrete = new HashMap<>();

    private Map<HostId, Integer> status_hosts = new HashMap<>();

    private Map<HostLocation, HostId> snapshot = new HashMap<>();

    ArrayList<FlowRule> banFlowRules = new ArrayList<>();

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;


    private final Logger log = getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostProviderRegistry providerRegistry;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected TopologyService topologyService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostStore hostStore;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigRegistry registry;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected InterfaceService interfaceService;

    private final InternalHostProvider processor = new InternalHostProvider();
    private final DeviceListener deviceListener = new InternalDeviceListener();
    private final InternalConfigListener cfgListener = new InternalConfigListener();

    private ApplicationId appId;

    /** Enable host removal on port/device down events. */
    private boolean hostRemovalEnabled = true;

    /** Request ARP packets for neighbor discovery by the Host Location Provider; default is true. */
    private boolean requestArp = true;

    /** Requests IPv6 NDP Neighbor Solicitation and Advertisement by the Host Location Provider; default is false. */
    private boolean requestIpv6ND = false;

    /** Requests IPv6 NDP Router Solicitation and Advertisement by the Host Location Provider; default is false. */
    private boolean requestIpv6NdpRsRa = false;

    /** Use DHCP to update IP address of the host; default is false. */
    private boolean useDhcp = false;

    /** Use DHCPv6 to update IP address of the host; default is false. */
    private boolean useDhcp6 = false;

    /** Enable requesting packet intercepts. */
    private boolean requestInterceptsEnabled = true;

    /** Allow hosts to be multihomed. */
    private boolean multihomingEnabled = false;

    private HostProviderService providerService;

    ExecutorService deviceEventHandler;
    private ExecutorService probeEventHandler;
    // Packet workers - 0 will leverage available processors
    private static final int DEFAULT_THREADS = 0;
    private PredictableExecutor packetWorkers;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigService netcfgService;

    private ConfigFactory<ConnectPoint, HostLearningConfig> hostLearningConfig =
            new ConfigFactory<ConnectPoint, HostLearningConfig>(
                    SubjectFactories.CONNECT_POINT_SUBJECT_FACTORY,
                    HostLearningConfig.class, "hostLearning") {
                @Override
                public HostLearningConfig createConfig() {
                    return new HostLearningConfig();
                }
            };

    /**
     * Creates an OpenFlow host provider.
     */
    public MitmDetection2() {
        super(new ProviderId("of", "org.onosproject.provider.host"));
    }

    private void acquisisciSnapshot(){

        Map<HostLocation, HostId> newSnapshot = new HashMap<>();

        Iterable<Device> dispositivi = deviceService.getDevices();
        List<Device> listaDispositivi = new ArrayList<Device>();
        dispositivi.forEach(listaDispositivi::add);

        for(Device d : listaDispositivi){
            Set<Host> hosts = hostStore.getConnectedHosts(d.id());
            List<Host> listaHosts = new ArrayList<>(hosts);
            for(Host h : listaHosts){
                List<HostLocation> listaLocations = new ArrayList<>(getLocations(h.id()));
                for(HostLocation l : listaLocations){
                    if(!newSnapshot.containsKey(l)){
                        newSnapshot.put(l, h.id());
                    }else{
                        log.error("+++ERRORE+++ \nRilevati due Hosts aventi stessa Location.");
                        return;
                    }
                }
            }
        }
        this.snapshot = newSnapshot;
       
    }
    public void banna_attaccante(MacAddress macAddress, DeviceId deviceId) {

        // Inseriamo una regola di flusso per isolare l'Host Malevolo Permanentemente
        Criterion matchMac = Criteria.matchEthSrc(macAddress);
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .add(matchMac)
                .build();
        FlowRule flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .withSelector(selector)
                .withTreatment(DefaultTrafficTreatment.emptyTreatment())
                .withPriority(50000)
                .makePermanent()
                .fromApp(appId)
                .build();
        flowRuleService.applyFlowRules(flowRule);
        banFlowRules.add(flowRule);
        HostId hId = HostId.hostId(macAddress);
        status_hosts.remove(hId);
        chiavi_segrete.remove(hId);
    }

    private Set<HostLocation> getLocations(HostId hID) {
        Host host = hostService.getHost(hID);
        return host.locations();
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
        return data;
    }

   

    private void popolaMappaChiaviSegrete()throws Exception{

        HostId h1 = HostId.hostId("00:00:00:00:00:01/None");
        String chiavePubblicaH1 = "3059301306072a8648ce3d020106082a8648ce3d0301070342000485ad0eb6edaa7d7d1ce30a38319e9577c8c938519a565a5912037c2a782907fe1acf7fd1d7a80dc5e376817cf94ab2f0f2e9e79b574be956dea50b20a0729ee5";
        PrivateKey privateKeyController = convertiInPrivateKey(CHIAVE_PRIVATA_CONTROLLER);
        PublicKey pubblicaH1 = convertiInPublicKey(chiavePubblicaH1);
        SecretKey chiave_condivisa_h1_c = generaChiaveCondivisa(privateKeyController, pubblicaH1);
        this.chiavi_segrete.put(h1, chiave_condivisa_h1_c);
        this.status_hosts.put(h1, 0);

        HostId h2 = HostId.hostId("00:00:00:00:00:02/None");
        String chiavePubblicaH2 = "3059301306072a8648ce3d020106082a8648ce3d0301070342000498f2c8333abe9d85a1e57516e4459514280e60838f60449825650e4c951ea4cde0a8ba94d155007d90802da259b4a5aaac74cda9c1c7e9b2cfd84d801a908dfb";
        SecretKey chiave_condivisa_h2_c = generaChiaveCondivisa(convertiInPrivateKey(CHIAVE_PRIVATA_CONTROLLER), convertiInPublicKey(chiavePubblicaH2));
        this.chiavi_segrete.put(h2, chiave_condivisa_h2_c);
        this.status_hosts.put(h2, 0);

        HostId h3 = HostId.hostId("00:00:00:00:00:03/None");
        String chiavePubblicaH3 = "3059301306072a8648ce3d020106082a8648ce3d030107034200041009e90153e15fe741e749b65dd55dcb8d7159680dfe2cea489a5e5497e78bf18c944ec07ddd89eb41031642f38478cb077b7d7dfd5852d2451d95d495c8e0d1";
        SecretKey chiave_condivisa_h3_c = generaChiaveCondivisa(convertiInPrivateKey(CHIAVE_PRIVATA_CONTROLLER), convertiInPublicKey(chiavePubblicaH3));
        this.chiavi_segrete.put(h3, chiave_condivisa_h3_c);
        this.status_hosts.put(h3, 0);

        HostId h4 = HostId.hostId("00:00:00:00:00:04/None");
        String chiavePubblicaH4 = "3059301306072a8648ce3d020106082a8648ce3d030107034200043bb53d8481c35b9631d301f3c3f37e8310552e43f3ba17d4ea077ea310d19e60ac78298d055cd9dc1dc14192108b70c4ca7bbbe7cce3191bdaeeca1d9ae69d02";
        SecretKey chiave_condivisa_h4_c = generaChiaveCondivisa(convertiInPrivateKey(CHIAVE_PRIVATA_CONTROLLER), convertiInPublicKey(chiavePubblicaH4));
        this.chiavi_segrete.put(h4, chiave_condivisa_h4_c);
        this.status_hosts.put(h4, 0);
    }

    public static PublicKey convertiInPublicKey(String chiave) throws Exception {
        byte[] keyBytes = hexStringToByteArray(chiave);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(spec);
    }

    public static PrivateKey convertiInPrivateKey(String chiave) throws Exception {
        byte[] keyBytes = hexStringToByteArray(chiave);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePrivate(spec);
    }

    public static SecretKey generaChiaveCondivisa(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        byte [] chiaveCondivisa = keyAgreement.generateSecret();
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        chiaveCondivisa = hash.digest(chiaveCondivisa);
        return new SecretKeySpec(chiaveCondivisa, 0, chiaveCondivisa.length, AES_ALGO.substring(0, 3));
    }


    public static ByteBuffer encryptMessage(SecretKey sessionKey) throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        Cipher cipher = Cipher.getInstance(AES_ALGO);

        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey, parameterSpec);
        cipher.updateAAD(ASSOCIATED_DATA);
        byte[] ciphertext = cipher.doFinal(PLAIN_TEXT.getBytes());
        ByteBuffer payload = ByteBuffer.allocate(iv.length + ciphertext.length + 4);
        payload.putInt(iv.length);
        payload.put(iv);
        payload.put(ciphertext);
        
        return payload;
    }
    

    public static ByteBuffer decryptMessage(byte[] ciphertextWithIv, SecretKey sessionKey) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGO);
        byte[] iv = new byte[GCM_IV_LENGTH];
        System.arraycopy(ciphertextWithIv, 0, iv, 0, GCM_IV_LENGTH);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, sessionKey, parameterSpec);
        cipher.updateAAD(ASSOCIATED_DATA);
        byte[] ciphertext = new byte[ciphertextWithIv.length - GCM_IV_LENGTH];
        System.arraycopy(ciphertextWithIv, GCM_IV_LENGTH, ciphertext, 0, ciphertext.length);
        return ByteBuffer.wrap(cipher.doFinal(ciphertext));
    }


    @Activate
    public void activate(ComponentContext context) {
        cfgService.registerProperties(getClass());
        appId = coreService.registerApplication("org.mitmdetection2.app");
        deviceEventHandler = newSingleThreadScheduledExecutor(groupedThreads("onos/host-loc-provider",
                "device-event-handler", log));
        probeEventHandler = newSingleThreadScheduledExecutor(groupedThreads("onos/host-loc-provider",
                "probe-event-handler", log));
        packetWorkers = new PredictableExecutor(DEFAULT_THREADS, groupedThreads("onos/host-loc-provider",
                "packet-worker-%d", log));
        providerService = providerRegistry.register(this);


        packetService.addProcessor(processor, PacketProcessor.advisor(1));
        deviceService.addListener(deviceListener);
        registry.registerConfigFactory(hostLearningConfig);
        modified(context);
        netcfgService.addListener(cfgListener);

        log.info("Started with Application ID {}", appId.id());
        
        scheduler.scheduleAtFixedRate(hostProbing, INITIAL_DELAY, PERIOD, TimeUnit.SECONDS);
    }

    @Deactivate
    public void deactivate() {
        cfgService.unregisterProperties(getClass(), false);

        withdrawIntercepts();

        scheduler.shutdown();

        providerRegistry.unregister(this);
        packetService.removeProcessor(processor);
        deviceService.removeListener(deviceListener);
        deviceEventHandler.shutdown();
        probeEventHandler.shutdown();
        packetWorkers.shutdown();
        providerService = null;
        registry.unregisterConfigFactory(hostLearningConfig);
        netcfgService.removeListener(cfgListener);
        for (FlowRule flowRule : banFlowRules) {
            if(flowRule != null){
                flowRuleService.removeFlowRules(flowRule);
                banFlowRules.remove(flowRule);
            }
        }
        log.info("Stopped");
    }

    @Modified
    public void modified(ComponentContext context) {
        readComponentConfiguration(context);

        if (requestInterceptsEnabled) {
            requestIntercepts();
        } else {
            withdrawIntercepts();
        }
    }

    /**
     * Request packet intercepts.
     */
    private void requestIntercepts() {
        // Use ARP
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_ARP);
        if (requestArp) {
            packetService.requestPackets(selector.build(), PacketPriority.CONTROL, appId);
        } else {
            packetService.cancelPackets(selector.build(), PacketPriority.CONTROL, appId);
        }

        // Use IPv6 NDP Neighbor Solicitation and Advertisement
        selector.matchEthType(Ethernet.TYPE_IPV6)
                .matchIPProtocol(IPv6.PROTOCOL_ICMP6);
        if (requestIpv6ND) {
            selector.matchIcmpv6Type(ICMP6.NEIGHBOR_SOLICITATION);
            packetService.requestPackets(selector.build(), PacketPriority.CONTROL, appId);
            selector.matchIcmpv6Type(ICMP6.NEIGHBOR_ADVERTISEMENT);
            packetService.requestPackets(selector.build(), PacketPriority.CONTROL, appId);
        } else {
            selector.matchIcmpv6Type(ICMP6.NEIGHBOR_SOLICITATION);
            packetService.cancelPackets(selector.build(), PacketPriority.CONTROL, appId);
            selector.matchIcmpv6Type(ICMP6.NEIGHBOR_ADVERTISEMENT);
            packetService.cancelPackets(selector.build(), PacketPriority.CONTROL, appId);
        }

        // Use IPv6 NDP Router Solicitation and Advertisement
        if (requestIpv6NdpRsRa) {
            selector.matchIcmpv6Type(ICMP6.ROUTER_SOLICITATION);
            packetService.requestPackets(selector.build(), PacketPriority.CONTROL, appId);
            selector.matchIcmpv6Type(ICMP6.ROUTER_ADVERTISEMENT);
            packetService.requestPackets(selector.build(), PacketPriority.CONTROL, appId);
        } else {
            selector.matchIcmpv6Type(ICMP6.ROUTER_SOLICITATION);
            packetService.cancelPackets(selector.build(), PacketPriority.CONTROL, appId);
            selector.matchIcmpv6Type(ICMP6.ROUTER_ADVERTISEMENT);
            packetService.cancelPackets(selector.build(), PacketPriority.CONTROL, appId);
        }
    }

    /**
     * Withdraw packet intercepts.
     */
    private void withdrawIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.cancelPackets(selector.build(), PacketPriority.CONTROL, appId);

        // IPv6 Neighbor Solicitation packet.
        selector.matchEthType(Ethernet.TYPE_IPV6);
        selector.matchIPProtocol(IPv6.PROTOCOL_ICMP6);
        selector.matchIcmpv6Type(ICMP6.NEIGHBOR_SOLICITATION);
        packetService.cancelPackets(selector.build(), PacketPriority.CONTROL, appId);

        // IPv6 Neighbor Advertisement packet.
        selector.matchIcmpv6Type(ICMP6.NEIGHBOR_ADVERTISEMENT);
        packetService.cancelPackets(selector.build(), PacketPriority.CONTROL, appId);
    }

    /**
     * Extracts properties from the component configuration context.
     *
     * @param context the component context
     */
    private void readComponentConfiguration(ComponentContext context) {
        Dictionary<?, ?> properties = context.getProperties();
        Boolean flag;

        /*flag = Tools.isPropertyEnabled(properties, HOST_REMOVAL_ENABLED);
        if (flag == null) {
            log.info("Host removal on port/device down events is not configured, " +
                    "using current value of {}", hostRemovalEnabled);
        } else {
            hostRemovalEnabled = flag;
            log.info("Configured. Host removal on port/device down events is {}",
                    hostRemovalEnabled ? "enabled" : "disabled");
        }
        */
        hostRemovalEnabled = true;
            log.info("Configured. Host removal on port/device down events is {}",
                    hostRemovalEnabled ? "enabled" : "disabled");

        flag = Tools.isPropertyEnabled(properties, REQUEST_ARP);
        if (flag == null) {
            log.info("Using ARP is not configured, " +
                    "using current value of {}", requestArp);
        } else {
            requestArp = flag;
            log.info("Configured. Using ARP is {}",
                    requestArp ? "enabled" : "disabled");
        }

        flag = Tools.isPropertyEnabled(properties, REQUEST_NDP);
        if (flag == null) {
            log.info("Using IPv6 Neighbor Discovery is not configured, " +
                    "using current value of {}", requestIpv6ND);
        } else {
            requestIpv6ND = flag;
            log.info("Configured. Using IPv6 NDP Neighbor Solicitation and Advertisement is {}",
                    requestIpv6ND ? "enabled" : "disabled");
        }

        flag = Tools.isPropertyEnabled(properties, REQUEST_NDP_RS_RA);
        if (flag == null) {
            log.info("Using IPv6 Neighbor Discovery is not configured, " +
                    "using current value of {}", requestIpv6NdpRsRa);
        } else {
            requestIpv6NdpRsRa = flag;
            log.info("Configured. Using IPv6 NDP Router Solicitation and Advertisement is {}",
                    requestIpv6NdpRsRa ? "enabled" : "disabled");
        }

        flag = Tools.isPropertyEnabled(properties, USE_DHCP);
        if (flag == null) {
            log.info("Using DHCP is not configured, " +
                    "using current value of {}", useDhcp);
        } else {
            useDhcp = flag;
            log.info("Configured. Using DHCP is {}",
                    useDhcp ? "enabled" : "disabled");
        }

        flag = Tools.isPropertyEnabled(properties, USE_DHCP6);
        if (flag == null) {
            log.info("Using DHCP6 is not configured, " +
                    "using current value of {}", useDhcp6);
        } else {
            useDhcp6 = flag;
            log.info("Configured. Using DHCP6 is {}",
                    useDhcp6 ? "enabled" : "disabled");
        }

        flag = Tools.isPropertyEnabled(properties, REQUEST_INTERCEPTS_ENABLED);
        if (flag == null) {
            log.info("Request intercepts is not configured, " +
                    "using current value of {}", requestInterceptsEnabled);
        } else {
            requestInterceptsEnabled = flag;
            log.info("Configured. Request intercepts is {}",
                    requestInterceptsEnabled ? "enabled" : "disabled");
        }

        flag = Tools.isPropertyEnabled(properties, MULTIHOMING_ENABLED);
        if (flag == null) {
            log.info("Multihoming is not configured, " +
                    "using current value of {}", multihomingEnabled);
        } else {
            multihomingEnabled = flag;
            log.info("Configured. Multihoming is {}",
                    multihomingEnabled ? "enabled" : "disabled");
        }
    }

    @Override
    public void triggerProbe(Host host) {
        //log.info("Triggering probe on device {} ", host);

        // FIXME Disabling host probing for now, because sending packets from a
        // broadcast MAC address caused problems when two ONOS networks were
        // interconnected. Host probing should take into account the interface
        // configuration when determining which source address to use.

        //MastershipRole role = deviceService.getRole(host.location().deviceId());
        //if (role.equals(MastershipRole.MASTER)) {
        //    host.ipAddresses().forEach(ip -> {
        //        sendProbe(host, ip);
        //    });
        //} else {
        //    log.info("not the master, master will probe {}");
        //}
    }

    private class HostProbing implements Runnable {
        Boolean mappa_chiavi_popolata = false;
        @Override
        public void run() {
            Map<HostLocation, HostId> newSnapshot = snapshot;
            // Inviamo un Probe ad ogni Host e incrementiamo il loro contatore di status
            // Se il contatore arriva a 3, espelliamo l'host inattivo
            if(!newSnapshot.isEmpty()){

                if(!mappa_chiavi_popolata){
                    try {
                        popolaMappaChiaviSegrete();
                        mappa_chiavi_popolata = true;
                    }catch(Exception e) {
                        log.error("Errore nel popolamento della mappa delle chiavi segrete.");
                    }

                }
                
                for(HostLocation l : newSnapshot.keySet()){

                    // Il nat è fidato per definizione, non serve controllare
                    if(newSnapshot.get(l).equals(HostId.hostId("00:00:00:00:00:05/None"))){
                        continue;
                    }

                    // Assumo che l'host è caduto
                    if(status_hosts.get(newSnapshot.get(l)) == 3){
                        log.warn("L'Host {} risulta inattivo. Rimozione dell'Host effettuata.", newSnapshot.get(l));
                        hostStore.removeHost(newSnapshot.get(l));
                        acquisisciSnapshot();
                        status_hosts.remove(newSnapshot.get(l));
                        chiavi_segrete.remove(newSnapshot.get(l));
                        continue;
                    }
                    // L'host non ha ancora esaurito i suoi tentativi, invio il probing packet
                    sendProbe(hostService.getHost(newSnapshot.get(l)));
                    status_hosts.put(newSnapshot.get(l), status_hosts.get(newSnapshot.get(l))+1);

                }
            }
            
        }

        private void sendProbe(Host host) {
            try {
                Ethernet eth = new Ethernet();
                eth.setSourceMACAddress("02:42:ac:11:00:02").setDestinationMACAddress(host.mac()).setEtherType(Ethernet.TYPE_IPV4);
    
                IPv4 ipv4 = new IPv4();
                ipv4.setSourceAddress("172.17.0.2").setDestinationAddress(host.ipAddresses().iterator().next().getIp4Address().toInt())
                    .setProtocol(IPv4.PROTOCOL_ICMP);
    
                ICMP icmp = new ICMP();
                icmp.setIcmpType((byte) 0).setIcmpCode((byte) 0);
                
                SecretKey key = chiavi_segrete.get(host.id());
                ByteBuffer payload = encryptMessage(key);

                icmp.setPayload(new Data(payload.array()));
        
                ipv4.setPayload(icmp);
                eth.setPayload(ipv4);
    
                TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(host.location().port()).build();
                OutboundPacket packet = new DefaultOutboundPacket(host.location().deviceId(), treatment, ByteBuffer.wrap(eth.serialize()));
                packetService.emit(packet);
    
                log.info("Inviato Pacchetto di Probing all'host: {}", host.id());
                
    
            } catch (Exception e) {
                log.error("+++ERRORE+++ Errore nell'invio del Pacchetto di Probing all'host: {}", host.id());
            }
        }
    
    }


    // This method is using source ip as 0.0.0.0 , to receive the reply even from the sub net hosts.
    private Ethernet buildArpRequest(IpAddress targetIp, Host host) {
        return ARP.buildArpRequest(MacAddress.BROADCAST.toBytes(), Ip4Address.ZERO.toOctets(),
                MacAddress.BROADCAST.toBytes(), targetIp.toOctets(),
                MacAddress.BROADCAST.toBytes(), VlanId.NONE.toShort());
    }

    private class InternalHostProvider implements PacketProcessor {
        /**
         * Create or update host information.
         * Will not update IP if IP is null, all zero or self-assigned.
         *
         * @param hid       host ID
         * @param mac       source Mac address
         * @param vlan      VLAN ID
         * @param innerVlan inner VLAN ID
         * @param outerTpid outer TPID
         * @param hloc      host location
         * @param ip        source IP address or null if not updating
         */
        private void createOrUpdateHost(HostId hid, MacAddress mac, VlanId vlan,
                                        VlanId innerVlan, EthType outerTpid,
                                        HostLocation hloc, IpAddress ip) {
            log.debug("Creating Host {} based on Location {}", hid, hloc);
            Set<HostLocation> newLocations = Sets.newHashSet(hloc);

            if (multihomingEnabled) {
                Host existingHost = hostService.getHost(hid);
                if (existingHost != null) {
                    Set<HostLocation> prevLocations = existingHost.locations();

                    if (prevLocations.stream().noneMatch(loc -> loc.deviceId().equals(hloc.deviceId()))) {
                        // New location is on a device that we haven't seen before
                        // Could be a dual-home host.
                        newLocations.addAll(prevLocations);
                    } else {
                        // Move within the same switch
                        // Simply replace old location that is on the same device
                        prevLocations.stream().filter(loc -> !loc.deviceId().equals(hloc.deviceId()))
                                .forEach(newLocations::add);
                    }
                }
            }

            HostDescription desc = ip == null || ip.isZero() || ip.isSelfAssigned() ?
                    new DefaultHostDescription(mac, vlan, newLocations, Sets.newHashSet(),
                            innerVlan, outerTpid, false) :
                    new DefaultHostDescription(mac, vlan, newLocations, Sets.newHashSet(ip),
                            innerVlan, outerTpid, false);
            try {
                providerService.hostDetected(hid, desc, false);
            } catch (IllegalStateException e) {
                log.debug("Host {} suppressed", hid);
            }
            acquisisciSnapshot();
        }

        /**
         * Updates IP address for an existing host.
         *
         * @param hid host ID
         * @param ip IP address
         */
        private void updateHostIp(HostId hid, IpAddress ip) {
            Host host = hostService.getHost(hid);
            if (host == null) {
                log.warn("Fail to update IP for {}. Host does not exist", hid);
                return;
            }

            HostDescription desc = new DefaultHostDescription(hid.mac(), hid.vlanId(),
                    host.locations(), Sets.newHashSet(ip), false);
            try {
                providerService.hostDetected(hid, desc, false);
            } catch (IllegalStateException e) {
                log.debug("Host {} suppressed", hid);
            }
        }

        @Override
        public void process(PacketContext context) {
            // Verify valid context
            if (context == null) {
                return;
            }
            // Verify valid Ethernet packet
            Ethernet eth = context.inPacket().parsed();
            if (eth == null) {
                return;
            }

            //Inizio Controlli di Sicurezza
            
            MacAddress srcMac = eth.getSourceMAC();

            DeviceId deviceId = context.inPacket().receivedFrom().deviceId();
            PortNumber portNumber = context.inPacket().receivedFrom().port();
            String verifica = deviceId.toString() + "/" + portNumber.toString();

            Map<HostLocation, HostId> newSnapshot = new HashMap<>(snapshot);
            
            if (eth.getEtherType() == Ethernet.TYPE_ARP && !srcMac.toString().equals("00:00:00:00:00:05")){
                ARP arp = (ARP) eth.getPayload();
                IpAddress srcIp = IpAddress.valueOf(IpAddress.Version.INET,
                        arp.getSenderProtocolAddress());
                // mitigazione ARP
                for (HostLocation l : newSnapshot.keySet()){
                    if (verifica.equals(l.toString())){
                        Host host = hostService.getHost(newSnapshot.get(l));
                        if(!host.ipAddresses().isEmpty() && !host.ipAddresses().contains(srcIp)){
                            log.warn("Rilevato Pacchetto ARP Malformato. Pacchetto Scartato.");
                            context.block();
                            banna_attaccante(host.mac(), deviceId);
                            hostStore.removeHost(newSnapshot.get(l));
                            log.warn("Espulso Host Malevolo avente indirizzo MAC: {} sul Device: {}", host.mac(), deviceId);
                            newSnapshot.remove(l);
                            snapshot = newSnapshot;
                            return;                       
                        }
                    }
                }

            }
            
            if (eth.getEtherType() == Ethernet.TYPE_IPV4) {
                
                IPv4 ipv4 = (IPv4) eth.getPayload();
                IpAddress srcIp = IpAddress.valueOf(ipv4.getSourceAddress());
                IpAddress dstIp = IpAddress.valueOf(ipv4.getDestinationAddress());
                //mitigazione HTS Poisoning
                for (HostLocation l : newSnapshot.keySet()) {
                    if (verifica.equals(l.toString())) {

                        if (!srcMac.equals(newSnapshot.get(l).mac())) {
                            log.warn("Rilevato Pacchetto IPv4 Malformato. Pacchetto Scartato.");
                            context.block();
                            MacAddress mac_attaccante = newSnapshot.get(l).mac();
                            banna_attaccante(mac_attaccante, deviceId);
                            hostStore.removeHost(newSnapshot.get(l));
                            log.warn("Espulso Host Malevolo avente indirizzo MAC: {} sul Device: {}", mac_attaccante, deviceId);
                            newSnapshot.remove(l);
                            snapshot = newSnapshot;
                            return;                       
                        }
                        
                    }

                }

                if (ipv4.getProtocol() == IPv4.PROTOCOL_ICMP) {
                    
                    ICMP icmp = (ICMP) ipv4.getPayload();
                    if (icmp.getIcmpType() == ICMP.TYPE_ECHO_REPLY) {

                        // Ricezione Probing
                        HostId hostId = HostId.hostId(srcMac);
                        try {
                            byte[] payload = icmp.getPayload().serialize();
                            byte[] payloadRidotto = new byte[payload.length - 11];
                            System.arraycopy(payload, 11, payloadRidotto, 0, payloadRidotto.length);
                            byte[] check = new byte[7];
                            System.arraycopy(payload, 4, check, 0, 7);
                            String payload_string = new String(check, StandardCharsets.UTF_8);
                            if(payload_string.equals("PROBING")){

                                try{
                                    SecretKey key = chiavi_segrete.get(hostId);
                                    
                                    ByteBuffer decryptedPayload = decryptMessage(payloadRidotto, key);

                                    if(PLAIN_TEXT.equals(new String(decryptedPayload.array(), StandardCharsets.UTF_8))){
                                        log.info("Ricevuto Pacchetto di Probing da: {}", hostId);
                                        status_hosts.put(hostId, 0);
                                        context.block();
                                    }
                                    else if(status_hosts.get(hostId) < 3){
                                        context.block();
                                        log.warn("+++ATTENZIONE+++ Non è stata trovata una corrispondenza nel contenuto del payload ricevuto dall'host: {}", hostId);
                                    }
                                }catch (Exception e){
                                    context.block();
                                    log.error("Eccezione: ", e);
                                    log.error("+++ERRORE+++ Verifica di Validità del Probe non riuscita per l'host: {}", hostId);
                                }
                            }

                        } catch (Exception e) {
                            //Il pacchetto non era di probing, quindi verrà gestito da qualcun altro
                        }
                        
                         

                        
                    }
                }
                
            }
            //Fine Controlli di Sicurezza

            
            
            // Dispatch to a worker thread
            HostId hostId = HostId.hostId(eth.getSourceMAC(), VlanId.vlanId(eth.getVlanID()));
            packetWorkers.execute(() -> processPacketInternal(context), hostId.hashCode());
            
        }

        private void processPacketInternal(PacketContext context) {
            Ethernet eth = context.inPacket().parsed();

            MacAddress srcMac = eth.getSourceMAC();
            if (srcMac.isBroadcast() || srcMac.isMulticast()) {
                return;
            }

            VlanId vlan = VlanId.vlanId(eth.getVlanID());
            VlanId outerVlan = VlanId.vlanId(eth.getQinQVID());
            VlanId innerVlan = VlanId.NONE;
            EthType outerTpid = EthType.EtherType.UNKNOWN.ethType();
            // Set up values for double-tagged hosts
            if (outerVlan.toShort() != Ethernet.VLAN_UNTAGGED) {
                innerVlan = vlan;
                vlan = outerVlan;
                outerTpid = EthType.EtherType.lookup(eth.getQinQTPID()).ethType();
            }
            ConnectPoint heardOn = context.inPacket().receivedFrom();

            // If this arrived on control port, bail out.
            if (heardOn.port().isLogical()) {
                return;
            }

            // If this is not an edge port, bail out.
            Topology topology = topologyService.currentTopology();
            if (topologyService.isInfrastructure(topology, heardOn)) {
                return;
            }

            HostLocation hloc = new HostLocation(heardOn, System.currentTimeMillis());
            HostId hid = HostId.hostId(eth.getSourceMAC(), vlan);
            MacAddress destMac = eth.getDestinationMAC();

            // Ignore location probes
            if (multihomingEnabled && destMac.isOnos() && !MacAddress.NONE.equals(destMac)) {
                return;
            }

            HostLearningConfig cfg = netcfgService.getConfig(heardOn, HostLearningConfig.class);
            // if learning is disabled bail out.
            if ((cfg != null) && (!cfg.hostLearningEnabled())) {
                log.debug("Learning disabled for {}, abort.", heardOn);
                return;
            }

            // ARP: possible new hosts, update both location and IP
            if (eth.getEtherType() == Ethernet.TYPE_ARP) {
                ARP arp = (ARP) eth.getPayload();
                IpAddress ip = IpAddress.valueOf(IpAddress.Version.INET,
                        arp.getSenderProtocolAddress());
                createOrUpdateHost(hid, srcMac, vlan, innerVlan, outerTpid, hloc, ip);

                // IPv4: update location only
            } else if (eth.getEtherType() == Ethernet.TYPE_IPV4) {
                // Update host location
                createOrUpdateHost(hid, srcMac, vlan, innerVlan, outerTpid, hloc, null);
                if (useDhcp) {
                    DHCP dhcp = findDhcp(eth).orElse(null);
                    // DHCP ACK: additionally update IP of DHCP client
                    if (dhcp != null  && dhcp.getPacketType().equals(DHCP.MsgType.DHCPACK)) {
                        MacAddress hostMac = MacAddress.valueOf(dhcp.getClientHardwareAddress());
                        VlanId hostVlan = VlanId.vlanId(eth.getVlanID());
                        HostId hostId = HostId.hostId(hostMac, hostVlan);
                        updateHostIp(hostId, IpAddress.valueOf(dhcp.getYourIPAddress()));
                    }
                }
                // NeighborAdvertisement and NeighborSolicitation: possible
                // new hosts, update both location and IP.
                //
                // IPv6: update location only
            } else if (eth.getEtherType() == Ethernet.TYPE_IPV6) {
                IPv6 ipv6 = (IPv6) eth.getPayload();
                IpAddress ip = IpAddress.valueOf(IpAddress.Version.INET6,
                        ipv6.getSourceAddress());

                // skip extension headers
                IPacket pkt = ipv6;
                while (pkt.getPayload() != null &&
                        pkt.getPayload() instanceof IExtensionHeader) {
                    pkt = pkt.getPayload();
                }
                pkt = pkt.getPayload();

                // DHCPv6 protocol
                DHCP6 dhcp6 = findDhcp6(pkt).orElse(null);
                if (dhcp6 != null && useDhcp6) {
                    createOrUpdateHost(hid, srcMac, vlan, innerVlan, outerTpid, hloc, null);
                    handleDhcp6(dhcp6, vlan);
                    return;
                }

                if (pkt != null && pkt instanceof ICMP6) {
                    // Neighbor Discovery Protocol
                    pkt = pkt.getPayload();
                    if (pkt != null) {
                        if ((pkt instanceof RouterAdvertisement || pkt instanceof RouterSolicitation)) {
                            if (ip.isZero()) {
                                return;
                            }
                            // RouterSolicitation, RouterAdvertisement
                            createOrUpdateHost(hid, srcMac, vlan, innerVlan, outerTpid, hloc, ip);
                            return;
                        }
                        if (pkt instanceof NeighborSolicitation || pkt instanceof NeighborAdvertisement) {
                            // Duplicate Address Detection
                            if (ip.isZero()) {
                                return;
                            }
                            // NeighborSolicitation, NeighborAdvertisement
                            createOrUpdateHost(hid, srcMac, vlan, innerVlan, outerTpid, hloc, ip);

                            // Also learn from the target address of NeighborAdvertisement
                            if (pkt instanceof NeighborAdvertisement) {
                                NeighborAdvertisement na = (NeighborAdvertisement) pkt;
                                Ip6Address targetAddr = Ip6Address.valueOf(na.getTargetAddress());
                                createOrUpdateHost(hid, srcMac, vlan, innerVlan, outerTpid, hloc, targetAddr);
                            }
                            return;
                        }
                    }
                }

                // multicast, exclude DHCPv6
                if (eth.isMulticast() && dhcp6 == null) {
                    return;
                }

                // normal IPv6 packets
                createOrUpdateHost(hid, srcMac, vlan, innerVlan, outerTpid, hloc, null);
            }
        }

        /**
         * Handles DHCPv6 packet, if message type is ACK, update IP address
         * according to DHCPv6 payload (IA Address option).
         *
         * @param dhcp6 the DHCPv6 payload
         * @param vlanId the vlan of this packet
         */
        private void handleDhcp6(DHCP6 dhcp6, VlanId vlanId) {
            // extract the relay message if exist
            while (dhcp6 != null && DHCP6.RELAY_MSG_TYPES.contains(dhcp6.getMsgType())) {
                dhcp6 = dhcp6.getOptions().stream()
                        .filter(opt -> opt instanceof Dhcp6RelayOption)
                        .map(BasePacket::getPayload)
                        .map(pld -> (DHCP6) pld)
                        .findFirst()
                        .orElse(null);
            }

            if (dhcp6 == null) {
                // Can't find dhcp payload
                log.warn("Can't find dhcp payload from relay message");
                return;
            }

            if (dhcp6.getMsgType() != DHCP6.MsgType.REPLY.value()) {
                // Update IP address only when we received REPLY message
                return;
            }
            Optional<Dhcp6ClientIdOption> clientIdOption = dhcp6.getOptions()
                    .stream()
                    .filter(opt -> opt instanceof Dhcp6ClientIdOption)
                    .map(opt -> (Dhcp6ClientIdOption) opt)
                    .findFirst();

            if (!clientIdOption.isPresent()) {
                // invalid DHCPv6 option
                log.warn("Can't find client ID from DHCPv6 {}", dhcp6);
                return;
            }

            byte[] linkLayerAddr = clientIdOption.get().getDuid().getLinkLayerAddress();
            if (linkLayerAddr == null || linkLayerAddr.length != 6) {
                // No any mac address found
                log.warn("Can't find client mac from option {}", clientIdOption);
                return;
            }
            MacAddress clientMac = MacAddress.valueOf(linkLayerAddr);

            // Extract IPv6 address from IA NA ot IA TA option
            Optional<Dhcp6IaNaOption> iaNaOption = dhcp6.getOptions()
                    .stream()
                    .filter(opt -> opt instanceof Dhcp6IaNaOption)
                    .map(opt -> (Dhcp6IaNaOption) opt)
                    .findFirst();
            Optional<Dhcp6IaTaOption> iaTaOption = dhcp6.getOptions()
                    .stream()
                    .filter(opt -> opt instanceof Dhcp6IaTaOption)
                    .map(opt -> (Dhcp6IaTaOption) opt)
                    .findFirst();
            Optional<Dhcp6IaAddressOption> iaAddressOption;
            if (iaNaOption.isPresent()) {
                iaAddressOption = iaNaOption.get().getOptions().stream()
                        .filter(opt -> opt instanceof Dhcp6IaAddressOption)
                        .map(opt -> (Dhcp6IaAddressOption) opt)
                        .findFirst();
            } else if (iaTaOption.isPresent()) {
                iaAddressOption = iaTaOption.get().getOptions().stream()
                        .filter(opt -> opt instanceof Dhcp6IaAddressOption)
                        .map(opt -> (Dhcp6IaAddressOption) opt)
                        .findFirst();
            } else {
                iaAddressOption = Optional.empty();
            }
            if (iaAddressOption.isPresent()) {
                Ip6Address ip = iaAddressOption.get().getIp6Address();
                HostId hostId = HostId.hostId(clientMac, vlanId);
                updateHostIp(hostId, ip);
            } else {
                log.warn("Can't find IPv6 address from DHCPv6 {}", dhcp6);
            }
        }

        private Optional<DHCP> findDhcp(Ethernet eth) {
            IPacket pkt = eth.getPayload();
            return Stream.of(pkt)
                    .filter(Objects::nonNull)
                    .filter(p -> p instanceof IPv4)
                    .map(IPacket::getPayload)
                    .filter(Objects::nonNull)
                    .filter(p -> p instanceof UDP)
                    .map(IPacket::getPayload)
                    .filter(Objects::nonNull)
                    .filter(p -> p instanceof DHCP)
                    .map(p -> (DHCP) p)
                    .findFirst();
        }

        private Optional<DHCP6> findDhcp6(IPacket pkt) {
            return Stream.of(pkt)
                    .filter(Objects::nonNull)
                    .filter(p -> p instanceof UDP)
                    .map(IPacket::getPayload)
                    .filter(Objects::nonNull)
                    .filter(p -> p instanceof DHCP6)
                    .map(p -> (DHCP6) p)
                    .findFirst();
        }
    }

    // Auxiliary listener to device events.
    private class InternalDeviceListener implements DeviceListener {
        @Override
        public void event(DeviceEvent event) {
            deviceEventHandler.execute(() -> handleEvent(event));
        }

        private void handleEvent(DeviceEvent event) {
            Device device = event.subject();
            switch (event.type()) {
                case DEVICE_ADDED:
                    break;
                case DEVICE_AVAILABILITY_CHANGED:
                    if (hostRemovalEnabled && !deviceService.isAvailable(device.id())) {
                        processDeviceDown(device.id());
                    }
                    break;
                case DEVICE_SUSPENDED:
                case DEVICE_UPDATED:
                    // Nothing to do?
                    break;
                case DEVICE_REMOVED:
                    if (hostRemovalEnabled) {
                        processDeviceDown(device.id());
                    }
                    break;
                case PORT_ADDED:
                    acquisisciSnapshot();
                    break;
                case PORT_UPDATED:
                    if (hostRemovalEnabled && !event.port().isEnabled()) {
                        processPortDown(new ConnectPoint(device.id(), event.port().number()));
                        acquisisciSnapshot();
                    }
                    break;
                case PORT_REMOVED:
                    if (hostRemovalEnabled) {
                        processPortDown(new ConnectPoint(device.id(), event.port().number()));
                        acquisisciSnapshot();
                    }
                    break;
                default:
                    break;
            }
        }
    }

    /**
     * When a device goes down, update the location of affected hosts.
     *
     * @param deviceId the device that goes down
     */
    private void processDeviceDown(DeviceId deviceId) {
        hostService.getConnectedHosts(deviceId).forEach(affectedHost -> affectedHost.locations().stream()
                .filter(hostLocation -> hostLocation.deviceId().equals(deviceId))
                .forEach(affectedLocation ->
                        providerService.removeLocationFromHost(affectedHost.id(), affectedLocation))
        );
    }

    /**
     * When a port goes down, update the location of affected hosts.
     *
     * @param connectPoint the port that goes down
     */
    private void processPortDown(ConnectPoint connectPoint) {
        hostService.getConnectedHosts(connectPoint).forEach(affectedHost ->
                providerService.removeLocationFromHost(affectedHost.id(), new HostLocation(connectPoint, 0L))
        );
    }


    private class InternalConfigListener implements NetworkConfigListener {

        @Override
        public void event(NetworkConfigEvent event) {
            switch (event.type()) {
                case CONFIG_ADDED:
                case CONFIG_UPDATED:
                    log.debug("HostLearningConfig event of type  {}", event.type());
                    // if learning enabled do nothing
                    HostLearningConfig learningConfig = (HostLearningConfig) event.config().get();
                    if (learningConfig.hostLearningEnabled()) {
                        return;
                    }

                    // if host learning is disable remove this location from existing, learnt hosts
                    ConnectPoint connectPoint = learningConfig.subject();
                    Set<Host> connectedHosts = hostService.getConnectedHosts(connectPoint);
                    for (Host host : connectedHosts) {
                        BasicHostConfig hostConfig = netcfgService.getConfig(host.id(), BasicHostConfig.class);

                        if ((hostConfig == null) || (!hostConfig.locations().contains(connectPoint))) {
                            // timestamp shoud not matter for comparing HostLocation and ConnectPoint
                            providerService.removeLocationFromHost(host.id(), new HostLocation(connectPoint, 1));
                        }
                    }
                    break;
                case CONFIG_REMOVED:
                default:
                    break;
            }
        }

        @Override
        public boolean isRelevant(NetworkConfigEvent event) {
            if (!event.configClass().equals(HostLearningConfig.class)) {
                return false;
            }
            return true;
        }
    }
}