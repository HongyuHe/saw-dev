#include "ns3/boolean.h"
#include "ns3/command-line.h"
#include "ns3/config.h"
#include "ns3/double.h"
#include "ns3/enum.h"
#include "ns3/he-phy.h"
#include "ns3/internet-stack-helper.h"
#include "ns3/ipv4-address-helper.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/log.h"
#include "ns3/mobility-helper.h"
#include "ns3/multi-model-spectrum-channel.h"
#include "ns3/on-off-helper.h"
#include "ns3/packet-sink-helper.h"
#include "ns3/packet-sink.h"
#include "ns3/rng-seed-manager.h"
#include "ns3/spectrum-wifi-helper.h"
#include "ns3/ssid.h"
#include "ns3/string.h"
#include "ns3/udp-client-server-helper.h"
#include "ns3/uinteger.h"
#include "ns3/wifi-acknowledgment.h"
#include "ns3/yans-wifi-channel.h"
#include "ns3/yans-wifi-helper.h"
#include "ns3/trace-helper.h"
#include "ns3/wifi-module.h" 

#include <functional>
#include <numeric>
#include <fstream>


using namespace ns3;

NS_LOG_COMPONENT_DEFINE("wifi6-network");

int
main(int argc, char* argv[])
{
    bool enableUlOfdma{true};
    bool udp{false};
    bool downlink{false};
    bool useRts{false};
    bool useExtendedBlockAck{false};
    double simulationTime{10}; // seconds
    double distance{1.0};      //! Fixed in meters
    double frequency{5};       // whether 2.4, 5 or 6 GHz
    std::size_t clients{3};
    std::string dlAckSeqType = (enableUlOfdma)? 
        "MU-BAR" : "NO-OFDMA"; // Shouldn't matter to the attack, but mu-bar seems to be the best.
    bool enableBsrp{true};
    bool useCentral26TonesRus{false}; //! Having problems when enabling central subcarriers.
    int mcs{2}; // -1 indicates an unset value
    int totalChannelWidth = 20;
    int gi_nanosec = 3200;
    uint32_t payloadSize = (enableUlOfdma)? 700 :
        700; // must fit in the max TX duration when transmitting at MCS 0 over an RU of 26 tones
    std::string phyModel{"Yans"};
    double minExpectedThroughput{0};
    double maxExpectedThroughput{0};
    Time accessReqInterval{0};

    CommandLine cmd(__FILE__);
    cmd.AddValue("clients",
                 "Number of non-AP devices",
                 clients);
    cmd.AddValue("frequency",
                 "Whether working in the 2.4, 5 or 6 GHz band (other values gets rejected)",
                 frequency);
    cmd.AddValue("distance",
                 "Distance in meters between the station and the access point",
                 distance);
    cmd.AddValue("simulationTime", "Simulation time in seconds", simulationTime);
    cmd.AddValue("udp", "UDP if set to 1, TCP otherwise", udp);
    cmd.AddValue("downlink",
                 "Generate downlink flows if set to 1, uplink flows otherwise",
                 downlink);
    cmd.AddValue("useRts", "Enable/disable RTS/CTS", useRts);
    cmd.AddValue("useExtendedBlockAck", "Enable/disable use of extended BACK", useExtendedBlockAck);
    cmd.AddValue("nStations", "Number of non-AP HE stations", clients);
    //* ACK sequnce shouldn't matter for the attack.
    cmd.AddValue("dlAckType",
                 "Ack sequence type for DL OFDMA (NO-OFDMA, ACK-SU-FORMAT, MU-BAR, AGGR-MU-BAR)",
                 dlAckSeqType);
    cmd.AddValue("enableUlOfdma",
                 "Enable UL OFDMA (useful if DL OFDMA is enabled and TCP is used)",
                 enableUlOfdma);
    cmd.AddValue("enableBsrp",
                 "Enable BSRP (useful if DL and UL OFDMA are enabled and TCP is used)",
                 enableBsrp);
    cmd.AddValue(
        "muSchedAccessReqInterval",
        "Duration of the interval between two requests for channel access made by the MU scheduler",
        accessReqInterval);
    cmd.AddValue("mcs", "if set, limit testing to a specific MCS (0-11)", mcs);
    cmd.AddValue("payloadSize", "The application payload size in bytes", payloadSize);
    cmd.AddValue("phyModel",
                 "PHY model to use when OFDMA is disabled (Yans or Spectrum). If OFDMA is enabled "
                 "then Spectrum is automatically selected",
                 phyModel);
    cmd.AddValue("minExpectedThroughput",
                 "if set, simulation fails if the lowest throughput is below this value",
                 minExpectedThroughput);
    cmd.AddValue("maxExpectedThroughput",
                 "if set, simulation fails if the highest throughput is above this value",
                 maxExpectedThroughput);
    cmd.Parse(argc, argv);

    std::string tputFilePath = "scratch/attacks/data/rr_tputs_" + std::to_string(clients) + "ue.csv";
    std::ofstream tputFile(tputFilePath);
    if (!tputFile.is_open()) {
        std::cerr << "Failed to open the file: " << tputFilePath << std::endl;
        return 1;
    }
    // Write the header
    tputFile << "mcs,channel_mhz,gi_ns,tput_mbps,origin,n_clients" << std::endl;

    std::string schedFilePath = "scratch/attacks/data/rr_sched_" + std::to_string(clients) + "ue.csv";
    std::ofstream schedFile(schedFilePath);
    if (!schedFile.is_open()) {
        std::cerr << "Failed to open the file: " << schedFilePath << std::endl;
        return 1;
    }
    // Write the header
    schedFile << "time_milli,total,unsolicited,schedule1,candidates,schedule2" << std::endl;
    schedFile.close();
    
    std::cout << "\nOFDMA flag: " << enableUlOfdma << std::endl;

    if (enableUlOfdma) {
        useRts = true;
    }

    if (useRts)
    {
        Config::SetDefault("ns3::WifiRemoteStationManager::RtsCtsThreshold", StringValue("0"));
        Config::SetDefault("ns3::WifiDefaultProtectionManager::EnableMuRts", BooleanValue(true));
    }

    if (dlAckSeqType == "ACK-SU-FORMAT")
    {
        Config::SetDefault("ns3::WifiDefaultAckManager::DlMuAckSequenceType",
                           EnumValue(WifiAcknowledgment::DL_MU_BAR_BA_SEQUENCE));
    }
    else if (dlAckSeqType == "MU-BAR")
    {
        Config::SetDefault("ns3::WifiDefaultAckManager::DlMuAckSequenceType",
                           EnumValue(WifiAcknowledgment::DL_MU_TF_MU_BAR));
    }
    else if (dlAckSeqType == "AGGR-MU-BAR")
    {
        Config::SetDefault("ns3::WifiDefaultAckManager::DlMuAckSequenceType",
                           EnumValue(WifiAcknowledgment::DL_MU_AGGREGATE_TF));
    }
    else if (dlAckSeqType != "NO-OFDMA")
    {
        NS_ABORT_MSG("Invalid DL ack sequence type (must be NO-OFDMA, ACK-SU-FORMAT, MU-BAR or "
                     "AGGR-MU-BAR)");
    }

    if (phyModel != "Yans" && phyModel != "Spectrum")
    {
        NS_ABORT_MSG("Invalid PHY model (must be Yans or Spectrum)");
    }
    if (dlAckSeqType != "NO-OFDMA")
    {
        // SpectrumWifiPhy is required for OFDMA
        phyModel = "Spectrum";
    }


    double prevThroughput[12] = {0};

    // std::cout << "MCS value"
    //           << "\t\t"
    //           << "Channel width"
    //           << "\t\t"
    //           << "GI" // Guard interval.
    //           << "\t\t"
    //           << "Throughput" << '\n';
    int minMcs = 0;
    int maxMcs = 11;
    if (mcs >= 0 && mcs <= 11)
    {
        minMcs = mcs;
        maxMcs = mcs;
    }
    for (int mcs = minMcs; mcs <= maxMcs; mcs++)
    {
        uint8_t index = 0;
        double previous = 0;
        uint8_t maxChannelWidth = frequency == 2.4 ? 40 : 160;
        int channelWidth = 20;
        uint8_t nStations = 4;
        if (totalChannelWidth > 0) {
            maxChannelWidth = totalChannelWidth;
            channelWidth = totalChannelWidth;
            if (totalChannelWidth == 20) {
                nStations = 8+1;
                //! We have to take into account the central 26-tone RUs, even if they are not used.
                //! Otherwise, min(nStations, STAs) will be always less than the # of first-level RUs (26-tones),
                //! which will never be used in this case.
                // if (useCentral26TonesRus)
                //     nStations++;

            } else if (totalChannelWidth == 40) {
                nStations = 16+2;
                // if (useCentral26TonesRus)
                //     nStations += 2;
            } else if (totalChannelWidth >= 80) {
                nStations = 32+5;
                // if (useCentral26TonesRus)
                //     nStations += 5;
            }
        }

        while (channelWidth <= maxChannelWidth) // MHz
        {
            // for (int gi = 3200; gi >= 800;) // Nanoseconds
            for (int gi = gi_nanosec; gi >= gi_nanosec;) // Nanoseconds
            {
                if (!udp)
                {
                    Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(payloadSize));
                }

                NodeContainer wifiStaNodes;
                wifiStaNodes.Create(clients);
                NodeContainer wifiApNode;
                wifiApNode.Create(1);

                WifiMacHelper mac;
                WifiHelper wifi;
                std::string channelStr("{0, " + std::to_string(channelWidth) + ", ");
                StringValue ctrlRate;
                auto nonHtRefRateMbps = HePhy::GetNonHtReferenceRate(mcs) / 1e6;

                std::ostringstream ossDataMode;
                ossDataMode << "HeMcs" << mcs;

                if (frequency == 6)
                {
                    ctrlRate = StringValue(ossDataMode.str());
                    channelStr += "BAND_6GHZ, 0}";
                    Config::SetDefault("ns3::LogDistancePropagationLossModel::ReferenceLoss",
                                       DoubleValue(48));
                }
                else if (frequency == 5)
                {
                    std::ostringstream ossControlMode;
                    ossControlMode << "OfdmRate" << nonHtRefRateMbps << "Mbps";
                    ctrlRate = StringValue(ossControlMode.str());
                    channelStr += "BAND_5GHZ, 0}";
                }
                else if (frequency == 2.4)
                {
                    std::ostringstream ossControlMode;
                    ossControlMode << "ErpOfdmRate" << nonHtRefRateMbps << "Mbps";
                    ctrlRate = StringValue(ossControlMode.str());
                    channelStr += "BAND_2_4GHZ, 0}";
                    Config::SetDefault("ns3::LogDistancePropagationLossModel::ReferenceLoss",
                                       DoubleValue(40));
                }
                else
                {
                    std::cout << "Wrong frequency value!" << std::endl;
                    return 0;
                }

                wifi.SetStandard(WIFI_STANDARD_80211ax);
                Ssid ssid = Ssid("ns3-80211ax");

                wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                             "DataMode",
                                             StringValue(ossDataMode.str()),
                                             "ControlMode",
                                             ctrlRate);
                // Set guard interval and MPDU buffer size
                wifi.ConfigHeOptions("GuardInterval",
                                     TimeValue(NanoSeconds(gi)),
                                     "MpduBufferSize",
                                     UintegerValue(useExtendedBlockAck ? 256 : 64));

                NetDeviceContainer apDevice;
                NetDeviceContainer staDevices;
                if (phyModel == "Spectrum")
                {
                    Ptr<MultiModelSpectrumChannel> spectrumChannel =
                        CreateObject<MultiModelSpectrumChannel>();
                    Ptr<LogDistancePropagationLossModel> lossModel =
                        CreateObject<LogDistancePropagationLossModel>();

                    spectrumChannel->AddPropagationLossModel(lossModel);
                    
                    SpectrumWifiPhyHelper phy;
                    phy.SetPcapDataLinkType(WifiPhyHelper::DLT_IEEE802_11_RADIO);
                    phy.SetChannel(spectrumChannel);

                    mac.SetType("ns3::StaWifiMac", "Ssid", SsidValue(ssid),
                        "ActiveProbing", BooleanValue(false)
                        // "PsMode", StringValue("SLEEP")
                        // "QosSupported", BooleanValue(true),
                    );
                    phy.Set("ChannelSettings", StringValue(channelStr));
                    staDevices = wifi.Install(phy, mac, wifiStaNodes);

                    if (dlAckSeqType != "NO-OFDMA")
                    {
                        //* Configure the WiFi 6 scheduler.
                        mac.SetMultiUserScheduler("ns3::RrMultiUserScheduler",
                                                  "EnableUlOfdma",
                                                  BooleanValue(enableUlOfdma),
                                                  "EnableBsrp",
                                                  BooleanValue(enableBsrp),
                                                  "AccessReqInterval",
                                                  TimeValue(accessReqInterval),
                                                  "UseCentral26TonesRus",
                                                  BooleanValue(useCentral26TonesRus)
                                                  ,"NStations",
                                                  UintegerValue(nStations)
                                                  );
                    }
                    mac.SetType("ns3::ApWifiMac",
                                "EnableBeaconJitter",
                                BooleanValue(false),
                                "Ssid",
                                SsidValue(ssid));
                    apDevice = wifi.Install(phy, mac, wifiApNode);

                    // phy.EnablePcap("attacker", staDevices.Get(0), true);
                    phy.EnablePcap("ap.pcap", apDevice.Get(0), true, true);
                    // phy.EnablePcapAll("all", true);
                    // AsciiTraceHelper ascii;
                    // phy.EnableAsciiAll(ascii.CreateFileStream("wifi-trace.tr"));
                    // LogComponentEnable("WifiMac", LOG_LEVEL_ALL);
                    // LogComponentEnable("OnOffApplication", LOG_LEVEL_ALL);

                    //! Doesn't work w/o adjusting associated link IDs 
                    // //* Change  MAC addresses for clients
                    // for (uint32_t i = 0; i < clients; ++i) {
                    //     std::string macAddress = "00:00:00:00:00:C" + std::to_string(i+1);
                    //     // wifiStaNodes.Get(i)->GetDevice(0)->GetObject<WifiNetDevice>()->SetAddress(Mac48Address(macAddress.c_str()));
                    //     Ptr<NetDevice> dev = staDevices.Get(i);
                    //     Ptr<WifiNetDevice> wifiDev = dev->GetObject<WifiNetDevice>();
                    //     wifiDev->SetAddress(Mac48Address(macAddress.c_str()));
                    // }
                    // //* Change MAC address for the AP
                    // wifiApNode.Get(0)->GetObject<Node>()->GetDevice(0)
                    //     ->GetObject<WifiNetDevice>()->SetAddress(Mac48Address("00:00:00:00:00:AA"));
                    // Ptr<NetDevice> dev = apDevice.Get(0);
                    // Ptr<WifiNetDevice> wifiDev = dev->GetObject<WifiNetDevice>();
                    // wifiDev->SetAddress(Mac48Address("00:00:00:00:00:0A"));
                }
                else
                {
                    // //* Disable frame aggregation.
                    // Config::SetDefault("ns3::WifiMac::BE_MaxAmpduSize", UintegerValue(0));
                    YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
                    YansWifiPhyHelper phy;
                    phy.SetPcapDataLinkType(WifiPhyHelper::DLT_IEEE802_11_RADIO);
                    phy.SetChannel(channel.Create());


                    mac.SetType("ns3::StaWifiMac", "Ssid", SsidValue(ssid)
                        // "ActiveProbing", BooleanValue(false),
                        // "QosSupported", BooleanValue(true),
                    );
                    phy.Set("ChannelSettings", StringValue(channelStr));
                    staDevices = wifi.Install(phy, mac, wifiStaNodes);

                    mac.SetType("ns3::ApWifiMac",
                                "EnableBeaconJitter",
                                BooleanValue(false),
                                "Ssid",
                                SsidValue(ssid));
                    apDevice = wifi.Install(phy, mac, wifiApNode);
                    
                    // phy.EnablePcap("ap.pcap", staDevices.Get(0), true, true);
                    phy.EnablePcap("ap.pcap", apDevice.Get(0), true, true);
                    // phy.EnablePcapAll("all", true);
                    // AsciiTraceHelper ascii;
                    // phy.EnableAsciiAll(ascii.CreateFileStream("wifi-trace.tr"));
                    // LogComponentEnable("WifiMac", LOG_LEVEL_ALL);
                    // LogComponentEnable("OnOffApplication", LOG_LEVEL_ALL);
                }

                RngSeedManager::SetSeed(1);
                RngSeedManager::SetRun(1);
                int64_t streamNumber = 42;
                streamNumber += wifi.AssignStreams(apDevice, streamNumber);
                streamNumber += wifi.AssignStreams(staDevices, streamNumber);

                // Mobility:
                //* Set the position of the AP at (0,0,0)
                MobilityHelper mobilityAp;
                Ptr<ListPositionAllocator> positionAllocAp = CreateObject<ListPositionAllocator>();
                positionAllocAp->Add(Vector(0.0, 0.0, 0.0)); // Position of the AP
                mobilityAp.SetPositionAllocator(positionAllocAp);
                mobilityAp.SetMobilityModel("ns3::ConstantPositionMobilityModel");
                mobilityAp.Install(wifiApNode);

                //* Set the position of each client device at (distance, 0, 0)
                MobilityHelper mobilitySta;
                Ptr<ListPositionAllocator> positionAllocSta = CreateObject<ListPositionAllocator>();
                for (uint32_t i = 0; i < clients; ++i)
                {
                    positionAllocSta->Add(Vector(distance, 0.0, 0.0)); // Position each client at (distance, 0, 0)
                }
                mobilitySta.SetPositionAllocator(positionAllocSta);
                mobilitySta.SetMobilityModel("ns3::ConstantPositionMobilityModel");
                mobilitySta.Install(wifiStaNodes);

                /* Internet stack*/
                InternetStackHelper stack;
                stack.Install(wifiApNode);
                stack.Install(wifiStaNodes);

                Ipv4AddressHelper address;
                address.SetBase("10.0.0.0", "255.255.255.0");
                // * The 1st client is 10.0.0.1
                Ipv4InterfaceContainer staNodeInterfaces = address.Assign(staDevices);
                Ipv4InterfaceContainer apNodeInterface = address.Assign(apDevice);

                //* Manually set the AP node's IP address to 10.0.0.254
                Ptr<Ipv4> ipv4 = wifiApNode.Get(0)->GetObject<Ipv4>();
                int32_t interfaceIndex = ipv4->GetInterfaceForDevice(apDevice.Get(0));
                ipv4->RemoveAddress(interfaceIndex, 0);  // Remove the assigned IP
                ipv4->AddAddress(interfaceIndex, Ipv4InterfaceAddress("10.0.0.254", "255.255.255.0"));
                ipv4->SetMetric(interfaceIndex, 1);  // Optional: set the metric if needed
                ipv4->SetUp(interfaceIndex);

                /* Setting applications */
                // ApplicationContainer serverApp;
                auto serverNodes = downlink ? std::ref(wifiStaNodes) : std::ref(wifiApNode);
                
                Ipv4InterfaceContainer serverInterfaces;
                NodeContainer clientNodes;
                for (std::size_t i = 0; i < clients; i++)
                {
                    if (downlink) {
                        serverInterfaces.Add(staNodeInterfaces.Get(i));
                        clientNodes.Add(wifiApNode.Get(0));
                    } else {
                        // Directly use the manually assigned AP address
                        serverInterfaces.Add(apNodeInterface.Get(0));
                        clientNodes.Add(wifiStaNodes.Get(i));
                    }
                }
                // std::cout << "Total clients: " << clientNodes.GetN() << std::endl;
                // std::cout << "Total servers: " << serverNodes.() << std::endl;

                std::vector<ApplicationContainer> serverApps(clients); // Store each server app for each client
                ApplicationContainer serverApp;
                std::cout << "MCS value"
                    << "\t"
                    << "Channel width"
                    << "\t"
                    << "GI" // Guard interval.
                    << "\t\t"
                    << "Throughput" 
                    << "\t\n";

                if (udp)
                {
                    // UDP flow
                    uint16_t port = 9;
                    UdpServerHelper server(port);
                    // * Install one sink for all clients in case of UDP for now.
                    serverApps[0] = server.Install(serverNodes.get());
                    serverApps[0].Start(Seconds(0.0));
                    serverApps[0].Stop(Seconds(simulationTime + 1));

                    for (std::size_t i = 0; i < clients; i++)
                    {
                        UdpClientHelper client(serverInterfaces.GetAddress(i), port);
                        client.SetAttribute("MaxPackets", UintegerValue(4294967295U));
                        client.SetAttribute("Interval", TimeValue(Time("0.00001"))); // packets/s
                        client.SetAttribute("PacketSize", UintegerValue(payloadSize));
                        ApplicationContainer clientApp = client.Install(clientNodes.Get(i));
                        clientApp.Start(Seconds(1.0));
                        clientApp.Stop(Seconds(simulationTime + 1));
                    }
                }
                else
                {   
                    // std::cout << "Setting up AP: " << apNodeInterface.GetAddress(0) << std::endl;
                    // uint16_t port = 50000;
                    // Address localAddress(InetSocketAddress(Ipv4Address::GetAny(), port));
                    // PacketSinkHelper packetSinkHelper("ns3::TcpSocketFactory", localAddress);
                    // serverApp = packetSinkHelper.Install(serverNodes.get());
                    // serverApp.Start(Seconds(0.0));
                    // serverApp.Stop(Seconds(simulationTime + 1));

                    //* TCP flows
                    std::vector<uint16_t> ports(clients);
                    for (std::size_t i = 0; i < clients; i++) {
                        //* Assign a unique port to each client on the AP
                        ports[i] = 50000 + i;
                        Address localAddress(InetSocketAddress(Ipv4Address::GetAny(), ports[i]));
                        PacketSinkHelper packetSinkHelper("ns3::TcpSocketFactory", localAddress);
                        //* Install a PacketSink on the server for each unique port
                        serverApps[i] = packetSinkHelper.Install(serverNodes.get());
                        serverApps[i].Start(Seconds(0.0));
                        serverApps[i].Stop(Seconds(simulationTime + 1));

                        //* Client setup
                        std::cout << "Setting up Client[" << i << "]: " << staNodeInterfaces.GetAddress(i) << std::endl;
                        OnOffHelper onoff("ns3::TcpSocketFactory", Ipv4Address::GetAny());
                        std::string onTimeType = "ns3::ExponentialRandomVariable[Mean=0.5]";
                        std::string offTimeType = "ns3::ExponentialRandomVariable[Mean=0.5]";
                        if (i == 0) {
                            onTimeType = "ns3::ConstantRandomVariable[Constant=1]";
                            offTimeType = "ns3::ConstantRandomVariable[Constant=0]";
                        } 
                        // //* Each STA can have different OnTime/OffTime patterns
                        // if (i == 0) {
                        //     onTimeType = "ns3::ConstantRandomVariable[Constant=0.5]";
                        //     offTimeType = "ns3::ConstantRandomVariable[Constant=0.5]";
                        // } else if (i == 1) {
                        //     onTimeType = "ns3::UniformRandomVariable[Min=0.1|Max=1.0]";
                        //     offTimeType = "ns3::UniformRandomVariable[Min=0.5|Max=2.0]";
                        // } else if (i == 2) {
                        //     onTimeType = "ns3::ExponentialRandomVariable[Mean=2]";
                        //     offTimeType = "ns3::ExponentialRandomVariable[Mean=0.5]";
                        // } else {
                        //     //* Always on.
                        //     onTimeType = "ns3::ConstantRandomVariable[Constant=1]";
                        //     offTimeType = "ns3::ConstantRandomVariable[Constant=0]";
                            
                        // }
                        onoff.SetAttribute("OnTime", StringValue(onTimeType));
                        onoff.SetAttribute("OffTime", StringValue(offTimeType));
                        onoff.SetAttribute("PacketSize", UintegerValue(payloadSize));
                        //* 20MHz channel with 1-8 STAs (3.2us GI, MCS 2)
                        //*  26-tone: 2.3Mbps; 52-tone: 4.5Mbps, 106-tone: 9.6Mbps, 242-tone: 21.9Mbps
                        std::string dataRate = "2Mb/s";
                        // if (i == 0) {
                        //     dataRate = "6Mb/s";
                        // }
                        onoff.SetAttribute("DataRate", DataRateValue(dataRate));
                        //* Maching the ports assigned on the server slide
                        // AddressValue remoteAddress(InetSocketAddress(serverInterfaces.GetAddress(0), port));
                        AddressValue remoteAddress(InetSocketAddress(serverInterfaces.GetAddress(0), ports[i]));
                        onoff.SetAttribute("Remote", remoteAddress);
                        
                        ApplicationContainer clientApp = onoff.Install(clientNodes.Get(i));
                        clientApp.Start(Seconds(0.5));
                        clientApp.Stop(Seconds(simulationTime + 1));
                    }

                    // // TCP flow
                    // uint16_t port = 50000;
                    // Address localAddress(InetSocketAddress(Ipv4Address::GetAny(), port));
                    // PacketSinkHelper packetSinkHelper("ns3::TcpSocketFactory", localAddress);
                    // serverApp = packetSinkHelper.Install(serverNodes.get());
                    // serverApp.Start(Seconds(0.0));
                    // serverApp.Stop(Seconds(simulationTime + 1));

                    // for (std::size_t i = 0; i < nStations; i++)
                    // {
                    //     OnOffHelper onoff("ns3::TcpSocketFactory", Ipv4Address::GetAny());
                    //     onoff.SetAttribute("OnTime",
                    //                        StringValue("ns3::ConstantRandomVariable[Constant=1]"));
                    //     onoff.SetAttribute("OffTime",
                    //                        StringValue("ns3::ConstantRandomVariable[Constant=0]"));
                    //     onoff.SetAttribute("PacketSize", UintegerValue(payloadSize));
                    //     std::string dataRate = "1GB/s";
                    //     onoff.SetAttribute("DataRate", DataRateValue(dataRate));// DataRateValue(1000000000)); // bit/s (125MB/s)
                    //     // onoff.SetAttribute("DataRate", DataRateValue(1000000000)); // bit/s (125MB/s)
                    //     AddressValue remoteAddress(
                    //         InetSocketAddress(serverInterfaces.GetAddress(i), port));
                    //     onoff.SetAttribute("Remote", remoteAddress);
                    //     ApplicationContainer clientApp = onoff.Install(clientNodes.Get(i));
                    //     clientApp.Start(Seconds(1.0));
                    //     clientApp.Stop(Seconds(simulationTime + 1));
                    // }
                }

                Simulator::Schedule(Seconds(0), &Ipv4GlobalRoutingHelper::PopulateRoutingTables);
                Simulator::Stop(Seconds(simulationTime + 1));
                Simulator::Run();

                uint64_t totalRxBytes = 0;
                if (udp)
                {
                    for (uint32_t i = 0; i < serverApps[0].GetN(); i++)
                    {
                        totalRxBytes +=
                            payloadSize * DynamicCast<UdpServer>(serverApps[0].Get(i))->GetReceived();
                    }
                }
                else
                {
                    //* Calculate individual uplink throughput for each client
                    std::vector<uint64_t> rxBytesPerClient(clients, 0); // Track received bytes for each client
                    std::vector<double> tputPerClient(clients, 0); // Track received bytes for each client
                    for (std::size_t i = 0; i < clients; i++) {
                        // //! UL: Assuming a single AP connected to multiple UEs.
                        Ptr<PacketSink> sink = DynamicCast<PacketSink>(serverApps[i].Get(0));
                        if (sink) {
                            rxBytesPerClient[i] = sink->GetTotalRx();
                            tputPerClient[i] = (rxBytesPerClient[i] * 8) / (simulationTime * 1000000.0); // Mbit/s
                            std::cout << mcs << "\t\t" << channelWidth << " MHz\t\t" << gi << " ns\t\t"
                                      << tputPerClient[i] << " Mbit/s\t" << "(Client[" << i << "])" << std::endl;
                            
                            tputFile << mcs << "," 
                                << channelWidth << "," 
                                << gi << "," 
                                << tputPerClient[i] << "," 
                                << "client" << i + 1 << "," 
                                << clients << std::endl;
                        }
                        for (uint32_t i = 0; i < serverApp.GetN(); i++)
                        {
                            rxBytesPerClient[i] += DynamicCast<PacketSink>(serverApp.Get(i))->GetTotalRx();
                        }
                    }
                    totalRxBytes = std::accumulate(rxBytesPerClient.begin(), rxBytesPerClient.end(), 0);
                }
                double throughput = (totalRxBytes * 8) / (simulationTime * 1000000.0); // Mbit/s

                Simulator::Destroy();

                std::cout << mcs << "\t\t" << channelWidth << " MHz\t\t" << gi << " ns\t\t"
                          << throughput << " Mbit/s\t" << "(Total)\n" << std::endl;

                // When multiple stations are used, there are chances that association requests
                // collide and hence the throughput may be lower than expected. Therefore, we relax
                // the check that the throughput cannot decrease by introducing a scaling factor (or
                // tolerance)
                double tolerance = 0.10;
                // test first element
                if (mcs == 0 && channelWidth == 20 && gi == 3200)
                {
                    if (throughput * (1 + tolerance) < minExpectedThroughput)
                    {
                        NS_LOG_ERROR("Obtained throughput " << throughput << " is not expected!");
                        exit(1);
                    }
                }
                // test last element
                if (mcs == 11 && channelWidth == 160 && gi == 800)
                {
                    if (maxExpectedThroughput > 0 &&
                        throughput > maxExpectedThroughput * (1 + tolerance))
                    {
                        NS_LOG_ERROR("Obtained throughput " << throughput << " is not expected!");
                        exit(1);
                    }
                }
                // Skip comparisons with previous cases if more than one stations are present
                // because, e.g., random collisions in the establishment of Block Ack agreements
                // have an impact on throughput
                if (clients == 1)
                {
                    // test previous throughput is smaller (for the same mcs)
                    if (throughput * (1 + tolerance) > previous)
                    {
                        previous = throughput;
                    }
                    else if (throughput > 0)
                    {
                        NS_LOG_ERROR("Obtained throughput " << throughput << " is not expected!");
                        exit(1);
                    }
                    // test previous throughput is smaller (for the same channel width and GI)
                    if (throughput * (1 + tolerance) > prevThroughput[index])
                    {
                        prevThroughput[index] = throughput;
                    }
                    else if (throughput > 0)
                    {
                        NS_LOG_ERROR("Obtained throughput " << throughput << " is not expected!");
                        exit(1);
                    }
                }
                index++;
                gi /= 2;
            }
            channelWidth *= 2;
        }
    }
    // Close the file
    tputFile.close();
    std::cout << "Data has been written to " << tputFilePath << "." << std::endl;
    return 0;
}
