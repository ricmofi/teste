/*Para demonstrar a estimativa precisa do protocolo LLTP-
QoS, inicialmente a simulação é realizada de acordo com o modelo
de rede proposto 2m x 2m, juntamente com os 20 nós de sensores
implantados aleatoriamente com faixa de transmissão de 50 cm.*/

/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2011 University of Kansas
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Justin Rohrer <rohrej@ittc.ku.edu>
 *
 * James P.G. Sterbenz <jpgs@ittc.ku.edu>, director
 * ResiliNets Research Group  http://wiki.ittc.ku.edu/resilinets
 * Information and Telecommunication Technology Center (ITTC)
 * and Department of Electrical Engineering and Computer Science
 * The University of Kansas Lawrence, KS USA.
 *
 * Work supported in part by NSF FIND (Future Internet Design) Program
 * under grant CNS-0626918 (Postmodern Internet Architecture),
 * NSF grant CNS-1050226 (Multilayer Network Resilience Analysis and Experimentation on GENI),
 * US Department of Defense (DoD), and ITTC at The University of Kansas.
 */

/*
 * This example program allows one to run ns-3 DSDV, mt_aodv, or OLSR under
 * a typical random waypoint mobility model.
 *
 * By default, the simulation runs for 200 simulated seconds, of which
 * the first 50 are used for start-up time.  The number of nodes is 50.
 * Nodes move according to RandomWaypointMobilityModel with a speed of
 * 20 m/s and no pause time within a 300x1500 m xregion.  The WiFi is
 * in ad hoc mode with a 2 Mb/s rate (802.11b) and a Friis loss model.
 * The transmit power is set to 7.5 dBm.
 *
 * It is possible to change the mobility and density of the network by
 * directly modifying the speed and the number of nodes.  It is also
 * possible to change the characteristics of the network by changing
 * the transmit power (as power increases, the impact of mobility
 * decreases and the effective density increases).
 *
 * By default, OLSR is used, but specifying a value of 2 for the protocol
 * will cause mt_aodv to be used, and specifying a value of 3 will cause
 * DSDV to be used.
 *
 * By default, there are 10 source/sink data pairs sending UDP data
 * at an application rate of 2.048 Kb/s each.    This is typically done
 * at a rate of 4 64-byte packets per second.  Application data is
 * started at a random time between 50 and 51 seconds and continues
 * to the end of the simulation.
 *
 * The program outputs a few items:
 * - packet receptions are notified to stdout such as:
 *   <timestamp> <node-id> received one packet from <src-address>
 * - each second, the data reception statistics are tabulated and output
 *   to a comma-separated value (csv) file
 * - some tracing and flow monitor configuration that used to work is
 *   left commented inline in the program
 */

#include <fstream>
#include <iostream>
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/aodv-module.h"
#include "ns3/mt_aodv-module.h"
#include "ns3/mt_aodv-rtable.h"
#include "ns3/olsr-module.h"
#include "ns3/dsdv-module.h"
#include "ns3/dsr-module.h"
#include "ns3/applications-module.h"
#include "ns3/yans-wifi-helper.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/lr-wpan-helper.h"
#include "ns3/netanim-module.h"
#include "ctime"

using namespace ns3;
using namespace dsr;

NS_LOG_COMPONENT_DEFINE ("manet-routing-compare");

class WifiPhyStats : public Object
 {
 public:
   static TypeId GetTypeId (void);
 
   WifiPhyStats ();
 
   virtual ~WifiPhyStats ();
 
   uint32_t GetTxBytes ();

   void WifiPhyTxBeginTrace (std::string context, Ptr<const Packet> p, double txPowerW);
 
   void PhyTxTrace (std::string context, Ptr<const Packet> packet, WifiMode mode, WifiPreamble preamble, uint8_t txPower);
 
   void PhyTxDrop (std::string context, Ptr<const Packet> packet);

   void PhyRxDrop (std::string context, Ptr<const Packet> packet, WifiPhyRxfailureReason reason);
 
 private:
   uint32_t m_phyTxPkts; 
   uint32_t m_phyTxBytes; 
 };
 
 NS_OBJECT_ENSURE_REGISTERED (WifiPhyStats);
 
 TypeId
 WifiPhyStats::GetTypeId (void)
 {
   static TypeId tid = TypeId ("ns3::WifiPhyStats")
     .SetParent<Object> ()
     .AddConstructor<WifiPhyStats> ();
   return tid;
 }
 
 WifiPhyStats::WifiPhyStats ()
   : m_phyTxPkts (0),
     m_phyTxBytes (0)
 {
 }
 
 WifiPhyStats::~WifiPhyStats ()
 {
 }

 void 
  WifiPhyStats::WifiPhyTxBeginTrace (std::string context, Ptr<const Packet> p, double txPowerW)
{
  NS_LOG_FUNCTION (this);
  NS_LOG_UNCOND ("WifiPhyTxBeginTrace");
}
 
 void
 WifiPhyStats::PhyTxTrace (std::string context, Ptr<const Packet> packet, WifiMode mode, WifiPreamble preamble, uint8_t txPower)
 {
   NS_LOG_FUNCTION (this << context << packet << "PHYTX mode=" << mode );
   ++m_phyTxPkts;
   uint32_t pktSize = packet->GetSize ();
   m_phyTxBytes += pktSize;
 
   NS_LOG_UNCOND ("Received PHY size=" << pktSize);
 }
 
 void
 WifiPhyStats::PhyTxDrop (std::string context, Ptr<const Packet> packet)

 { 
   NS_LOG_UNCOND (Simulator::Now()<<"PHY Tx Drop");
 }
 
 
 uint32_t
 WifiPhyStats::GetTxBytes ()
 {
   return m_phyTxBytes;
 }
void
WifiPhyStats::PhyRxDrop (std::string context, Ptr<const Packet> packet, WifiPhyRxfailureReason reason)
{
  NS_LOG_UNCOND (Simulator::Now()<<"PHY Rx Drop");NS_LOG_UNCOND("this " << reason);
}

                                            
class RoutingExperiment
{
public:
  RoutingExperiment ();
  void Run (int nSinks, double txp, std::string CSVfileName);
  //static void SetMACParam (ns3::NetDeviceContainer & devices,
  //                                 int slotDistance);
  std::string CommandSetup (int argc, char **argv);
  
  
private:
  Ptr<Socket> SetupPacketReceive (Ipv4Address addr, Ptr<Node> node);
  void ReceivePacket (Ptr<Socket> socket);
  void CheckThroughput ();

  uint32_t port;
  uint32_t bytesTotal;
  uint32_t packetsReceived;

  std::string m_CSVfileName;
  int m_nSinks;
  std::string m_protocolName;
  double m_txp;
  bool m_traceMobility;
  uint32_t m_protocol;
  Ptr<WifiPhyStats> m_wifiPhyStats;
  int m_nwifis;

};

RoutingExperiment::RoutingExperiment ()
  : port (9),
    bytesTotal (0),
    packetsReceived (0),
    m_CSVfileName ("manet-routing.output.csv"),
    m_traceMobility (false),
    m_protocol (2), // mt_aodv
    m_nwifis(21)

{
  m_wifiPhyStats = CreateObject<WifiPhyStats> ();

}

static inline std::string
PrintReceivedPacket (Ptr<Socket> socket, Ptr<Packet> packet, Address senderAddress)
{
  std::ostringstream oss;

  oss << Simulator::Now ().GetSeconds () << " " << socket->GetNode ()->GetId ();

  if (InetSocketAddress::IsMatchingType (senderAddress))
    {
      InetSocketAddress addr = InetSocketAddress::ConvertFrom (senderAddress);
      oss << " received one packet from " << addr.GetIpv4 ();
    }
  else
    {
      oss << " received one packet!";
    }
  return oss.str ();
}

void
RoutingExperiment::ReceivePacket (Ptr<Socket> socket)
{
  Ptr<Packet> packet;
  Address senderAddress;
  while ((packet = socket->RecvFrom (senderAddress)))
    {
      bytesTotal += packet->GetSize ();
      packetsReceived += 1;
      //NS_LOG_UNCOND (PrintReceivedPacket (socket, packet, senderAddress));
    }
}

void
RoutingExperiment::CheckThroughput ()
{
  double kbs = (bytesTotal * 8.0) / 1000;
  bytesTotal = 0;

  std::ofstream out (m_CSVfileName.c_str (), std::ios::app);

  out << (Simulator::Now ()).GetSeconds () << ","
      << kbs << ","
      << packetsReceived << ","
      << m_nSinks << ","
      << m_protocolName << ","
      << m_txp << ""
      << std::endl;

  out.close ();
  packetsReceived = 0;
  Simulator::Schedule (Seconds (1.0), &RoutingExperiment::CheckThroughput, this);
}

Ptr<Socket>
RoutingExperiment::SetupPacketReceive (Ipv4Address addr, Ptr<Node> node)
{
  TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
  Ptr<Socket> sink = Socket::CreateSocket (node, tid);
  InetSocketAddress local = InetSocketAddress (addr, port);
  sink->Bind (local);
  sink->SetRecvCallback (MakeCallback (&RoutingExperiment::ReceivePacket, this));

  return sink;
}

std::string
RoutingExperiment::CommandSetup (int argc, char **argv)
{
  CommandLine cmd;
  cmd.AddValue ("CSVfileName", "The name of the CSV output file name", m_CSVfileName);
  cmd.AddValue ("traceMobility", "Enable mobility tracing", m_traceMobility);
  cmd.AddValue ("protocol", "0=AODV;1=OLSR;2=Mt_aodv;3=DSDV;4=DSR", m_protocol);
  cmd.AddValue ("nodes", "Numero de nos", m_nwifis);

  cmd.Parse (argc, argv);
  return m_CSVfileName;
}

void TearDownLink (Ptr<Node> nodeA, uint32_t interfaceA)
 {
   nodeA->GetObject<Ipv4> ()->SetDown (interfaceA);
  }

  void TearUpLink (Ptr<Node> nodeA, uint32_t interfaceA)
 {
   nodeA->GetObject<Ipv4> ()->SetUp (interfaceA);
  }


/*void Print ("Routing Table RT")
{
  RT.printPaths();
  mt_aodv::RoutingTableEntry::printPaths();
}*/


int
main (int argc, char *argv[])
{
  //LogComponentEnable("Mt_aodvRoutingProtocol", LOG_LEVEL_ALL);
  //LogComponentEnable("AodvRoutingProtocol", LOG_LEVEL_ALL);


  WifiPhyStats WifiPhyStats;
  RoutingExperiment experiment;
  std::string CSVfileName = experiment.CommandSetup (argc,argv);

  //blank out the last output file and write the column headers
  std::ofstream out (CSVfileName.c_str ());
  out << "SimulationSecond," <<
  "ReceiveRate," <<
  "PacketsReceived," <<
  "NumberOfSinks," <<
  "RoutingProtocol," <<
  "TransmissionPower" <<
  std::endl;
  out.close ();

  int nSinks = 1;
  double txp = 8.5;
  //m_wifiPhyStats = CreateObject<WifiPhyStats> ();

  experiment.Run (nSinks, txp, CSVfileName);
}
 
void
RoutingExperiment::Run (int nSinks, double txp, std::string CSVfileName)
{ srand(time(NULL));
  Packet::EnablePrinting ();
  m_nSinks = nSinks;
  m_txp = txp;
  m_CSVfileName = CSVfileName;

  int nWifis =m_nwifis;

  double TotalTime = 610.0;
  std::string rate ("50kbps");
  
  std::string phyMode ("ErpOfdmRate24Mbps");
  std::string tr_name ("manet-routing-compare");
  int nodeSpeed = 2; //in m/s
  int nodePause = 1; //in s
  m_protocolName = "protocol";

  //uint32_t SentPackets = 0;
  //uint32_t ReceivedPackets = 0;
  //uint32_t LostPackets = 0;

  Config::SetDefault  ("ns3::OnOffApplication::PacketSize",StringValue ("256"));
  Config::SetDefault ("ns3::OnOffApplication::DataRate",  StringValue (rate));

  //Set Non-unicastMode rate to unicast mode
  Config::SetDefault ("ns3::WifiRemoteStationManager::NonUnicastMode",StringValue (phyMode));

  NodeContainer adhocNodes;
  adhocNodes.Create (nWifis);

  // setting up wifi phy and channel using helpers
  //LrWpanHelper wpan;
  //NetDeviceContainer adhocDevices = wpan.Install(adhocNodes);

  WifiHelper wifi;
  wifi.SetStandard (WIFI_STANDARD_80211g);

  YansWifiPhyHelper wifiPhy;
  YansWifiChannelHelper wifiChannel;
  wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
  wifiChannel.AddPropagationLoss ("ns3::FriisPropagationLossModel");
  wifiPhy.SetChannel (wifiChannel.Create ());
  


  // Add a mac and disable rate control
  WifiMacHelper wifiMac;
  //wpan.SetRemoteStationManager ("ns3::ConstantRateWifiManager",

  
  wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                               "DataMode",StringValue (phyMode),
                                "ControlMode",StringValue (phyMode));

  wifiPhy.Set ("TxPowerStart",DoubleValue (txp));
  wifiPhy.Set ("TxPowerEnd", DoubleValue (txp));

  wifiMac.SetType ("ns3::AdhocWifiMac");
  NetDeviceContainer adhocDevices = wifi.Install (wifiPhy, wifiMac, adhocNodes);

  Ns2MobilityHelper mob = Ns2MobilityHelper("ricardo/grid_21.mob");

  mob.Install();


  AodvHelper aodv;
  Mt_aodvHelper mt_aodv;
  OlsrHelper olsr;
  DsdvHelper dsdv;
  DsrHelper dsr;
  DsrMainHelper dsrMain;
  Ipv4ListRoutingHelper list;
  InternetStackHelper internet;

  switch (m_protocol)
    {
    case 0:
      list.Add (aodv, 100);
      m_protocolName = "AODV";
      break;
    case 1:
      list.Add (olsr, 100);
      m_protocolName = "OLSR";
      break;
    case 2:
      list.Add (mt_aodv, 100);
      m_protocolName = "MT_AODV";
      break;
    case 3:
      list.Add (dsdv, 100);
      m_protocolName = "DSDV";
      break;
    case 4:
      m_protocolName = "DSR";
      break;
    default:
      NS_FATAL_ERROR ("No such protocol:" << m_protocol);
    }

  if (m_protocol < 4)
    {
      internet.SetRoutingHelper (list);
      internet.Install (adhocNodes);
    }
  else if (m_protocol == 4)
    {
      internet.Install (adhocNodes);
      dsrMain.Install (dsr, adhocNodes);
    }

  NS_LOG_INFO ("assigning ip address");

  Ipv4AddressHelper addressAdhoc;
  addressAdhoc.SetBase ("10.10.10.0", "255.255.255.0");
  Ipv4InterfaceContainer adhocInterfaces;
  adhocInterfaces = addressAdhoc.Assign (adhocDevices);

  OnOffHelper onoff1 ("ns3::UdpSocketFactory",Address ());
  onoff1.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
  onoff1.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));

  
  Ptr<Socket> sink = SetupPacketReceive (adhocInterfaces.GetAddress (0), adhocNodes.Get (0));
  AddressValue remoteAddress (InetSocketAddress (adhocInterfaces.GetAddress (0), port));
  onoff1.SetAttribute ("Remote", remoteAddress);


  for (int i = 1; i < nWifis; i++)
    {
      Ptr<UniformRandomVariable> var = CreateObject<UniformRandomVariable> ();
      ApplicationContainer temp = onoff1.Install (adhocNodes.Get (i));
      temp.Start (Seconds (var->GetValue (10.0,11.0)));
      temp.Stop (Seconds (TotalTime));
      }
      

  std::stringstream ss;
  ss << nWifis;
  std::string nodes = ss.str ();

  std::stringstream ss2;
  ss2 << nodeSpeed;
  std::string sNodeSpeed = ss2.str ();

  std::stringstream ss3;
  ss3 << nodePause;
  std::string sNodePause = ss3.str ();

  std::stringstream ss4;
  ss4 << rate;
  std::string sRate = ss4.str ();

  int AMOUNT=20;
  int MAX=20;

  int value[20];
  for (int i=0;i<AMOUNT;i++)
  {
    bool check;
    int n;
    do
    {
      n=rand()%MAX+1;
      check=true;
      for (int j=0;j<i;j++)
      {
        if (n ==value[j])
        {
          check=false;
          break;
        }
      } 
    }while(!check);
    value[i]=n;
  }

   int a=30;
  
  for (uint i=0;i<10;i++){
       
    Ptr<UniformRandomVariable> var1 = CreateObject<UniformRandomVariable> ();
    Simulator::Schedule (Seconds(a), &TearDownLink, adhocNodes.Get(value[i]), 1);
    a=a+10;
  }
    
  //NS_LOG_INFO ("Configure Tracing.");
  //tr_name = tr_name + "_" + m_protocolName +"_" + nodes + "nodes_" + sNodeSpeed + "speed_" + sNodePause + "pause_" + sRate + "rate";

  //AsciiTraceHelper ascii;
  //Ptr<OutputStreamWrapper> osw = ascii.CreateFileStream ( (tr_name + ".tr").c_str());
  //wifiPhy.EnableAsciiAll (osw);
  //AsciiTraceHelper ascii;
  //MobilityHelper::EnableAsciiAll (ascii.CreateFileStream (tr_name + m_protocolName+".mob"));

  //wifiPhy.EnablePcapAll("T2-log-Nodes");
  
  //int d=rand()%
  ////int a=20;
  //Ptr<UniformRandomVariable> var2 = CreateObject<UniformRandomVariable> ();
  /*for (int a=20;a<120;){
    for (int i = 1; i < 3;i++)
      { 
        Ptr<UniformRandomVariable> var1 = CreateObject<UniformRandomVariable> ();
        Simulator::Schedule (Seconds(a), &TearDownLink, adhocNodes.Get(i), 1);
        Ptr<UniformRandomVariable> var1a = CreateObject<UniformRandomVariable> ();
        Simulator::Schedule (Seconds(a+15), &TearUpLink, adhocNodes.Get(i), 1);   
        a=a+15;           
      }
    }*/


  //Simulator::Schedule (Seconds(10.0), &Print);
  //Schedule (const Time &delay, const Ptr< EventImpl > &event)
  //RoutingTableEntry::printPaths();
  uint aleatorio=rand()%10000;  
  std::string d ="_";
  d=d+std::to_string(aleatorio);

  Ptr<OutputStreamWrapper> routingStream =Create<OutputStreamWrapper> (m_protocolName+d+"routing-table2.routes", std::ios::out);
  //Ipv4RoutingHelper routingtable;
  mt_aodv.PrintRoutingTableAllEvery (Seconds (1.0),routingStream);  


  Ptr<FlowMonitor> monitor;
  FlowMonitorHelper flowmon;
  monitor = flowmon.InstallAll();

   //Config::Connect ("/NodeList/*/DeviceList/*/Phy/State/Tx", MakeCallback (&WifiPhyStats::PhyTxTrace, m_wifiPhyStats));
   // TxDrop, RxDrop not working yet.  Not sure what I'm doing wrong.
   //Config::Connect ("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/PhyTxDrop", MakeCallback (&WifiPhyStats::PhyTxDrop, m_wifiPhyStats));   
   //Config::Connect ("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/PhyRxDrop", MakeCallback (&WifiPhyStats::PhyRxDrop, m_wifiPhyStats));
   //Config::Connect ("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/PhyTxBegin",
                   //MakeCallback (&WifiPhyStats::WifiPhyTxBeginTrace, m_wifiPhyStats));

  NS_LOG_INFO ("Run Simulation.");

  CheckThroughput ();

  //AnimationInterface anim (m_protocolName+"_compare.xml");
  //anim.SetBackgroundImage("/home/ricardo/sim/ns-allinone-3.30.1/ns-3.30.1/ricardo/b4.png", 1.0, 1.0, 0.007, 0.006, 1.0);

  Simulator::Stop (Seconds (TotalTime+2.0));
  Simulator::Run ();



/*int j=0;
float AvgThroughput = 0;
Time Jitter;
Time Delay;*/

Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier> (flowmon.GetClassifier ());
  std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats ();
/*
  for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator iter = stats.begin (); iter != stats.end (); ++iter)
    {
    Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (iter->first);


NS_LOG_INFO("----Protocol: " << m_protocolName);
NS_LOG_INFO("Flow ID:" <<iter->first);
NS_LOG_INFO("SrcAddr " <<t.sourceAddress << " DstAddr "<< t.destinationAddress);
NS_LOG_INFO("Sent Packets =" <<iter->second.txPackets);
NS_LOG_INFO("Received Packets =" <<iter->second.rxPackets);
NS_LOG_INFO("Lost Packets =" <<iter->second.txPackets-iter->second.rxPackets);
NS_LOG_INFO("Packet Delivery Ratio =" <<iter->second.rxPackets*100/iter->second.txPackets << "%");
NS_LOG_INFO("Packet loss ratio =" << (iter->second.txPackets-iter->second.rxPackets)*100/iter->second.txPackets << "%");
NS_LOG_INFO("Delay =" <<iter->second.delaySum);
NS_LOG_INFO("Jitter =" <<iter->second.jitterSum);
NS_LOG_INFO("Throughput =" <<iter->second.rxBytes * 8.0/(iter->second.timeLastRxPacket.GetSeconds()-iter->second.timeFirstTxPacket.GetSeconds())/1024<<"Kbps");

SentPackets = SentPackets +(iter->second.txPackets);
ReceivedPackets = ReceivedPackets + (iter->second.rxPackets);
LostPackets = LostPackets + (iter->second.txPackets-iter->second.rxPackets);
AvgThroughput = AvgThroughput + (iter->second.rxBytes * 8.0/(iter->second.timeLastRxPacket.GetSeconds()-iter->second.timeFirstTxPacket.GetSeconds())/1024);
Delay = Delay + (iter->second.delaySum);
Jitter = Jitter + (iter->second.jitterSum);

j = j + 1;

}

AvgThroughput = AvgThroughput/j;
NS_LOG_INFO("----Protocol: " << m_protocolName);
NS_LOG_INFO("--------Total Results of the simulation----------"<<std::endl);
NS_LOG_INFO("Total Sent packets  =" << SentPackets);
NS_LOG_INFO("Total Received Packets =" << ReceivedPackets);
NS_LOG_INFO("Total Lost Packets =" << LostPackets);
NS_LOG_INFO("Packet Loss ratio =" << ((LostPackets*100)/SentPackets)<< "%");
NS_LOG_INFO("Packet Delivery Ratio =" << ((ReceivedPackets*100)/SentPackets)<< "%");
NS_LOG_UNCOND("Average Throughput =" << AvgThroughput<< "Kbps");
NS_LOG_UNCOND("End to End Delay =" << Delay);
NS_LOG_UNCOND("End to End Jitter delay =" << Jitter);
NS_LOG_INFO("Total Flod id " << j);*/

monitor->SerializeToXmlFile((tr_name+m_protocolName+d+".xml").c_str(), true, true);

  //flowmon->SerializeToXmlFile ((tr_name + ".flowmon").c_str(), false, false);

  Simulator::Destroy ();
}

