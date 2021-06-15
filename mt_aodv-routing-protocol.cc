//Achar todas as rotas para o destino
//Encaminhar para as rotas com menor caminho
//Nao criar rotas novas com RREQ, somente com RREP.

/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2009 IITP RAS
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
 * Based on
 *      NS-2 MT_AODV model developed by the CMU/MONARCH group and optimized and
 *      tuned by Samir Das and Mahesh Marina, University of Cincinnati;
 *
 *      MT_AODV-UU implementation by Erik Nordström of Uppsala University
 *      http://core.it.uu.se/core/index.php/MT_AODV-UU
 *
 * Authors: Elena Buchatskaia <borovkovaes@iitp.ru>
 *          Pavel Boyko <boyko@iitp.ru>
 */
#define NS_LOG_APPEND_CONTEXT                                   \
  if (m_ipv4) { std::clog << Simulator::Now().GetSeconds()<<"[node " << m_ipv4->GetObject<Node> ()->GetId () << "] "; }

#include "mt_aodv-routing-protocol.h"
#include "ns3/log.h"
#include "ns3/boolean.h"
#include "ns3/random-variable-stream.h"
#include "ns3/inet-socket-address.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/udp-l4-protocol.h"
#include "ns3/udp-header.h"
#include "ns3/wifi-net-device.h"
#include "ns3/adhoc-wifi-mac.h"
#include "ns3/string.h"
#include "ns3/pointer.h"
#include <algorithm>
#include <limits>
#include <ctime>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("Mt_aodvRoutingProtocol");

namespace mt_aodv {
NS_OBJECT_ENSURE_REGISTERED (RoutingProtocol);

/// UDP Port for MT_AODV control traffic
const uint32_t RoutingProtocol::MT_AODV_PORT = 654;

/**
* \ingroup mt_aodv
* \brief Tag used by MT_AODV implementation
*/
class DeferredRouteOutputTag : public Tag
{

public:
  /**
   * \brief Constructor
   * \param o the output interface
   */
  DeferredRouteOutputTag (int32_t o = -1) : Tag (),
                                            m_oif (o)
  {
  }

  /**
   * \brief Get the type ID.
   * \return the object TypeId
   */
  static TypeId GetTypeId ()
  {
    //std::cout<<" static TypeId GetTypeId () "<<std::endl;
    static TypeId tid = TypeId ("ns3::mt_aodv::DeferredRouteOutputTag")
      .SetParent<Tag> ()
      .SetGroupName ("Mt_aodv")
      .AddConstructor<DeferredRouteOutputTag> ()
    ;

    return tid;
  }

  TypeId  GetInstanceTypeId () const
  {
    //std::cout<<" protocol.cc TypeId  GetInstanceTypeId () const "<<std::endl;

    return GetTypeId ();
  }

  /**
   * \brief Get the output interface
   * \return the output interface
   */
  int32_t GetInterface () const
  {
    //std::cout<<" protocol.cc int32_t GetInterface () const "<<std::endl;

    return m_oif;
  }

  /**
   * \brief Set the output interface
   * \param oif the output interface
   */
  void SetInterface (int32_t oif)
  {
    //std::cout<<" protocol.cc void SetInterface (int32_t oif) "<<std::endl;

    m_oif = oif;
  }

  uint32_t GetSerializedSize () const
  {
    //std::cout<<"  protocol.cc uint32_t GetSerializedSize () const "<<std::endl;

    return sizeof(int32_t);
  }

  void  Serialize (TagBuffer i) const
  {
    //std::cout<<" protocol.cc void  Serialize (TagBuffer i) const "<<std::endl;

    i.WriteU32 (m_oif);
  }

  void  Deserialize (TagBuffer i)
  {
    //std::cout<<" protocol.cc void  Deserialize (TagBuffer i) "<<std::endl;

    m_oif = i.ReadU32 ();
  }

  void  Print (std::ostream &os) const
  {
    //std::cout<<" void  protocol.cc Print (std::ostream &os) const "<<std::endl;

    os << "DeferredRouteOutputTag: output interface = " << m_oif;
  }

private:
  /// Positive if output device is fixed in RouteOutput
  int32_t m_oif;
};

NS_OBJECT_ENSURE_REGISTERED (DeferredRouteOutputTag);




//-----------------------------------------------------------------------------
RoutingProtocol::RoutingProtocol ()
  : m_rreqRetries (2),
    m_ttlStart (1),
    m_ttlIncrement (2),
    m_ttlThreshold (7),
    m_timeoutBuffer (2),
    m_rreqRateLimit (10),
    m_rerrRateLimit (10),
    m_activeRouteTimeout (Seconds (3)),
    m_netDiameter (35),
    m_nodeTraversalTime (MilliSeconds (40)),
    m_netTraversalTime (Time ((2 * m_netDiameter) * m_nodeTraversalTime)),
    m_pathDiscoveryTime ( Time (2 * m_netTraversalTime)),
    m_myRouteTimeout (Time (2 * std::max (m_pathDiscoveryTime, m_activeRouteTimeout))),
    m_helloInterval (Seconds (1)),
    m_allowedHelloLoss (2),
    m_deletePeriod (Time (5 * std::max (m_activeRouteTimeout, m_helloInterval))),
    m_nextHopWait (m_nodeTraversalTime + MilliSeconds (10)),
    m_blackListTimeout (Time (m_rreqRetries * m_netTraversalTime)),
    m_maxQueueLen (64),
    m_maxQueueTime (Seconds (30)),
    m_destinationOnly (false),
    m_gratuitousReply (true),
    m_enableHello (true),
    m_routingTable (m_deletePeriod),
    m_queue (m_maxQueueLen, m_maxQueueTime),
    m_requestId (0),
    m_seqNo (0),
    m_rreqIdCache (m_pathDiscoveryTime),
    m_dpd (m_pathDiscoveryTime),
    m_nb (m_helloInterval),
    m_rreqCount (0),
    m_rerrCount (0),
    m_htimer (Timer::CANCEL_ON_DESTROY),
    m_rreqRateLimitTimer (Timer::CANCEL_ON_DESTROY),
    m_rerrRateLimitTimer (Timer::CANCEL_ON_DESTROY),
    m_lastBcastTime (Seconds (0))
{
  m_nb.SetCallback (MakeCallback (&RoutingProtocol::SendRerrWhenBreaksLinkToNextHop, this));

  srand(time(NULL));
  if(m_routingTableList.size()<4){
    m_routingTableList.push_back(RoutingTable(m_deletePeriod));
  }
}

TypeId
RoutingProtocol::GetTypeId (void)
{
    //std::cout<<" RoutingProtocol::GetTypeId (void) "<<std::endl;

  static TypeId tid = TypeId ("ns3::mt_aodv::RoutingProtocol")
    .SetParent<Ipv4RoutingProtocol> ()
    .SetGroupName ("Mt_aodv")
    .AddConstructor<RoutingProtocol> ()
    .AddAttribute ("HelloInterval", "HELLO messages emission interval.",
                   TimeValue (Seconds (1)),
                   MakeTimeAccessor (&RoutingProtocol::m_helloInterval),
                   MakeTimeChecker ())
    .AddAttribute ("TtlStart", "Initial TTL value for RREQ.",
                   UintegerValue (1),
                   MakeUintegerAccessor (&RoutingProtocol::m_ttlStart),
                   MakeUintegerChecker<uint16_t> ())
    .AddAttribute ("TtlIncrement", "TTL increment for each attempt using the expanding ring search for RREQ dissemination.",
                   UintegerValue (2),
                   MakeUintegerAccessor (&RoutingProtocol::m_ttlIncrement),
                   MakeUintegerChecker<uint16_t> ())
    .AddAttribute ("TtlThreshold", "Maximum TTL value for expanding ring search, TTL = NetDiameter is used beyond this value.",
                   UintegerValue (7),
                   MakeUintegerAccessor (&RoutingProtocol::m_ttlThreshold),
                   MakeUintegerChecker<uint16_t> ())
    .AddAttribute ("TimeoutBuffer", "Provide a buffer for the timeout.",
                   UintegerValue (2),
                   MakeUintegerAccessor (&RoutingProtocol::m_timeoutBuffer),
                   MakeUintegerChecker<uint16_t> ())
    .AddAttribute ("RreqRetries", "Maximum number of retransmissions of RREQ to discover a route",
                   UintegerValue (2),
                   MakeUintegerAccessor (&RoutingProtocol::m_rreqRetries),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("RreqRateLimit", "Maximum number of RREQ per second.",
                   UintegerValue (10),
                   MakeUintegerAccessor (&RoutingProtocol::m_rreqRateLimit),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("RerrRateLimit", "Maximum number of RERR per second.",
                   UintegerValue (10),
                   MakeUintegerAccessor (&RoutingProtocol::m_rerrRateLimit),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("NodeTraversalTime", "Conservative estimate of the average one hop traversal time for packets and should include "
                   "queuing delays, interrupt processing times and transfer times.",
                   TimeValue (MilliSeconds (40)),
                   MakeTimeAccessor (&RoutingProtocol::m_nodeTraversalTime),
                   MakeTimeChecker ())
    .AddAttribute ("NextHopWait", "Period of our waiting for the neighbour's RREP_ACK = 10 ms + NodeTraversalTime",
                   TimeValue (MilliSeconds (50)),
                   MakeTimeAccessor (&RoutingProtocol::m_nextHopWait),
                   MakeTimeChecker ())
    .AddAttribute ("ActiveRouteTimeout", "Period of time during which the route is considered to be valid",
                   TimeValue (Seconds (3)),
                   MakeTimeAccessor (&RoutingProtocol::m_activeRouteTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("MyRouteTimeout", "Value of lifetime field in RREP generating by this node = 2 * max(ActiveRouteTimeout, PathDiscoveryTime)",
                   TimeValue (Seconds (11.2)),
                   MakeTimeAccessor (&RoutingProtocol::m_myRouteTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("BlackListTimeout", "Time for which the node is put into the blacklist = RreqRetries * NetTraversalTime",
                   TimeValue (Seconds (5.6)),
                   MakeTimeAccessor (&RoutingProtocol::m_blackListTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("DeletePeriod", "DeletePeriod is intended to provide an upper bound on the time for which an upstream node A "
                   "can have a neighbor B as an active next hop for destination D, while B has invalidated the route to D."
                   " = 5 * max (HelloInterval, ActiveRouteTimeout)",
                   TimeValue (Seconds (15)),
                   MakeTimeAccessor (&RoutingProtocol::m_deletePeriod),
                   MakeTimeChecker ())
    .AddAttribute ("NetDiameter", "Net diameter measures the maximum possible number of hops between two nodes in the network",
                   UintegerValue (35),
                   MakeUintegerAccessor (&RoutingProtocol::m_netDiameter),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("NetTraversalTime", "Estimate of the average net traversal time = 2 * NodeTraversalTime * NetDiameter",
                   TimeValue (Seconds (2.8)),
                   MakeTimeAccessor (&RoutingProtocol::m_netTraversalTime),
                   MakeTimeChecker ())
    .AddAttribute ("PathDiscoveryTime", "Estimate of maximum time needed to find route in network = 2 * NetTraversalTime",
                   TimeValue (Seconds (5.6)),
                   MakeTimeAccessor (&RoutingProtocol::m_pathDiscoveryTime),
                   MakeTimeChecker ())
    .AddAttribute ("MaxQueueLen", "Maximum number of packets that we allow a routing protocol to buffer.",
                   UintegerValue (64),
                   MakeUintegerAccessor (&RoutingProtocol::SetMaxQueueLen,
                                         &RoutingProtocol::GetMaxQueueLen),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("MaxQueueTime", "Maximum time packets can be queued (in seconds)",
                   TimeValue (Seconds (30)),
                   MakeTimeAccessor (&RoutingProtocol::SetMaxQueueTime,
                                     &RoutingProtocol::GetMaxQueueTime),
                   MakeTimeChecker ())
    .AddAttribute ("AllowedHelloLoss", "Number of hello messages which may be loss for valid link.",
                   UintegerValue (2),
                   MakeUintegerAccessor (&RoutingProtocol::m_allowedHelloLoss),
                   MakeUintegerChecker<uint16_t> ())
    .AddAttribute ("GratuitousReply", "Indicates whether a gratuitous RREP should be unicast to the node originated route discovery.",
                   BooleanValue (true),
                   MakeBooleanAccessor (&RoutingProtocol::SetGratuitousReplyFlag,
                                        &RoutingProtocol::GetGratuitousReplyFlag),
                   MakeBooleanChecker ())
    .AddAttribute ("DestinationOnly", "Indicates only the destination may respond to this RREQ.",
                   BooleanValue (false),
                   MakeBooleanAccessor (&RoutingProtocol::SetDestinationOnlyFlag,
                                        &RoutingProtocol::GetDestinationOnlyFlag),
                   MakeBooleanChecker ())
    .AddAttribute ("EnableHello", "Indicates whether a hello messages enable.",
                   BooleanValue (true),
                   MakeBooleanAccessor (&RoutingProtocol::SetHelloEnable,
                                        &RoutingProtocol::GetHelloEnable),
                   MakeBooleanChecker ())
    .AddAttribute ("EnableBroadcast", "Indicates whether a broadcast data packets forwarding enable.",
                   BooleanValue (true),
                   MakeBooleanAccessor (&RoutingProtocol::SetBroadcastEnable,
                                        &RoutingProtocol::GetBroadcastEnable),
                   MakeBooleanChecker ())
    .AddAttribute ("UniformRv",
                   "Access to the underlying UniformRandomVariable",
                   StringValue ("ns3::UniformRandomVariable"),
                   MakePointerAccessor (&RoutingProtocol::m_uniformRandomVariable),
                   MakePointerChecker<UniformRandomVariable> ())
  ;
  return tid;
}
/*
void RoutingProtocol::TrocaTabela(RoutingTable m_routingTable,std::vector<RoutingTable> m_routingTableList){

  //std::cout<<"trocou a tabela" << std::endl;
  m_routingTable = m_routingTableList[1];

}*/


void
RoutingProtocol::SetMaxQueueLen (uint32_t len)
{
    //std::cout<<" RoutingProtocol::SetMaxQueueLen - Configura o tamanho da fila "<<std::endl;

  m_maxQueueLen = len;
  m_queue.SetMaxQueueLen (len);
}
void
RoutingProtocol::SetMaxQueueTime (Time t)
{
    //std::cout<<" RoutingProtocol::SetMaxQueueTime - Configura o tempo max da fila "<<std::endl;

  m_maxQueueTime = t;
  m_queue.SetQueueTimeout (t);
}

RoutingProtocol::~RoutingProtocol ()
{

}

void
RoutingProtocol::DoDispose ()
{
  //std::cout<<" RoutingProtocol::DoDispose () "<<std::endl;

  m_ipv4 = 0;
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::iterator iter =
         m_socketAddresses.begin (); iter != m_socketAddresses.end (); iter++)
    {
      iter->first->Close ();
    }
  m_socketAddresses.clear ();
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::iterator iter =
         m_socketSubnetBroadcastAddresses.begin (); iter != m_socketSubnetBroadcastAddresses.end (); iter++)
    {
      iter->first->Close ();
    }
  m_socketSubnetBroadcastAddresses.clear ();
  Ipv4RoutingProtocol::DoDispose ();
}

void
RoutingProtocol::PrintRoutingTable (Ptr<OutputStreamWrapper> stream, Time::Unit unit) const
{
  *stream->GetStream () << "Node: " << m_ipv4->GetObject<Node> ()->GetId ()
                        << "; Time: " << Now ().As (unit)
                        << ", Local time: " << GetObject<Node> ()->GetLocalTime ().As (unit)
                        << ", MT_AODV Routing table" << std::endl;

  m_routingTable.Print (stream);
  *stream->GetStream () << std::endl;

  for(uint i=0;i<m_routingTableList.size();i++)
{
  //std::cout<<"Print "<<m_routingTableList.size()<<std::endl;
  m_routingTableList[i].Print (stream);
  *stream->GetStream () << std::endl;
} 
  
}

int64_t
RoutingProtocol::AssignStreams (int64_t stream)
{
  //std::cout<<" RoutingProtocol::AssignStreams (int64_t stream) "<<std::endl;

  NS_LOG_FUNCTION (this << stream);
  m_uniformRandomVariable->SetStream (stream);
  return 1;
}

void
RoutingProtocol::Start ()
{
  //std::cout<<" RoutingProtocol::Start () - Inica os tempos limites RREQ e RERR"<<std::endl;
  NS_LOG_FUNCTION (this);
  if (m_enableHello)
    {
      m_nb.ScheduleTimer ();
    }

  m_rreqRateLimitTimer.SetFunction (&RoutingProtocol::RreqRateLimitTimerExpire,
                                    this);
  m_rreqRateLimitTimer.Schedule (Seconds (1));

  m_rerrRateLimitTimer.SetFunction (&RoutingProtocol::RerrRateLimitTimerExpire,
                                    this);
  m_rerrRateLimitTimer.Schedule (Seconds (1));

}
Ptr<Ipv4Route>
RoutingProtocol::RouteOutput(Ptr<Packet> p, const Ipv4Header &header,
                              Ptr<NetDevice> oif, Socket::SocketErrno &sockerr)
{
 //std::cout<<Simulator::Now()<<" RoutingProtocol::RouteOutput () "<<std::endl;
  
  NS_LOG_FUNCTION (this << header << (oif ? oif->GetIfIndex () : 0));
  if (!p)
    {
      NS_LOG_DEBUG ("Packet is == 0");
      return LoopbackRoute (header, oif); // later
    }
  if (m_socketAddresses.empty ())
    {
      sockerr = Socket::ERROR_NOROUTETOHOST;
      NS_LOG_LOGIC ("No mt_aodv interfaces");
      Ptr<Ipv4Route> route;
      return route;
    }
  sockerr = Socket::ERROR_NOTERROR;
  Ptr<Ipv4Route> route;
  Ipv4Address dst = header.GetDestination ();
  RoutingTableEntry rt;

  std::vector<int> tabelas_pos;
  //std::vector<int> hops_rt;
  //std::vector<int> tabelas_pos_min_hops;
  int c=0;
  int d=99;
  for (std::vector<RoutingTable>::iterator it = m_routingTableList.begin();it!=m_routingTableList.end();it++)
  {
    if (it->LookupValidRoute (dst, rt))
    { 
      if (rt.GetHop()<d)
        {
          d=rt.GetHop();
        }
    }
  }

  for (std::vector<RoutingTable>::iterator it = m_routingTableList.begin();it!=m_routingTableList.end();it++)
  {
    if (it->LookupValidRoute (dst, rt))
    { 
      if (rt.GetHop()==d)
        {
          tabelas_pos.push_back(c);
        }
    }
    c++;
  }


  if (tabelas_pos.size()>0){
    c=rand()%tabelas_pos.size();  
  }
    //11MAR

    if (tabelas_pos.size()>0){
      if (m_routingTableList[tabelas_pos[c]].LookupValidRoute (dst, rt))
      {
        route = rt.GetRoute ();
        NS_ASSERT (route != 0);
        NS_LOG_DEBUG ("Exist route to " << route->GetDestination () << " from interface " << route->GetSource ());
        if (oif != 0 && route->GetOutputDevice () != oif)
          {
            NS_LOG_DEBUG ("Output device doesn't match. Dropped.");
            sockerr = Socket::ERROR_NOROUTETOHOST;
            return Ptr<Ipv4Route> ();
          }

          //if (m_routingTableList[tabelas_pos[c]].LookupRoute(dst,rt))
          //{        
            UpdateRouteLifeTimei (dst,m_activeRouteTimeout,tabelas_pos[c]); //atualiza o destino se tiver enviando pacote
            UpdateRouteLifeTimei (route->GetGateway (),m_activeRouteTimeout,0);
            
            /*for (uint i=0;i<m_routingTableList.size();i++){
              if (m_routingTableList[i].LookupRoute(rt.GetNextHop(),rt)){ //atualiza o gateway em todas as tabelas
                UpdateRouteLifeTimei (dst, m_activeRouteTimeout,i);
                UpdateRouteLifeTimei (route->GetGateway (),m_activeRouteTimeout,i);
              }
            }*/
          //}
        return route;
      }
        //07MAR2021//UpdateRouteLifeTime (route->GetGateway ().first, m_activeRouteTimeout);
        
    }
  

  /*if (m_routingTable.LookupValidRoute (dst, rt))
    {
      route = rt.GetRoute ();
      NS_ASSERT (route != 0);
      NS_LOG_DEBUG ("Exist route to " << route->GetDestination () << " from interface " << route->GetSource ());
      if (oif != 0 && route->GetOutputDevice () != oif)
        {
          NS_LOG_DEBUG ("Output device doesn't match. Dropped.");
          sockerr = Socket::ERROR_NOROUTETOHOST;
          return Ptr<Ipv4Route> ();
        }
      UpdateRouteLifeTime (dst, m_activeRouteTimeout);
      UpdateRouteLifeTime (route->GetGateway (), m_activeRouteTimeout);

      //07MAR2021//UpdateRouteLifeTime (route->GetGateway ().first, m_activeRouteTimeout);
      return route;
    }*/

  // Valid route not found, in this case we return loopback.
  // Actual route request will be deferred until packet will be fully formed,
  // routed to loopback, received from loopback and passed to RouteInput (see below)
  uint32_t iif = (oif ? m_ipv4->GetInterfaceForDevice (oif) : -1);
  DeferredRouteOutputTag tag (iif);
  NS_LOG_DEBUG ("Valid Route not found");
  if (!p->PeekPacketTag (tag))
    {
      p->AddPacketTag (tag);
    }

 //std::cout<<"RouteOutput - Retornou Loopback"<<std::endl;
  return LoopbackRoute (header, oif);
}



void
RoutingProtocol::DeferredRouteOutput (Ptr<const Packet> p, const Ipv4Header & header,
                                      UnicastForwardCallback ucb, ErrorCallback ecb)
{
 //std::cout<<" RoutingProtocol::DeferredRouteOutput (Ptr<const Packet> p, const Ipv4Header & header, UnicastForwardCallback ucb, ErrorCallback ecb) "<<std::endl;

  NS_LOG_FUNCTION (this << p << header);
  NS_ASSERT (p != 0 && p != Ptr<Packet> ());

  QueueEntry newEntry (p, header, ucb, ecb);
  bool result = m_queue.Enqueue (newEntry);
  if (result)
    {
      NS_LOG_LOGIC ("Add packet " << p->GetUid () << " to queue. Protocol " << (uint16_t) header.GetProtocol ());
      RoutingTableEntry rt;
      //10MAR
      /// VERIFICAR O QUE FAZER 
      //for(uint i=0; i<m_routingTableList.size();i++){
        bool result = m_routingTableList[0].LookupRoute (header.GetDestination (), rt);

        if (result){
         //std::cout<<header.GetDestination ()<<std::endl;
         //std::cout<<"resultado Positivo"<<std::endl;
        }
        else{
         //std::cout<<"resultado negativo"<<std::endl;
        }

      //bool result = m_routingTable.LookupRoute (header.GetDestination (), rt);
        if (!result || ((rt.GetFlag () != IN_SEARCH) && result))
          {//std::cout<<"resultado negativo2"<<std::endl;
            NS_LOG_LOGIC ("Send new RREQ for outbound packet to " << header.GetDestination ());
            SendRequest (header.GetDestination ());
          }

      }
    
     //Simulator::Schedule (Seconds(12.0), &RoutingProtocol::TrocaTabela,m_routingTable,m_routingTableList);
}

bool
RoutingProtocol::RouteInput (Ptr<const Packet> p, const Ipv4Header &header,
                             Ptr<const NetDevice> idev, UnicastForwardCallback ucb,
                             MulticastForwardCallback mcb, LocalDeliverCallback lcb, ErrorCallback ecb)
{
 //std::cout<<" RoutingProtocol::RouteInput (Ptr<const Packet> p, const Ipv4Header &header, Ptr<const NetDevice> idev, UnicastForwardCallback ucb, MulticastForwardCallback mcb, LocalDeliverCallback lcb, ErrorCallback ecb) "<<std::endl;

  NS_LOG_FUNCTION (this << p->GetUid () << header.GetDestination () << idev->GetAddress ());
  if (m_socketAddresses.empty ())
    {
      NS_LOG_LOGIC ("No mt_aodv interfaces");
      return false;
    }
  NS_ASSERT (m_ipv4 != 0);
  NS_ASSERT (p != 0);
  // Check if input device supports IP
  NS_ASSERT (m_ipv4->GetInterfaceForDevice (idev) >= 0);
  int32_t iif = m_ipv4->GetInterfaceForDevice (idev);

  Ipv4Address dst = header.GetDestination ();
  Ipv4Address origin = header.GetSource ();

  // Deferred route request
  if (idev == m_lo)
    {
      DeferredRouteOutputTag tag;
      if (p->PeekPacketTag (tag))
        {
          DeferredRouteOutput (p, header, ucb, ecb);
          return true;
        }
    }

  // Duplicate of own packet
  if (IsMyOwnAddress (origin))
    {
      return true;
    }

  // MT_AODV is not a multicast routing protocol
  if (dst.IsMulticast ())
    {
      return false;
    }

  // Broadcast local delivery/forwarding
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j =
         m_socketAddresses.begin (); j != m_socketAddresses.end (); ++j)
    {
      Ipv4InterfaceAddress iface = j->second;
      if (m_ipv4->GetInterfaceForAddress (iface.GetLocal ()) == iif)
        {
          if (dst == iface.GetBroadcast () || dst.IsBroadcast ())
            {
              if (m_dpd.IsDuplicate (p, header))
                {
                  NS_LOG_DEBUG ("Duplicated packet " << p->GetUid () << " from " << origin << ". Drop.");
                  return true;
                }
              UpdateRouteLifeTime (origin, m_activeRouteTimeout);
              Ptr<Packet> packet = p->Copy ();
              if (lcb.IsNull () == false)
                {
                  NS_LOG_LOGIC ("Broadcast local delivery to " << iface.GetLocal ());
                  lcb (p, header, iif);
                  // Fall through to additional processing
                }
              else
                {
                  NS_LOG_ERROR ("Unable to deliver packet locally due to null callback " << p->GetUid () << " from " << origin);
                  ecb (p, header, Socket::ERROR_NOROUTETOHOST);
                }
              if (!m_enableBroadcast)
                {
                  return true;
                }
              if (header.GetProtocol () == UdpL4Protocol::PROT_NUMBER)
                {
                  UdpHeader udpHeader;
                  p->PeekHeader (udpHeader);
                  if (udpHeader.GetDestinationPort () == MT_AODV_PORT)
                    {
                      // MT_AODV packets sent in broadcast are already managed
                      return true;
                    }
                }
              if (header.GetTtl () > 1)
                {
                  NS_LOG_LOGIC ("Forward broadcast. TTL " << (uint16_t) header.GetTtl ());
                  RoutingTableEntry toBroadcast;
                  //10MAR

                  if (m_routingTableList[0].LookupRoute (dst, toBroadcast))


                  //if (m_routingTable.LookupRoute (dst, toBroadcast))
                    {
                      Ptr<Ipv4Route> route = toBroadcast.GetRoute ();
                      ucb (route, packet, header);
                    }
                  else
                    {
                      NS_LOG_DEBUG ("No route to forward broadcast. Drop packet " << p->GetUid ());
                    }
                }
              else
                {
                  NS_LOG_DEBUG ("TTL exceeded. Drop packet " << p->GetUid ());
                }
              return true;
            }
        }
    }

    //14MAR VERIFICAR ATUALIZACAO

     /*if (m_ipv4->IsDestinationAddress (dst, iif))
    {
      UpdateRouteLifeTime (origin, m_activeRouteTimeout);
      RoutingTableEntry toOrigin;
      if (m_routingTable.LookupValidRoute (origin, toOrigin))
        {
          UpdateRouteLifeTime (toOrigin.GetNextHop (), m_activeRouteTimeout);
          m_nb.Update (toOrigin.GetNextHop (), m_activeRouteTimeout);
        }
      if (lcb.IsNull () == false)
        {
          NS_LOG_LOGIC ("Unicast local delivery to " << dst);
          lcb (p, header, iif);
        }
      else
        {
          NS_LOG_ERROR ("Unable to deliver packet locally due to null callback " << p->GetUid () << " from " << origin);
          ecb (p, header, Socket::ERROR_NOROUTETOHOST);
        }
      return true;
    }*/


  // Unicast local delivery
  if (m_ipv4->IsDestinationAddress (dst, iif))
    { //std::cout<<"RouteInput is IsDestinationAddress"<< std::endl;
      //UpdateRouteLifeTime (origin, m_activeRouteTimeout);
      for (uint i=0;i<m_routingTableList.size();i++){
          RoutingTableEntry toOrigin;

      //10MAR
        if (m_routingTableList[i].LookupValidRoute (origin, toOrigin))

        //if (m_routingTable.LookupValidRoute (origin, toOrigin))
          { 
            //std::cout<<"UpdateRouteLifeTimei do RouteInput"<< std::endl;

            UpdateRouteLifeTimei (toOrigin.GetNextHop (), m_activeRouteTimeout,i);

            //std::cout<<"Update m_nb do RouteInput"<< std::endl;

            m_nb.Update (toOrigin.GetNextHop (), m_activeRouteTimeout);
          }
        if (lcb.IsNull () == false)
          {
            NS_LOG_LOGIC ("Unicast local delivery to " << dst);
            lcb (p, header, iif);
          }
        else
          {
            NS_LOG_ERROR ("Unable to deliver packet locally due to null callback " << p->GetUid () << " from " << origin);
            ecb (p, header, Socket::ERROR_NOROUTETOHOST);
          }
        return true;
      }
    }

  // Check if input device supports IP forwarding
  if (m_ipv4->IsForwarding (iif) == false)
    {
      NS_LOG_LOGIC ("Forwarding disabled for this interface");
      ecb (p, header, Socket::ERROR_NOROUTETOHOST);
      return true;
    }

  // Forwarding
  return Forwarding (p, header, ucb, ecb);
}

bool
RoutingProtocol::Forwarding (Ptr<const Packet> p, const Ipv4Header & header,
                             UnicastForwardCallback ucb, ErrorCallback ecb)
{
  NS_LOG_FUNCTION (this);
  Ipv4Address dst = header.GetDestination ();
  Ipv4Address origin = header.GetSource ();
  for (uint i=0;i<m_routingTableList.size();i++){
    m_routingTableList[i].Purge ();
  }
  RoutingTableEntry toDst;
  std::vector<int> tabelas_pos;
  int c=0;
  int e=99;

  for (uint i=0;i<m_routingTableList.size();i++){
    if (m_routingTableList[i].LookupRoute (dst, toDst))
      {
         Ptr<Ipv4Route> rota = toDst.GetRoute ();
          if(rota->GetGateway()==origin){
            continue; //tentar evitar loops
          }
          RoutingTableEntry toOrigin2;
          m_routingTableList[0].LookupRoute(origin, toOrigin2);
          if(rota->GetGateway()==toOrigin2.GetNextHop()){
            continue; 
          }

        else if (toDst.GetFlag () == VALID)
          {
            if (toDst.GetHop()<e)
            {
               e=toDst.GetHop();
            }
          }
        }
      }
  for (uint i=0;i<m_routingTableList.size();i++){
    if (m_routingTableList[i].LookupRoute (dst, toDst))
      {
        if (toDst.GetFlag () == VALID)
          {
            if (toDst.GetHop()==e)
            {
              tabelas_pos.push_back(c);
            }
          }
        }
        c++;
      }
  int d=0;
    if (tabelas_pos.size()>0){
      c=rand()%tabelas_pos.size();  
      d=tabelas_pos[c];
    }

  //for (uint i=0;i<m_routingTableList.size();i++){
    if (m_routingTableList[d].LookupRoute (dst, toDst))
      {
        if (toDst.GetFlag () == VALID)
          {
            Ptr<Ipv4Route> route = toDst.GetRoute ();
            NS_LOG_LOGIC (route->GetSource () << " forwarding to " << dst << " from " << origin << " packet " << p->GetUid ());

            /*
             *  Each time a route is used to forward a data packet, its Active Route
             *  Lifetime field of the source, destination and the next hop on the
             *  path to the destination is updated to be no less than the current
             *  time plus ActiveRouteTimeout.
             */
            UpdateRouteLifeTimei (origin, m_activeRouteTimeout,0);
            UpdateRouteLifeTimei (dst, m_activeRouteTimeout,d);
            //UpdateRouteLifeTimei (route->GetGateway (), m_activeRouteTimeout,0);
            /*
             *  Since the route between each originator and destination pair is expected to be symmetric, the
             *  Active Route Lifetime for the previous hop, along the reverse path back to the IP source, is also updated
             *  to be no less than the current time plus ActiveRouteTimeout
             */
            RoutingTableEntry toOrigin;
            m_routingTableList[0].LookupRoute (origin, toOrigin);
            //std::cout<<"Forwarding UpdateRouteLifeTime "<<origin<<std::endl;
            UpdateRouteLifeTimei (toOrigin.GetNextHop (), m_activeRouteTimeout,0);

            m_nb.Update (route->GetGateway (), m_activeRouteTimeout);
            m_nb.Update (toOrigin.GetNextHop (), m_activeRouteTimeout);

            ucb (route, p, header);
            return true;
          }
        else
          {
            if (toDst.GetValidSeqNo ())
              {
                SendRerrWhenNoRouteToForward (dst, toDst.GetSeqNo (), origin);
                NS_LOG_DEBUG ("Drop packet " << p->GetUid () << " because no route to forward it.");
                return false;
              }
          }
      }
    //}
  NS_LOG_LOGIC ("route not found to " << dst << ". Send RERR message.");
  NS_LOG_DEBUG ("Drop packet " << p->GetUid () << " because no route to forward it.");
  SendRerrWhenNoRouteToForward (dst, 0, origin);
  return false;
}


void
RoutingProtocol::SetIpv4 (Ptr<Ipv4> ipv4)
{
  //std::cout<<" RoutingProtocol::SetIpv4 - Adiciona rota local na tabela 0"<<std::endl;

  NS_ASSERT (ipv4 != 0);
  NS_ASSERT (m_ipv4 == 0);

  m_ipv4 = ipv4;

  // Create lo route. It is asserted that the only one interface up for now is loopback
  NS_ASSERT (m_ipv4->GetNInterfaces () == 1 && m_ipv4->GetAddress (0, 0).GetLocal () == Ipv4Address ("127.0.0.1"));
  m_lo = m_ipv4->GetNetDevice (0);
  NS_ASSERT (m_lo != 0);
  // Remember lo route
  RoutingTableEntry rt (/*device=*/ m_lo, /*dst=*/ Ipv4Address::GetLoopback (), /*know seqno=*/ true, /*seqno=*/ 0,
                                    /*iface=*/ Ipv4InterfaceAddress (Ipv4Address::GetLoopback (), Ipv4Mask ("255.0.0.0")),
                                    /*hops=*/ 1, /*next hop=*/ Ipv4Address::GetLoopback (),
                                    /*lifetime=*/ Simulator::GetMaximumSimulationTime ());
  //m_routingTable.AddRoute (rt);

  m_routingTableList[0].AddRoute (rt); //Adiciona rota local na tabela 0
  
  Simulator::ScheduleNow (&RoutingProtocol::Start, this);
}

void
RoutingProtocol::NotifyInterfaceUp (uint32_t i)
{
 //std::cout<<" RoutingProtocol::NotifyInterfaceUp (uint32_t i) - cria socket l3 e envia Hello "<<std::endl;

  NS_LOG_FUNCTION (this << m_ipv4->GetAddress (i, 0).GetLocal ());
  Ptr<Ipv4L3Protocol> l3 = m_ipv4->GetObject<Ipv4L3Protocol> ();
  if (l3->GetNAddresses (i) > 1)
    {
      NS_LOG_WARN ("MT_AODV does not work with more then one address per each interface.");
    }
  Ipv4InterfaceAddress iface = l3->GetAddress (i, 0);
  if (iface.GetLocal () == Ipv4Address ("127.0.0.1"))
    {
      return;
    }

  // Create a socket to listen only on this interface
  Ptr<Socket> socket = Socket::CreateSocket (GetObject<Node> (),
                                             UdpSocketFactory::GetTypeId ());
  NS_ASSERT (socket != 0);
  socket->SetRecvCallback (MakeCallback (&RoutingProtocol::RecvMt_aodv, this));
  socket->BindToNetDevice (l3->GetNetDevice (i));
  socket->Bind (InetSocketAddress (iface.GetLocal (), MT_AODV_PORT));
  socket->SetAllowBroadcast (true);
  socket->SetIpRecvTtl (true);
  m_socketAddresses.insert (std::make_pair (socket, iface));

  // create also a subnet broadcast socket
  socket = Socket::CreateSocket (GetObject<Node> (),
                                 UdpSocketFactory::GetTypeId ());
  NS_ASSERT (socket != 0);
  socket->SetRecvCallback (MakeCallback (&RoutingProtocol::RecvMt_aodv, this));
  socket->BindToNetDevice (l3->GetNetDevice (i));
  socket->Bind (InetSocketAddress (iface.GetBroadcast (), MT_AODV_PORT));
  socket->SetAllowBroadcast (true);
  socket->SetIpRecvTtl (true);
  m_socketSubnetBroadcastAddresses.insert (std::make_pair (socket, iface));

  // Add local broadcast record to the routing table
  Ptr<NetDevice> dev = m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (iface.GetLocal ()));
  RoutingTableEntry rt (/*device=*/ dev, /*dst=*/ iface.GetBroadcast (), /*know seqno=*/ true, /*seqno=*/ 0, /*iface=*/ iface,
                                    /*hops=*/ 1, /*next hop=*/ iface.GetBroadcast (), /*lifetime=*/ Simulator::GetMaximumSimulationTime ());
  //m_routingTable.AddRoute (rt);

  m_routingTableList[0].AddRoute (rt);

  if (l3->GetInterface (i)->GetArpCache ())
    {
      m_nb.AddArpCache (l3->GetInterface (i)->GetArpCache ());  
    }

  // Allow neighbor manager use this interface for layer 2 feedback if possible
  Ptr<WifiNetDevice> wifi = dev->GetObject<WifiNetDevice> ();
  if (wifi == 0)
    {
      return;
    }
  Ptr<WifiMac> mac = wifi->GetMac ();
  if (mac == 0)
    {
      return;
    }

  mac->TraceConnectWithoutContext ("TxErrHeader", m_nb.GetTxErrorCallback ());

  
  RoutingTableEntry rt1 (/*device=*/ 0, /*dst=*/ Ipv4Address::GetLoopback (), /*know seqno=*/ true, /*seqno=*/ 0,
                                    /*iface=*/ Ipv4InterfaceAddress (Ipv4Address::GetLoopback (), Ipv4Mask ("255.0.0.0")),
                                    /*hops=*/ 1, /*next hop=*/ Ipv4Address::GetLoopback (),
                                    /*lifetime=*/ Simulator::GetMaximumSimulationTime ());
  //m_routingTable.AddRoute (rt);

  m_routingTableList[0].AddRoute (rt1); //Adiciona rota local na tabela 0


  SendHello();
   uint32_t startTime;
  if (m_enableHello)
    {
      m_htimer.SetFunction (&RoutingProtocol::HelloTimerExpire, this);
      startTime = m_uniformRandomVariable->GetInteger (0, 100);
      NS_LOG_DEBUG ("Starting at time " << startTime << "ms");
      m_htimer.Schedule (MilliSeconds (startTime));
    }
}

void
RoutingProtocol::NotifyInterfaceDown (uint32_t i)
{
  //std::cout<<"NotifyInterfaceDown i "<<i<<"tamanho da tabela "<< m_routingTableList.size()<<std::endl;
  NS_LOG_FUNCTION (this << m_ipv4->GetAddress (i, 0).GetLocal ());

  // Disable layer 2 link state monitoring (if possible)
  Ptr<Ipv4L3Protocol> l3 = m_ipv4->GetObject<Ipv4L3Protocol> ();
  Ptr<NetDevice> dev = l3->GetNetDevice (i);
  Ptr<WifiNetDevice> wifi = dev->GetObject<WifiNetDevice> ();
  if (wifi != 0)
    {
      Ptr<WifiMac> mac = wifi->GetMac ()->GetObject<AdhocWifiMac> ();
      if (mac != 0)
        {
          mac->TraceDisconnectWithoutContext ("TxErrHeader",
                                              m_nb.GetTxErrorCallback ());
          m_nb.DelArpCache (l3->GetInterface (i)->GetArpCache ());
        }
    }

  // Close socket
  Ptr<Socket> socket = FindSocketWithInterfaceAddress (m_ipv4->GetAddress (i, 0));
  NS_ASSERT (socket);
  socket->Close ();
  m_socketAddresses.erase (socket);

  // Close socket
  socket = FindSubnetBroadcastSocketWithInterfaceAddress (m_ipv4->GetAddress (i, 0));
  NS_ASSERT (socket);
  socket->Close ();
  m_socketSubnetBroadcastAddresses.erase (socket);

  if (m_socketAddresses.empty ())
    {
      //std::cout<<" Tamanho da Tabela if empty "<<m_routingTableList.size()<<std::endl;
      NS_LOG_LOGIC ("No mt_aodv interfaces");
      m_htimer.Cancel ();
      m_nb.Clear ();

      for (uint j=0; j<m_routingTableList.size();j++)
      {
        //std::cout<<" Tamanho da Tabela if empty "<<m_routingTableList.size()<<" indice da tabela "<< j<<std::endl;
        m_routingTableList[j].Clear ();
      }
      return;
    }

  for (uint j=0; j<m_routingTableList.size();j++)
	{
    //std::cout<<" Tamanho da Tabela "<<m_routingTableList.size()<<" indice da tabela"<< j<<std::endl;
    m_routingTableList[j].DeleteAllRoutesFromInterface (m_ipv4->GetAddress (i, 0));
  }

}

void
RoutingProtocol::NotifyAddAddress (uint32_t i, Ipv4InterfaceAddress address)
{
 //std::cout<<" RoutingProtocol::NotifyAddAddress - Adiciona Broadcast na tabela "<<std::endl;
  NS_LOG_FUNCTION (this << " interface " << i << " address " << address);
  Ptr<Ipv4L3Protocol> l3 = m_ipv4->GetObject<Ipv4L3Protocol> ();
  if (!l3->IsUp (i))
    {
      return;
    }
  if (l3->GetNAddresses (i) == 1)
    {
      Ipv4InterfaceAddress iface = l3->GetAddress (i, 0);
      Ptr<Socket> socket = FindSocketWithInterfaceAddress (iface);
      if (!socket)
        {
          if (iface.GetLocal () == Ipv4Address ("127.0.0.1"))
            {
              return;
            }
          // Create a socket to listen only on this interface
          Ptr<Socket> socket = Socket::CreateSocket (GetObject<Node> (),
                                                     UdpSocketFactory::GetTypeId ());
          NS_ASSERT (socket != 0);
          socket->SetRecvCallback (MakeCallback (&RoutingProtocol::RecvMt_aodv,this));
          socket->BindToNetDevice (l3->GetNetDevice (i));
          socket->Bind (InetSocketAddress (iface.GetLocal (), MT_AODV_PORT));
          socket->SetAllowBroadcast (true);
          m_socketAddresses.insert (std::make_pair (socket, iface));

          // create also a subnet directed broadcast socket
          socket = Socket::CreateSocket (GetObject<Node> (),
                                         UdpSocketFactory::GetTypeId ());
          NS_ASSERT (socket != 0);
          socket->SetRecvCallback (MakeCallback (&RoutingProtocol::RecvMt_aodv, this));
          socket->BindToNetDevice (l3->GetNetDevice (i));
          socket->Bind (InetSocketAddress (iface.GetBroadcast (), MT_AODV_PORT));
          socket->SetAllowBroadcast (true);
          socket->SetIpRecvTtl (true);
          m_socketSubnetBroadcastAddresses.insert (std::make_pair (socket, iface));

          // Add local broadcast record to the routing table
          Ptr<NetDevice> dev = m_ipv4->GetNetDevice (
              m_ipv4->GetInterfaceForAddress (iface.GetLocal ()));
          RoutingTableEntry rt (/*device=*/ dev, /*dst=*/ iface.GetBroadcast (), /*know seqno=*/ true,
                                            /*seqno=*/ 0, /*iface=*/ iface, /*hops=*/ 1,
                                            /*next hop=*/ iface.GetBroadcast (), /*lifetime=*/ Simulator::GetMaximumSimulationTime ());
          //m_routingTable.AddRoute (rt);

          //09MAR
          m_routingTableList[0].AddRoute (rt);
        }
    }
  else
    {
      NS_LOG_LOGIC ("MT_AODV does not work with more then one address per each interface. Ignore added address");
    }
}

void
RoutingProtocol::NotifyRemoveAddress (uint32_t i, Ipv4InterfaceAddress address)
{
  //std::cout<<" RoutingProtocol::NotifyRemoveAddress (uint32_t i, Ipv4InterfaceAddress address) "<<std::endl;

  NS_LOG_FUNCTION (this);
  Ptr<Socket> socket = FindSocketWithInterfaceAddress (address);
  if (socket)
    {
      m_routingTableList[0].DeleteAllRoutesFromInterface (address);
      socket->Close ();
      m_socketAddresses.erase (socket);

      Ptr<Socket> unicastSocket = FindSubnetBroadcastSocketWithInterfaceAddress (address);
      if (unicastSocket)
        {
          unicastSocket->Close ();
          m_socketAddresses.erase (unicastSocket);
        }

      Ptr<Ipv4L3Protocol> l3 = m_ipv4->GetObject<Ipv4L3Protocol> ();
      if (l3->GetNAddresses (i))
        {
          Ipv4InterfaceAddress iface = l3->GetAddress (i, 0);
          // Create a socket to listen only on this interface
          Ptr<Socket> socket = Socket::CreateSocket (GetObject<Node> (),
                                                     UdpSocketFactory::GetTypeId ());
          NS_ASSERT (socket != 0);
          socket->SetRecvCallback (MakeCallback (&RoutingProtocol::RecvMt_aodv, this));
          // Bind to any IP address so that broadcasts can be received
          socket->BindToNetDevice (l3->GetNetDevice (i));
          socket->Bind (InetSocketAddress (iface.GetLocal (), MT_AODV_PORT));
          socket->SetAllowBroadcast (true);
          socket->SetIpRecvTtl (true);
          m_socketAddresses.insert (std::make_pair (socket, iface));

          // create also a unicast socket
          socket = Socket::CreateSocket (GetObject<Node> (),
                                         UdpSocketFactory::GetTypeId ());
          NS_ASSERT (socket != 0);
          socket->SetRecvCallback (MakeCallback (&RoutingProtocol::RecvMt_aodv, this));
          socket->BindToNetDevice (l3->GetNetDevice (i));
          socket->Bind (InetSocketAddress (iface.GetBroadcast (), MT_AODV_PORT));
          socket->SetAllowBroadcast (true);
          socket->SetIpRecvTtl (true);
          m_socketSubnetBroadcastAddresses.insert (std::make_pair (socket, iface));

          // Add local broadcast record to the routing table
          Ptr<NetDevice> dev = m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (iface.GetLocal ()));
          RoutingTableEntry rt (/*device=*/ dev, /*dst=*/ iface.GetBroadcast (), /*know seqno=*/ true, /*seqno=*/ 0, /*iface=*/ iface,
                                            /*hops=*/ 1, /*next hop=*/ iface.GetBroadcast (), /*lifetime=*/ Simulator::GetMaximumSimulationTime ());

          m_routingTableList[0].AddRoute(rt);
        }
      if (m_socketAddresses.empty ())
        {
          NS_LOG_LOGIC ("No mt_aodv interfaces");
          m_htimer.Cancel ();
          m_nb.Clear ();

          m_routingTableList[0].Clear();
          return;
        }
    }
  else
    {
      NS_LOG_LOGIC ("Remove address not participating in MT_AODV operation");
    }
}

bool
RoutingProtocol::IsMyOwnAddress (Ipv4Address src)
{
  //std::cout<<" RoutingProtocol::IsMyOwnAddress (Ipv4Address src) "<<std::endl;

  NS_LOG_FUNCTION (this << src);
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j =
         m_socketAddresses.begin (); j != m_socketAddresses.end (); ++j)
    {
      Ipv4InterfaceAddress iface = j->second;
      if (src == iface.GetLocal ())
        {
          return true;
        }
    }
  return false;
}

Ptr<Ipv4Route>
RoutingProtocol::LoopbackRoute (const Ipv4Header & hdr, Ptr<NetDevice> oif) const
{
  //std::cout<<" RoutingProtocol::LoopbackRoute (const Ipv4Header & hdr, Ptr<NetDevice> oif) const "<<std::endl;

  NS_LOG_FUNCTION (this << hdr);
  NS_ASSERT (m_lo != 0);
  Ptr<Ipv4Route> rt = Create<Ipv4Route> ();
  rt->SetDestination (hdr.GetDestination ());
  //
  // Source address selection here is tricky.  The loopback route is
  // returned when MT_AODV does not have a route; this causes the packet
  // to be looped back and handled (cached) in RouteInput() method
  // while a route is found. However, connection-oriented protocols
  // like TCP need to create an endpoint four-tuple (src, src port,
  // dst, dst port) and create a pseudo-header for checksumming.  So,
  // MT_AODV needs to guess correctly what the eventual source address
  // will be.
  //
  // For single interface, single address nodes, this is not a problem.
  // When there are possibly multiple outgoing interfaces, the policy
  // implemented here is to pick the first available MT_AODV interface.
  // If RouteOutput() caller specified an outgoing interface, that
  // further constrains the selection of source address
  //
  std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j = m_socketAddresses.begin ();
  if (oif)
    {
      // Iterate to find an address on the oif device
      for (j = m_socketAddresses.begin (); j != m_socketAddresses.end (); ++j)
        {
          Ipv4Address addr = j->second.GetLocal ();
          int32_t interface = m_ipv4->GetInterfaceForAddress (addr);
          if (oif == m_ipv4->GetNetDevice (static_cast<uint32_t> (interface)))
            {
              rt->SetSource (addr);
              break;
            }
        }
    }
  else
    {
      rt->SetSource (j->second.GetLocal ());
    }
  NS_ASSERT_MSG (rt->GetSource () != Ipv4Address (), "Valid MT_AODV source address not found");
  rt->SetGateway (Ipv4Address ("127.0.0.1"));
  rt->SetOutputDevice (m_lo);
  return rt;
}

void
RoutingProtocol::SendRequest (Ipv4Address dst) 
{
 //std::cout<<Simulator::Now()<<" RoutingProtocol::SendRequest (Ipv4Address dst) "<<dst<<std::endl;

  NS_LOG_FUNCTION ( this << dst);
  // A node SHOULD NOT originate more than RREQ_RATELIMIT RREQ messages per second.
  if (m_rreqCount == m_rreqRateLimit)
    {
      Simulator::Schedule (m_rreqRateLimitTimer.GetDelayLeft () + MicroSeconds (100),
                           &RoutingProtocol::SendRequest, this, dst);
      return;
    }
  else
    {
      m_rreqCount++;
    }
  // Create RREQ header
  RreqHeader rreqHeader;
  rreqHeader.SetDst (dst);

  RoutingTableEntry rt;
  // Using the Hop field in Routing Table to manage the expanding ring search
  uint16_t ttl = m_ttlStart;
  if (m_routingTableList[0].LookupRoute (dst, rt))
  {
      if (rt.GetFlag () != IN_SEARCH)
        {
          ttl = std::min<uint16_t> (rt.GetHop () + m_ttlIncrement, m_netDiameter);
        }
      else
        {
          ttl = rt.GetHop () + m_ttlIncrement;
          if (ttl > m_ttlThreshold)
            {
              ttl = m_netDiameter;
            }
        }
      if (ttl == m_netDiameter)
        {
          rt.IncrementRreqCnt ();
        }
      if (rt.GetValidSeqNo ())
        {
          rreqHeader.SetDstSeqno (rt.GetSeqNo ());
        }
      else
        {
          rreqHeader.SetUnknownSeqno (true);
        }
      rt.SetHop (ttl);
      rt.SetFlag (IN_SEARCH);
      rt.SetLifeTime (m_pathDiscoveryTime);
      m_routingTableList[0].Update (rt);
    }
  else
    {
      rreqHeader.SetUnknownSeqno (true);
      Ptr<NetDevice> dev = 0;
      RoutingTableEntry newEntry (/*device=*/ dev, /*dst=*/ dst, /*validSeqNo=*/ false, /*seqno=*/ 0,
                                              /*iface=*/ Ipv4InterfaceAddress (),/*hop=*/ ttl,
                                              /*nextHop=*/ Ipv4Address (), /*lifeTime=*/ m_pathDiscoveryTime);
      // Check if TtlStart == NetDiameter
      
     //std::cout<<"inseriu rota"<<std::endl;
      if (ttl == m_netDiameter)
        {
          newEntry.IncrementRreqCnt ();
        }
      newEntry.SetFlag (IN_SEARCH);
      m_routingTableList[0].AddRoute (newEntry);
    }

  if (m_gratuitousReply)
    {
      rreqHeader.SetGratuitousRrep (true);
    }
  if (m_destinationOnly)
    {
      rreqHeader.SetDestinationOnly (true);
    }

  m_seqNo++;
  rreqHeader.SetOriginSeqno (m_seqNo);
  m_requestId++;
  rreqHeader.SetId (m_requestId);

  // Send RREQ as subnet directed broadcast from each interface used by mt_aodv
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j =
         m_socketAddresses.begin (); j != m_socketAddresses.end (); ++j)
    {
      Ptr<Socket> socket = j->first;
      Ipv4InterfaceAddress iface = j->second;

      rreqHeader.SetOrigin (iface.GetLocal ());
      m_rreqIdCache.IsDuplicate (iface.GetLocal (), m_requestId);

      Ptr<Packet> packet = Create<Packet> ();
      SocketIpTtlTag tag;
      tag.SetTtl (ttl);
      packet->AddPacketTag (tag);
      packet->AddHeader (rreqHeader);
      TypeHeader tHeader (MT_AODVTYPE_RREQ);
      packet->AddHeader (tHeader);
      // Send to all-hosts broadcast if on /32 addr, subnet-directed otherwise
      Ipv4Address destination;
      if (iface.GetMask () == Ipv4Mask::GetOnes ())
        {
          destination = Ipv4Address ("255.255.255.255");
        }
      else
        {
          destination = iface.GetBroadcast ();
        }
      NS_LOG_DEBUG ("Send RREQ with id " << rreqHeader.GetId () << " to socket");
      m_lastBcastTime = Simulator::Now ();

      //std::cout<<"Agendar SendTo"<< dst<<std::endl;
      Simulator::Schedule (Time (MilliSeconds (m_uniformRandomVariable->GetInteger (0, 10))), &RoutingProtocol::SendTo, this, socket, packet, destination);
    }
  ScheduleRreqRetry (dst);
}

void
RoutingProtocol::SendTo (Ptr<Socket> socket, Ptr<Packet> packet, Ipv4Address destination)
{
 //std::cout<<" RoutingProtocol::SendTo - Envia a mensagem (sempre broadcast)"<< destination<<std::endl;

  socket->SendTo (packet, 0, InetSocketAddress (destination, MT_AODV_PORT));

}
/*void
RoutingProtocol::ScheduleRreqRetry (Ipv4Address dst)
{
 //std::cout<<" RoutingProtocol::ScheduleRreqRetry (Ipv4Address dst) "<<dst<<std::endl;
  NS_LOG_FUNCTION (this << dst);
  if (m_addressReqTimer.find (dst) == m_addressReqTimer.end ())
    {//std::cout<< "ScheduleRreqRetry nao achou addressreqqtimer"<<std::endl;
      Timer timer (Timer::CANCEL_ON_DESTROY);
      m_addressReqTimer[dst] = timer;
    }
  m_addressReqTimer[dst].SetFunction (&RoutingProtocol::RouteRequestTimerExpire, this);
  m_addressReqTimer[dst].Remove ();
  m_addressReqTimer[dst].SetArguments (dst);
  RoutingTableEntry rt;
  
  for (uint j=0;j<m_routingTableList.size();j++){
    RoutingTableEntry rt1;
    if (m_routingTableList[j].LookupRoute (dst, rt1))
    { rt = rt1;
      break;
    }
    rt=rt1;
  } 

  //m_routingTable.LookupRoute(dst, rt);
  Time retry;
  if (rt.GetHop () < m_netDiameter)
    {
      retry = 2 * m_nodeTraversalTime * (rt.GetHop () + m_timeoutBuffer);
    }
  else
    {
      NS_ABORT_MSG_UNLESS (rt.GetRreqCnt () > 0, "Unexpected value for GetRreqCount ()");
      uint16_t backoffFactor = rt.GetRreqCnt () - 1;
      NS_LOG_LOGIC ("Applying binary exponential backoff factor " << backoffFactor);
      retry = m_netTraversalTime * (1 << backoffFactor);
    }

  m_addressReqTimer[dst].Schedule(retry);
 //std::cout<<" RoutingProtocol::ScheduleRreqRetry "<<dst<<" "<<retry.GetSeconds()<<std::endl;
  NS_LOG_LOGIC ("Scheduled RREQ retry in " << retry.GetSeconds () << " seconds");

}*/

void
RoutingProtocol::ScheduleRreqRetry (Ipv4Address dst)
{
 //std::cout<<" RoutingProtocol::ScheduleRreqRetry (Ipv4Address dst) "<<dst<<std::endl;
  NS_LOG_FUNCTION (this << dst);
  if (m_addressReqTimer.find (dst) == m_addressReqTimer.end ())
    {
      Timer timer (Timer::CANCEL_ON_DESTROY);
      m_addressReqTimer[dst] = timer;
    }
  m_addressReqTimer[dst].SetFunction (&RoutingProtocol::RouteRequestTimerExpire, this);
  m_addressReqTimer[dst].Remove ();
  m_addressReqTimer[dst].SetArguments (dst);
  RoutingTableEntry rt;
  m_routingTableList[0].LookupRoute (dst, rt);
  Time retry;
  if (rt.GetHop () < m_netDiameter)
    {
      retry = 2 * m_nodeTraversalTime * (rt.GetHop () + m_timeoutBuffer);
    }
  else
    {
      NS_ABORT_MSG_UNLESS (rt.GetRreqCnt () > 0, "Unexpected value for GetRreqCount ()");
      uint16_t backoffFactor = rt.GetRreqCnt () - 1;
      NS_LOG_LOGIC ("Applying binary exponential backoff factor " << backoffFactor);
      retry = m_netTraversalTime * (1 << backoffFactor);
    }
  m_addressReqTimer[dst].Schedule (retry);
  NS_LOG_LOGIC ("Scheduled RREQ retry in " << retry.GetSeconds () << " seconds");
}

void
RoutingProtocol::RecvMt_aodv (Ptr<Socket> socket)
{

  NS_LOG_FUNCTION (this << socket);
  Address sourceAddress;
  Ptr<Packet> packet = socket->RecvFrom (sourceAddress);
  InetSocketAddress inetSourceAddr = InetSocketAddress::ConvertFrom (sourceAddress);
  Ipv4Address sender = inetSourceAddr.GetIpv4 ();
  Ipv4Address receiver;

  if (m_socketAddresses.find (socket) != m_socketAddresses.end ())
    {
      receiver = m_socketAddresses[socket].GetLocal ();
    }
  else if (m_socketSubnetBroadcastAddresses.find (socket) != m_socketSubnetBroadcastAddresses.end ())
    {
      receiver = m_socketSubnetBroadcastAddresses[socket].GetLocal ();
    }
  else
    {
      NS_ASSERT_MSG (false, "Received a packet from an unknown socket");
    }
  NS_LOG_DEBUG ("MT_AODV node " << this << " received a MT_AODV packet from " << sender << " to " << receiver);

  //std::cout<<" RoutingProtocol::RecvMt_aodv  - recebe mensagens"   << " receiver "<< receiver<< "sender "<<sender<<std::endl;

  //std::cout<<" RoutingProtocol::RecvMt_aodv - atualiza vizinhos"<<std::endl;

  UpdateRouteToNeighbor (sender, receiver);
  TypeHeader tHeader (MT_AODVTYPE_RREQ);
  packet->RemoveHeader (tHeader);
  if (!tHeader.IsValid ())
    {
      NS_LOG_DEBUG ("MT_AODV message " << packet->GetUid () << " with unknown type received: " << tHeader.Get () << ". Drop");
      return; // drop
    }
  switch (tHeader.Get ())
    { 
    case MT_AODVTYPE_RREQ:
      { //std::cout<<" RoutingProtocol::RecvMt_aodv - RecvRequest"<<std::endl;
        RecvRequest (packet, receiver, sender);
        
        break;
      }
    case MT_AODVTYPE_RREP:
      {
        //std::cout<<" RoutingProtocol::RecvMt_aodv - RecvReply"<<std::endl;
        RecvReply (packet, receiver, sender);
        break;
      }
    case MT_AODVTYPE_RERR:
      {
        //std::cout<<" RoutingProtocol::RecvMt_aodv - RecvError"<<std::endl;
        RecvError (packet, sender);
        break;
      }
    case MT_AODVTYPE_RREP_ACK:
      {
        //std::cout<<" RoutingProtocol::RecvMt_aodv - RecvReplyAck"<<std::endl;
        RecvReplyAck (sender);
        break;
      }
    }
}


// receber o gateway??

bool
RoutingProtocol::UpdateRouteLifeTimei (Ipv4Address addr, Time lifetime, int i)
{
 //std::cout<<" RoutingProtocol::UpdateRouteLifeTimei (Ipv4Address addr, Time lifetime) "<<  Simulator::Now()<<" addr "<<addr << lifetime<< " "<< i<< std::endl;

  NS_LOG_FUNCTION (this << addr << lifetime);
  RoutingTableEntry rt;

  //13MAR - corrigir
  
    if (m_routingTableList[i].LookupRoute (addr, rt))
    {
      if (rt.GetFlag () == VALID)
        {
          NS_LOG_DEBUG ("Updating VALID route");
          rt.SetRreqCnt (0);
          rt.SetLifeTime (std::max (lifetime, rt.GetLifeTime ()));
          //rt.SetLifeTime (rt.GetLifeTime ());
          m_routingTableList[i].Update (rt);

          //tem que retornar para tabela 1 tbm
          return true;
        }
    }
     
  return false;  
}


bool
RoutingProtocol::UpdateRouteLifeTime (Ipv4Address addr, Time lifetime)
{
  //std::cout<<" RoutingProtocol::UpdateRouteLifeTime (Ipv4Address addr, Time lifetime) "<<addr<<std::endl;

  NS_LOG_FUNCTION (this << addr << lifetime);
  RoutingTableEntry rt;

    if (m_routingTableList[0].LookupRoute (addr, rt))
    {
      if (rt.GetFlag () == VALID)
        {
          NS_LOG_DEBUG ("Updating VALID route");
          rt.SetRreqCnt (0);
          rt.SetLifeTime (std::max (lifetime, rt.GetLifeTime ()));
          m_routingTableList[0].Update (rt);

          //tem que retornar para tabela 1 tbm
          return true;
        }
    }
     
  //}
  return false;  
}
  /*
  if (m_routingTable.LookupRoute (addr, rt))
    {
      if (rt.GetFlag () == VALID)
        {
          NS_LOG_DEBUG ("Updating VALID route");
          rt.SetRreqCnt (0);
          rt.SetLifeTime (std::max (lifetime, rt.GetLifeTime ()));
          m_routingTable.Update (rt);
          return true;
        }
    }
  return false;*/


void
RoutingProtocol::UpdateRouteToNeighbor (Ipv4Address sender, Ipv4Address receiver)
{
  //std::cout<<" RoutingProtocol::UpdateRouteToNeighbor - Insere ou atualiza rota na tabela 0 "  <<" sender "<<sender<< " receiver "<<receiver<<std::endl;

  NS_LOG_FUNCTION (this << "sender " << sender << " receiver " << receiver);
  RoutingTableEntry toNeighbor;

  
  if (!m_routingTableList[0].LookupRoute (sender, toNeighbor))
    {
      Ptr<NetDevice> dev = m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (receiver));
      RoutingTableEntry newEntry (/*device=*/ dev, /*dst=*/ sender, /*know seqno=*/ false, /*seqno=*/ 0,
                                              /*iface=*/ m_ipv4->GetAddress (m_ipv4->GetInterfaceForAddress (receiver), 0),
                                              /*hops=*/ 1, /*next hop=*/ sender, /*lifetime=*/ m_activeRouteTimeout);
      //m_routingTable.AddRoute (newEntry);

      //09MAR
    //std::cout<<" RoutingProtocol::UpdateRouteToNeighbor - Inseriu rota da tabela 0 " <<std::endl;

      m_routingTableList[0].AddRoute(newEntry);
    }
  else
    {
      Ptr<NetDevice> dev = m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (receiver));
      if (toNeighbor.GetValidSeqNo () && (toNeighbor.GetHop () == 1) && (toNeighbor.GetOutputDevice () == dev))
        {
          toNeighbor.SetLifeTime (std::max (m_activeRouteTimeout, toNeighbor.GetLifeTime ()));
          //std::cout<<" RoutingProtocol::UpdateRouteToNeighbor - Setou lifetime " <<std::endl;

        }
      else
        {
          RoutingTableEntry newEntry (/*device=*/ dev, /*dst=*/ sender, /*know seqno=*/ false, /*seqno=*/ 0,
                                                  /*iface=*/ m_ipv4->GetAddress (m_ipv4->GetInterfaceForAddress (receiver), 0),
                                                  /*hops=*/ 1, /*next hop=*/ sender, /*lifetime=*/ std::max (m_activeRouteTimeout, toNeighbor.GetLifeTime ()));
          //m_routingTable.Update (newEntry);

          //09MAR
          m_routingTableList[0].Update(newEntry);
          //std::cout<<" RoutingProtocol::UpdateRouteToNeighbor - Atualizou rota da tabela 0 " <<std::endl;

        }
    }
}

void
RoutingProtocol::RecvRequest (Ptr<Packet> p, Ipv4Address receiver, Ipv4Address src)
{
 //std::cout<<Simulator::Now()<<" RoutingProtocol::RecvRequest () "<<"receiver "<< receiver  <<" src "<< src<<std::endl;

  NS_LOG_FUNCTION (this);
  RreqHeader rreqHeader;
  p->RemoveHeader (rreqHeader);

 //std::cout<<" RoutingProtocol::RecvRequest () - remove cabecalho"<<std::endl;


  // A node ignores all RREQs received from any node in its blacklist
  RoutingTableEntry toPrev;
  //std::cout<<" RoutingProtocol::RecvRequest () - verifica se esta na blacklist - tabela 0"<<std::endl;

  if (m_routingTableList[0].LookupRoute (src, toPrev))
    {
      if (toPrev.IsUnidirectional ())
        { 
          //std::cout<<" RoutingProtocol::RecvRequest () "<<"esta na blacklist e retorna"<<std::endl;
          NS_LOG_DEBUG ("Ignoring RREQ from node in blacklist");
          return;
        }
    }

  //std::cout<<" RoutingProtocol::RecvRequest () - pega id e origem da mensagem"<<std::endl;

  uint32_t id = rreqHeader.GetId ();
  Ipv4Address origin = rreqHeader.GetOrigin ();

  /*
   *  Node checks to determine whether it has received a RREQ with the same Originator IP Address and RREQ ID.
   *  If such a RREQ has been received, the node silently discards the newly received RREQ.
   */
  //std::cout<<" RoutingProtocol::RecvRequest () - verifica se mensagem eh duplicada"<<std::endl;
  //std::cout<<"origem "<<origin<<" id "<<id<<std::endl;

  RoutingTableEntry toOrigin;
  if (m_rreqIdCache.IsDuplicate (origin, id))
    {
      //std::cout<<" RoutingProtocol::RecvRequest () "<<"eh duplicada e retorna"<<std::endl;
      NS_LOG_DEBUG ("Ignoring RREQ due to duplicate");
      //std::cout<<"origem "<<origin<<" id "<<id<<" DUPLICADO"<<std::endl;
      return;
    }

  // Increment RREQ hop count
  uint8_t hop = rreqHeader.GetHopCount () + 1;
  rreqHeader.SetHopCount (hop);

  /*
   *  When the reverse route is created or updated, the following actions on the route are also carried out:
   *  1. the Originator Sequence Number from the RREQ is compared to the corresponding destination sequence number
   *     in the route table entry and copied if greater than the existing value there
   *  2. the valid sequence number field is set to true;
   *  3. the next hop in the routing table becomes the node from which the  RREQ was received
   *  4. the hop count is copied from the Hop Count in the RREQ message;
   *  5. the Lifetime is set to be the maximum of (ExistingLifetime, MinimalLifetime), where
   *     MinimalLifetime = current time + 2*NetTraversalTime - 2*HopCount*NodeTraversalTime
   */

  bool achouRota=false;
  uint indiceRota=0;
  for (uint i=0;i<m_routingTableList.size();i++){
    if(m_routingTableList[i].LookupGateway(origin,src,toOrigin)){
      achouRota=true;
      indiceRota=i;
      break;
    }
  }
  if(achouRota)
    { 
      if (toOrigin.GetValidSeqNo ())
        {
          if (int32_t (rreqHeader.GetOriginSeqno ()) - int32_t (toOrigin.GetSeqNo ()) > 0)
            {
              toOrigin.SetSeqNo (rreqHeader.GetOriginSeqno ());
            }
        }
      else
        {
          toOrigin.SetSeqNo (rreqHeader.GetOriginSeqno ());
        }
      toOrigin.SetValidSeqNo (true);
      toOrigin.SetNextHop (src);
      toOrigin.SetOutputDevice (m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (receiver)));
      toOrigin.SetInterface (m_ipv4->GetAddress (m_ipv4->GetInterfaceForAddress (receiver), 0));
      toOrigin.SetHop (hop);
      toOrigin.SetLifeTime (std::max (Time (2 * m_netTraversalTime - 2 * hop * m_nodeTraversalTime),
                                      toOrigin.GetLifeTime ()));
      m_routingTableList[indiceRota].Update (toOrigin);
      //m_nb.Update (src, Time (AllowedHelloLoss * HelloInterval));
    }

   else
    {
      for (uint i=0;i<m_routingTableList.size();i++){
        if(!m_routingTableList[i].LookupRoute(origin,toOrigin)){
          Ptr<NetDevice> dev = m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (receiver));
          RoutingTableEntry newEntry (/*device=*/ dev, /*dst=*/ origin, /*validSeno=*/ true, /*seqNo=*/ rreqHeader.GetOriginSeqno (),
                                                  /*iface=*/ m_ipv4->GetAddress (m_ipv4->GetInterfaceForAddress (receiver), 0), /*hops=*/ hop,
                                                  /*nextHop*/ src, /*timeLife=*/ Time ((2 * m_netTraversalTime - 2 * hop * m_nodeTraversalTime)));
          m_routingTableList[i].AddRoute (newEntry);
          break;
        }
      }
    }

  RoutingTableEntry toNeighbor;
  if (!m_routingTableList[0].LookupRoute (src, toNeighbor))
    {
      NS_LOG_DEBUG ("Neighbor:" << src << " not found in routing table. Creating an entry");
      Ptr<NetDevice> dev = m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (receiver));
      RoutingTableEntry newEntry (dev, src, false, rreqHeader.GetOriginSeqno (),
                                  m_ipv4->GetAddress (m_ipv4->GetInterfaceForAddress (receiver), 0),
                                  1, src, m_activeRouteTimeout);
      m_routingTableList[0].AddRoute (newEntry);
    }
  else
    {
      toNeighbor.SetLifeTime (m_activeRouteTimeout);
      toNeighbor.SetValidSeqNo (false);
      toNeighbor.SetSeqNo (rreqHeader.GetOriginSeqno ());
      toNeighbor.SetFlag (VALID);
      toNeighbor.SetOutputDevice (m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (receiver)));
      toNeighbor.SetInterface (m_ipv4->GetAddress (m_ipv4->GetInterfaceForAddress (receiver), 0));
      toNeighbor.SetHop (1);
      toNeighbor.SetNextHop (src);
      m_routingTableList[0].Update (toNeighbor);
    }
  m_nb.Update (src, Time (m_allowedHelloLoss * m_helloInterval));

  NS_LOG_LOGIC (receiver << " receive RREQ with hop count " << static_cast<uint32_t> (rreqHeader.GetHopCount ())
                         << " ID " << rreqHeader.GetId ()
                         << " to destination " << rreqHeader.GetDst ());

  //  A node generates a RREP if either:
  //  (i)  it is itself the destination,
  if (IsMyOwnAddress (rreqHeader.GetDst ())) //retorna true se for o proprio endereco
    {
      m_routingTableList[0].LookupRoute (origin, toOrigin);
      NS_LOG_DEBUG ("Send reply since I am the destination");
      SendReply (rreqHeader, toOrigin);
      //std::cout<<"send reply"<<std::endl;
      return;
    }
  /*
   * (ii) or it has an active route to the destination, the destination sequence number in the node's existing route table entry for the destination
   *      is valid and greater than or equal to the Destination Sequence Number of the RREQ, and the "destination only" flag is NOT set.
   */
  RoutingTableEntry toDst;
  Ipv4Address dst = rreqHeader.GetDst ();

  //06MAIO
  //std::vector<int> hops_toDst;

  //int c=0;
  int d=0;
  int cHop=99;
  
  for (uint i=0; i<m_routingTableList.size();i++)
  { RoutingTableEntry toDst2;
    if (m_routingTableList[i].LookupRoute (dst, toDst2))
    { 
      if (toDst2.GetHop()<cHop && toDst2.GetFlag () == VALID)
        {
          cHop=toDst2.GetHop();
          d=i;
        }
    }
  }

  /*for (std::vector<RoutingTable>::iterator it = m_routingTableList.begin();it!=m_routingTableList.end();it++)
  { RoutingTableEntry toDst2;
    //std::cout<<c<<std::endl;
    if (it->LookupRoute (dst, toDst2))
    { 
      if (toDst2.GetHop()==cHop && toDst2.GetFlag () == VALID)
        {
          //toDst=toDst2;
          d=c;
          break;
        }
    } 
    c++;
  }*/
  std::cout<<"d"<<d<<std::endl;
  if (m_routingTableList[d].LookupRoute (dst, toDst))
    {
      /*
       * Drop RREQ, This node RREP will make a loop.
       */
      if (toDst.GetNextHop () == src)
        {
          NS_LOG_DEBUG ("Drop RREQ from " << src << ", dest next hop " << toDst.GetNextHop ());
          return;
        }
      /*
       * The Destination Sequence number for the requested destination is set to the maximum of the corresponding value
       * received in the RREQ message, and the destination sequence value currently maintained by the node for the requested destination.
       * However, the forwarding node MUST NOT modify its maintained value for the destination sequence number, even if the value
       * received in the incoming RREQ is larger than the value currently maintained by the forwarding node.
       */
      if ((rreqHeader.GetUnknownSeqno () || (int32_t (toDst.GetSeqNo ()) - int32_t (rreqHeader.GetDstSeqno ()) >= 0))
          && toDst.GetValidSeqNo () )
        {
          if (!rreqHeader.GetDestinationOnly () && toDst.GetFlag () == VALID)
            {
              m_routingTableList[0].LookupRoute (origin, toOrigin);
              SendReplyByIntermediateNode (toDst, toOrigin, rreqHeader.GetGratuitousRrep ());
              return;
            }
          rreqHeader.SetDstSeqno (toDst.GetSeqNo ());
          rreqHeader.SetUnknownSeqno (false);
        }
    }
  //std::cout<<"1893 1923"<<std::endl;
  SocketIpTtlTag tag;
  p->RemovePacketTag (tag);
  if (tag.GetTtl () < 2)
    { //std::cout<<"TTL exceeded"<<std::endl;
      NS_LOG_DEBUG ("TTL exceeded. Drop RREQ origin " << src << " destination " << dst );
      return;
    }

  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j =
         m_socketAddresses.begin (); j != m_socketAddresses.end (); ++j)
    {
      Ptr<Socket> socket = j->first;
      Ipv4InterfaceAddress iface = j->second;
      Ptr<Packet> packet = Create<Packet> ();
      SocketIpTtlTag ttl;
      ttl.SetTtl (tag.GetTtl () - 1);
      packet->AddPacketTag (ttl);
      packet->AddHeader (rreqHeader);
      TypeHeader tHeader (MT_AODVTYPE_RREQ);
      packet->AddHeader (tHeader);
      // Send to all-hosts broadcast if on /32 addr, subnet-directed otherwise
      Ipv4Address destination;
      if (iface.GetMask () == Ipv4Mask::GetOnes ())
        {
          destination = Ipv4Address ("255.255.255.255");
        }
      else
        {
          destination = iface.GetBroadcast ();
        }
      m_lastBcastTime = Simulator::Now ();

      //std::cout<<Simulator::Now()<<"RouteRequest dst"<<destination<<"src"<<src<<std::endl;

      Simulator::Schedule (Time (MilliSeconds (m_uniformRandomVariable->GetInteger (0, 10))), &RoutingProtocol::SendTo, this, socket, packet, destination);
    }
}

void
RoutingProtocol::SendReply (RreqHeader const & rreqHeader, RoutingTableEntry const & toOrigin)
{
  //std::cout<<" RoutingProtocol::SendReply (RreqHeader const & rreqHeader, RoutingTableEntry const & toOrigin) "<<std::endl;

  NS_LOG_FUNCTION (this << toOrigin.GetDestination ());
  /*
   * Destination node MUST increment its own sequence number by one if the sequence number in the RREQ packet is equal to that
   * incremented value. Otherwise, the destination does not change its sequence number before generating the  RREP message.
   */
  if (!rreqHeader.GetUnknownSeqno () && (rreqHeader.GetDstSeqno () == m_seqNo + 1))
    {
      m_seqNo++;
    }
  RrepHeader rrepHeader ( /*prefixSize=*/ 0, /*hops=*/ 0, /*dst=*/ rreqHeader.GetDst (),
                                          /*dstSeqNo=*/ m_seqNo, /*origin=*/ toOrigin.GetDestination (), 
                                          /*lifeTime=*/ m_myRouteTimeout);
  
    
 //std::cout<<" RoutingProtocol::SendReply"<<" origin "<<toOrigin.GetDestination ()<< " dst " << rreqHeader.GetDst ()<< std::endl;

  Ptr<Packet> packet = Create<Packet> ();
  SocketIpTtlTag tag;
  tag.SetTtl (toOrigin.GetHop ());
  packet->AddPacketTag (tag);
  packet->AddHeader (rrepHeader);
  TypeHeader tHeader (MT_AODVTYPE_RREP);
  packet->AddHeader (tHeader);
  Ptr<Socket> socket = FindSocketWithInterfaceAddress (toOrigin.GetInterface ());
  NS_ASSERT (socket);
  socket->SendTo (packet, 0, InetSocketAddress (toOrigin.GetNextHop (), MT_AODV_PORT));

}

void
RoutingProtocol::SendReplyByIntermediateNode (RoutingTableEntry & toDst, RoutingTableEntry & toOrigin, bool gratRep)
{
 //std::cout<<" SendReplyByIntermediateNode "<<"toDest.GetDestination "<<toDst.GetDestination()<<"toOrigin.GetDestination() "<<toOrigin.GetDestination()<<std::endl;

  NS_LOG_FUNCTION (this);
  RrepHeader rrepHeader (/*prefix size=*/ 0, /*hops=*/ toDst.GetHop (), /*dst=*/ toDst.GetDestination (), /*dst seqno=*/ toDst.GetSeqNo (),
                                          /*origin=*/ toOrigin.GetDestination (), 
                                          /*lifetime=*/ toDst.GetLifeTime ());
  /* If the node we received a RREQ for is a neighbor we are
   * probably facing a unidirectional link... Better request a RREP-ack
   */
  
  if (toDst.GetHop () == 1)
    {
      rrepHeader.SetAckRequired (true);
      RoutingTableEntry toNextHop;
      m_routingTableList[0].LookupRoute (toOrigin.GetNextHop (), toNextHop);
      toNextHop.m_ackTimer.SetFunction (&RoutingProtocol::AckTimerExpire, this);
      toNextHop.m_ackTimer.SetArguments (toNextHop.GetDestination (), m_blackListTimeout);
      toNextHop.m_ackTimer.SetDelay (m_nextHopWait);
    }

      //std::cout<<"Inseriu precursores "<<toOrigin.GetNextHop ()<<toDst.GetNextHop ()<<std::endl;

      toDst.InsertPrecursor (toOrigin.GetNextHop ());
      toOrigin.InsertPrecursor (toDst.GetNextHop ());
      //m_routingTableList[0].Update (toOrigin); 
  

  //toDst.InsertPrecursor (toOrigin.GetNextHop ());
  //toOrigin.InsertPrecursor (toDst.GetNextHop ());
  //for(uint i=0;i<m_routingTableList.size();i++){
    //UpdateRouteLifeTimei (toOrigin.GetDestination(),m_activeRouteTimeout,i);
    //m_routingTableList[i].UpdateRouteLifeTimei (toOrigin);
      //m_routingTable.Update (toDst);
      //m_routingTable.Update (toOrigin); 
  //}
  
  Ptr<Packet> packet = Create<Packet> ();
  SocketIpTtlTag tag;
  tag.SetTtl (toOrigin.GetHop ());
  packet->AddPacketTag (tag);
  packet->AddHeader (rrepHeader);
  TypeHeader tHeader (MT_AODVTYPE_RREP);
  packet->AddHeader (tHeader);
  Ptr<Socket> socket = FindSocketWithInterfaceAddress (toOrigin.GetInterface ());
  NS_ASSERT (socket);
  socket->SendTo (packet, 0, InetSocketAddress (toOrigin.GetNextHop (), MT_AODV_PORT));

  // Generating gratuitous RREPs
  if (gratRep)
    {
      RrepHeader gratRepHeader (/*prefix size=*/ 0, /*hops=*/ toOrigin.GetHop (), /*dst=*/ toOrigin.GetDestination (),
                                                 /*dst seqno=*/ toOrigin.GetSeqNo (), /*origin=*/ toDst.GetDestination (),
                                                 /*lifetime=*/ toOrigin.GetLifeTime ());
      Ptr<Packet> packetToDst = Create<Packet> ();
      SocketIpTtlTag gratTag;
      gratTag.SetTtl (toDst.GetHop ());
      packetToDst->AddPacketTag (gratTag);
      packetToDst->AddHeader (gratRepHeader);
      TypeHeader type (MT_AODVTYPE_RREP);
      packetToDst->AddHeader (type);
      Ptr<Socket> socket = FindSocketWithInterfaceAddress (toDst.GetInterface ());
      NS_ASSERT (socket);
      NS_LOG_LOGIC ("Send gratuitous RREP " << packet->GetUid ());
      socket->SendTo (packetToDst, 0, InetSocketAddress (toDst.GetNextHop (), MT_AODV_PORT));
    }
}

void
RoutingProtocol::SendReplyAck (Ipv4Address neighbor)
{
  //std::cout<<" RoutingProtocol::SendReplyAck (Ipv4Address neighbor) "<<neighbor<<std::endl;

  NS_LOG_FUNCTION (this << " to " << neighbor);
  RrepAckHeader h;
  TypeHeader typeHeader (MT_AODVTYPE_RREP_ACK);
  Ptr<Packet> packet = Create<Packet> ();
  SocketIpTtlTag tag;
  tag.SetTtl (1);
  packet->AddPacketTag (tag);
  packet->AddHeader (h);
  packet->AddHeader (typeHeader);
  RoutingTableEntry toNeighbor;
  m_routingTableList[0].LookupRoute (neighbor, toNeighbor);
  Ptr<Socket> socket = FindSocketWithInterfaceAddress (toNeighbor.GetInterface ());
  NS_ASSERT (socket);
  socket->SendTo (packet, 0, InetSocketAddress (neighbor, MT_AODV_PORT));
}

//Tabela por número de saltos
//Nao funciona pq ele cria uma entrada de tabela no RREQ.

/*
void
RoutingProtocol::RecvReply (Ptr<Packet> p, Ipv4Address receiver, Ipv4Address sender)
{
 //std::cout<<" RoutingProtocol::RecvReply (Ptr<Packet> p, Ipv4Address receiver, Ipv4Address sender) "
  <<"receiver "<< receiver<<" sender "<<sender<<std::endl;

  NS_LOG_FUNCTION (this << " src " << sender);
  RrepHeader rrepHeader;
  p->RemoveHeader (rrepHeader);
  Ipv4Address dst = rrepHeader.GetDst ();
  NS_LOG_LOGIC ("RREP destination " << dst << " RREP origin " << rrepHeader.GetOrigin ());

  uint8_t hop = rrepHeader.GetHopCount () + 1;
  rrepHeader.SetHopCount (hop);

  // If RREP is Hello message
  if (dst == rrepHeader.GetOrigin ())
    {
      ProcessHello (rrepHeader, receiver);
      return;
    }
  */
  /*
   * If the route table entry to the destination is created or updated, then the following actions occur:
   * -  the route is marked as active,
   * -  the destination sequence number is marked as valid,
   * -  the next hop in the route entry is assigned to be the node from which the RREP is received,
   *    which is indicated by the source IP address field in the IP header,
   * -  the hop count is set to the value of the hop count from RREP message + 1
   * -  the expiry time is set to the current time plus the value of the Lifetime in the RREP message,
   * -  and the destination sequence number is the Destination Sequence Number in the RREP message.
   */
  //Ptr<NetDevice> dev = m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (receiver));
  //RoutingTableEntry newEntry (/*device=*/ dev, /*dst=*/ dst, /*validSeqNo=*/ true, /*seqno=*/ rrepHeader.GetDstSeqno (),
   //                                       /*iface=*/ m_ipv4->GetAddress (m_ipv4->GetInterfaceForAddress (receiver), 0),/*hop=*/ hop,
    //                                      /*nextHop=*/ sender, /*lifeTime=*/ rrepHeader.GetLifeTime ());
  //RoutingTableEntry toDst;
  
  //09MAR

  /*  if(m_routingTableList.size()<hop){
      for(uint j=m_routingTableList.size();j<hop;j++){
        RoutingTable TabelaVazia(m_deletePeriod);
        m_routingTableList.push_back(TabelaVazia);
      }
    }

    if (m_routingTableList[hop-1].LookupGateway (dst,sender,toDst))
      {*/
        /*
         * The existing entry is updated only in the following circumstances:
         * (i) the sequence number in the routing table is marked as invalid in route table entry.
         */
        /*if (!toDst.GetValidSeqNo ())
          {
            m_routingTableList[hop-1].Update (newEntry);
          }
        // (ii)the Destination Sequence Number in the RREP is greater than the node's copy of the destination sequence number and the known value is valid,
        else if ((int32_t (rrepHeader.GetDstSeqno ()) - int32_t (toDst.GetSeqNo ())) > 0)
          {
            m_routingTableList[hop-1].Update (newEntry);
          }
        else
          {
            // (iii) the sequence numbers are the same, but the route is marked as inactive.
            if ((rrepHeader.GetDstSeqno () == toDst.GetSeqNo ()) && (toDst.GetFlag () != VALID))
              {
                m_routingTableList[hop-1].Update (newEntry);
              }
            // (iv)  the sequence numbers are the same, and the New Hop Count is smaller than the hop count in route table entry.
            else if ((rrepHeader.GetDstSeqno () == toDst.GetSeqNo ()) && (hop < toDst.GetHop ()))
              {
                m_routingTableList[hop-1].Update(newEntry);
              }

                  }
        }
            
       else
      {
        // The forward route for this destination is created if it does not already exist.
        NS_LOG_LOGIC ("add new route");
          m_routingTableList[hop-1].AddRoute (newEntry);
        }
    
 
  // Acknowledge receipt of the RREP by sending a RREP-ACK message back
  if (rrepHeader.GetAckRequired ())
    {
      SendReplyAck (sender);
      rrepHeader.SetAckRequired (false);
    }
  NS_LOG_LOGIC ("receiver " << receiver << " origin " << rrepHeader.GetOrigin ());
  if (IsMyOwnAddress (rrepHeader.GetOrigin ()))
    {
      if (toDst.GetFlag () == IN_SEARCH)
        {
          m_routingTableList[hop-1].Update (newEntry);
          m_addressReqTimer[dst].Remove ();
          m_addressReqTimer.erase (dst);
        }
      m_routingTableList[hop-1].LookupRoute (dst, toDst);

      SendPacketFromQueue (dst, toDst.GetRoute ());
      return;
    }

  RoutingTableEntry toOrigin;

  //09MAR
  if (!m_routingTableList[hop-1].LookupRoute (rrepHeader.GetOrigin (), toOrigin) || toOrigin.GetFlag () == IN_SEARCH)
    {
      return; // Impossible! drop.
    }

  toOrigin.SetLifeTime (std::max (m_activeRouteTimeout, toOrigin.GetLifeTime ()));

  //09MAR
  m_routingTableList[hop-1].Update (toOrigin);

  //09MAR

  // Update information about precursors
  if (m_routingTableList[hop-1].LookupValidRoute (rrepHeader.GetDst (), toDst))
    {
      toDst.InsertPrecursor (toOrigin.GetNextHop ());
      m_routingTableList[hop-1].Update (toDst);

      RoutingTableEntry toNextHopToDst;
      m_routingTableList[hop-1].LookupRoute (toDst.GetNextHop (), toNextHopToDst);
      toNextHopToDst.InsertPrecursor (toOrigin.GetNextHop ());
      m_routingTableList[hop-1].Update (toNextHopToDst);

      toOrigin.InsertPrecursor (toDst.GetNextHop ());
      m_routingTableList[hop-1].Update (toOrigin);

      RoutingTableEntry toNextHopToOrigin;
      m_routingTableList[hop-1].LookupRoute (toOrigin.GetNextHop (), toNextHopToOrigin);
      toNextHopToOrigin.InsertPrecursor (toDst.GetNextHop ());
      m_routingTableList[hop-1].Update (toNextHopToOrigin);
    }

  SocketIpTtlTag tag;
  p->RemovePacketTag (tag);
  if (tag.GetTtl () < 2)
    {
      NS_LOG_DEBUG ("TTL exceeded. Drop RREP destination " << dst << " origin " << rrepHeader.GetOrigin ());
      return;
    }

  Ptr<Packet> packet = Create<Packet> ();
  SocketIpTtlTag ttl;
  ttl.SetTtl (tag.GetTtl () - 1);
  packet->AddPacketTag (ttl);
  packet->AddHeader (rrepHeader);
  TypeHeader tHeader (MT_AODVTYPE_RREP);
  packet->AddHeader (tHeader);
  Ptr<Socket> socket = FindSocketWithInterfaceAddress (toOrigin.GetInterface ());
  NS_ASSERT (socket);
  socket->SendTo (packet, 0, InetSocketAddress (toOrigin.GetNextHop (), MT_AODV_PORT));
}
*/

//Tabela por destino


//RREP receiver = recebedor da msg, sender = enviador da msg, dst = destino IP, Origin = origem IP 
void
RoutingProtocol::RecvReply (Ptr<Packet> p, Ipv4Address receiver, Ipv4Address sender)
{
 //std::cout<<Simulator::Now()<<" RecvReply"<< " receiver "<< receiver<< " sender " << sender<<std::endl;

  NS_LOG_FUNCTION (this << " src " << sender);
  RrepHeader rrepHeader;
  p->RemoveHeader (rrepHeader);
  Ipv4Address dst = rrepHeader.GetDst ();
  NS_LOG_LOGIC ("RREP destination " << dst << " RREP origin " << rrepHeader.GetOrigin ());

  uint8_t hop = rrepHeader.GetHopCount () + 1;
  rrepHeader.SetHopCount (hop);

  // If RREP is Hello message
  if (dst == rrepHeader.GetOrigin ())
    {//std::cout<<"RECV Reply - EH HELLO - Chama o ProcessHello"<<std::endl;
      ProcessHello (rrepHeader, receiver);
      return;
    }

  /*
   * If the route table entry to the destination is created or updated, then the following actions occur:
   * -  the route is marked as active,
   * -  the destination sequence number is marked as valid,
   * -  the next hop in the route entry is assigned to be the node from which the RREP is received,
   *    which is indicated by the source IP address field in the IP header,
   * -  the hop count is set to the value of the hop count from RREP message + 1
   * -  the expiry time is set to the current time plus the value of the Lifetime in the RREP message,
   * -  and the destination sequence number is the Destination Sequence Number in the RREP message.
   */
  Ptr<NetDevice> dev = m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (receiver));
  RoutingTableEntry newEntry (/*device=*/ dev, /*dst=*/ dst, /*validSeqNo=*/ true, /*seqno=*/ rrepHeader.GetDstSeqno (),
                                       /*iface=*/ m_ipv4->GetAddress (m_ipv4->GetInterfaceForAddress (receiver), 0),/*hop=*/ hop,
                                         /*nextHop=*/ sender, /*lifeTime=*/ rrepHeader.GetLifeTime ());
  RoutingTableEntry toDst;
  int posicao=0;
  //09MAR
  //Verifica se possui rota para aquele destino em todas tabelas
  bool achou=false;
  for (uint i=0;i<m_routingTableList.size();i++)
  { 
    if (m_routingTableList[i].LookupRoute(dst,toDst))
    { //std::cout<<toDst.GetNextHop()<<std::endl;
      achou=true;
      break;
    }
  }
  //se não achar nenhuma rota, adiciona na tabela 0
  //if(!achou || toDst.GetNextHop()=="102.102.102.102" )
  //{ //std::cout<<" Adicionou na tabela 0 "<<" dst "<<dst<<" sender "<<sender<<std::endl;
    //m_routingTableList[0].AddRoute(newEntry);
  //}
  //se achar vai fazer update se tiver mesmo gateway ou IN_SEARCH, ou adicionar se não tiver mesmo gateway
  //não atualiza a rota com maior numero de saltos
  //else
  //{ 
    achou=false;
    for (uint i=0;i<m_routingTableList.size();i++)
    {
      m_routingTableList[i].LookupRoute(dst,toDst); //isso foi preciso pq o toDst eh alterado
      //if(m_routingTableList[i].LookupGateway(dst,sender,toDst))
      //{ 
        achou=true;
        /*
         * The existing entry is updated only in the following circumstances:
         * (i) the sequence number in the routing table is marked as invalid in route table entry.
         */
        if (!toDst.GetValidSeqNo ())
          { 
            //std::cout<<"achou gateway - Primeiro Update"<<dst<<sender<<std::endl;
            m_routingTableList[i].Update (newEntry);
            posicao=i;
            break;
          }
        // (ii)the Destination Sequence Number in the RREP is greater than the node's copy of the destination sequence number and the known value is valid,
        else if ((int32_t (rrepHeader.GetDstSeqno ()) - int32_t (toDst.GetSeqNo ())) > 0)
          {
            //std::cout<<"achou gateway - Segundo Update"<<dst<<sender<<std::endl;
            m_routingTableList[i].Update (newEntry);
            posicao=i;
            break;
          }
        else
          {
            // (iii) the sequence numbers are the same, but the route is marked as inactive.
            if ((rrepHeader.GetDstSeqno () == toDst.GetSeqNo ()) && (toDst.GetFlag () != VALID))
              {
                //std::cout<<"achou gateway - Terceiro Update"<<dst<<sender<<std::endl;
                m_routingTableList[i].Update (newEntry);
                //posicao=i;
                break;
              }
            // (iv)  the sequence numbers are the same, and the New Hop Count is smaller than the hop count in route table entry.
            else if ((rrepHeader.GetDstSeqno () == toDst.GetSeqNo ()) && (hop < toDst.GetHop ()))
              {
            //std::cout<<"achou gateway - Quarto Update"<<dst<<sender<<std::endl;
                m_routingTableList[i].Update(newEntry);
                posicao=i;
                break;
              }   
            else if ((rrepHeader.GetDstSeqno () == toDst.GetSeqNo ()) && (hop == toDst.GetHop ())){
              if(!m_routingTableList[i].LookupGateway(dst,sender,toDst)){
                if(m_routingTableList.size()<2){
                  RoutingTable TabelaVazia(m_deletePeriod);
                  m_routingTableList.push_back(TabelaVazia);
                  m_routingTableList.back().AddRoute(newEntry);
                  posicao=i+1;
                  break;
                }
                else{
                  if (i==0){
                    m_routingTableList.back().AddRoute(newEntry);
                    posicao=i+1;
                    break;
                }
                  if(i==1){
                    m_routingTableList[0].AddRoute(newEntry);
                    posicao=i;
                    break;
                  }

                }
              }               
            }
          }
      //}
    }
      if (!achou) //nao achou rota com esse gateway
        { 
          RoutingTableEntry toDst2; //foi criado novo toDst para não confundir com anterior
          //std::cout<<"nao achou gateway"<<std::endl;
          //vai percorrer as listas para incluir na primeira sem aquele destino
          for (uint i=0;i<m_routingTableList.size();i++)
          {        
            if(!m_routingTableList[i].LookupRoute(dst,toDst2)) //nao achou destino
            {
              m_routingTableList[i].AddRoute(newEntry);
              posicao=i;
              break;
            }
            //nao achou rota com mesmo gateway mas achou destino
            //cria nova tabela
            else if(i+1==m_routingTableList.size())
              { 
                //std::cout<<Simulator::Now()<<"Criou tabela"<<" dst "<<dst<<" sender "<<sender<<std::endl;
                RoutingTable TabelaVazia(m_deletePeriod);
                //if(m_routingTableList.size()<4){
                  m_routingTableList.push_back(TabelaVazia);
                  m_routingTableList.back().AddRoute(newEntry);
                  posicao=i+1;
                  break;
                //}
              }
            }
          }
        //}     
       
        
  // Acknowledge receipt of the RREP by sending a RREP-ACK message back
  if (rrepHeader.GetAckRequired ())
    {
      SendReplyAck (sender);
      rrepHeader.SetAckRequired (false);
    }

  m_routingTableList[0].LookupRoute(dst,toDst);
  NS_LOG_LOGIC ("receiver " << receiver << " origin " << rrepHeader.GetOrigin ());
  if (IsMyOwnAddress (rrepHeader.GetOrigin ()))
    {
      if (toDst.GetFlag () == IN_SEARCH)
        { 
          m_routingTableList[0].Update (newEntry);
          //m_routingTable.Update (newEntry);
          m_addressReqTimer[dst].Remove ();
          m_addressReqTimer.erase (dst);
        }

      //m_routingTableList[0].LookupGateway(dst,sender,toDst);
      m_routingTableList[0].LookupRoute (dst, toDst);
      //m_routingTable.LookupRoute (dst, toDst);
      SendPacketFromQueue (dst, toDst.GetRoute ());
      //std::cout<<Simulator::Now()<<" recvReply END"<< " receiver "<< receiver<< " sender " << sender<<std::endl;
      return;
    }

  RoutingTableEntry toOrigin;

  //09MAR
  if (!m_routingTableList[0].LookupRoute (rrepHeader.GetOrigin (), toOrigin) || toOrigin.GetFlag () == IN_SEARCH)
    {
      return; // Impossible! drop.
    }

  toOrigin.SetLifeTime (std::max (m_activeRouteTimeout, toOrigin.GetLifeTime ()));

  //09MAR
  m_routingTableList[0].Update (toOrigin);
  //m_routingTable.Update (toOrigin);


  //09MAR

  //Update information about precursors
  //Entender os precursores

    //for (uint i=0;i<m_routingTableList.size();i++){
    if (m_routingTableList[posicao].LookupValidRoute (rrepHeader.GetDst (), toDst))
    {
      RoutingTableEntry toNextHopToDst;
      RoutingTableEntry toNextHopToOrigin;

      m_routingTableList[0].LookupRoute (rrepHeader.GetOrigin (), toOrigin);
      m_routingTableList[0].LookupRoute (toDst.GetNextHop (), toNextHopToDst);
      m_routingTableList[0].LookupRoute (toOrigin.GetNextHop (), toNextHopToOrigin);

      toDst.InsertPrecursor (toOrigin.GetNextHop ());
      toDst.InsertPrecursor (rrepHeader.GetOrigin ());
      toNextHopToDst.InsertPrecursor (toOrigin.GetNextHop ());
      toOrigin.InsertPrecursor (toDst.GetNextHop ());
      toNextHopToOrigin.InsertPrecursor (toDst.GetNextHop ());

      m_routingTableList[posicao].Update (toDst);
      m_routingTableList[0].Update (toOrigin);
      m_routingTableList[0].Update (toNextHopToDst);
      m_routingTableList[0].Update (toNextHopToOrigin);
  }

  //if (m_routingTableList[posicao].LookupGateway (rrepHeader.GetDst (),sender, toDst)){
      //m_routingTableList[posicao].Update (toDst);
      //}
      
/*
  if (m_routingTable.LookupValidRoute (rrepHeader.GetDst (), toDst))
    {
      toDst.InsertPrecursor (toOrigin.GetNextHop ());
      m_routingTable.Update (toDst);

      RoutingTableEntry toNextHopToDst;
      m_routingTable.LookupRoute (toDst.GetNextHop (), toNextHopToDst);
      toNextHopToDst.InsertPrecursor (toOrigin.GetNextHop ());
      m_routingTable.Update (toNextHopToDst);

      toOrigin.InsertPrecursor (toDst.GetNextHop ());
      m_routingTable.Update (toOrigin);

      RoutingTableEntry toNextHopToOrigin;
      m_routingTable.LookupRoute (toOrigin.GetNextHop (), toNextHopToOrigin);
      toNextHopToOrigin.InsertPrecursor (toDst.GetNextHop ());
      m_routingTable.Update (toNextHopToOrigin);
    }
    */
  
  SocketIpTtlTag tag;
  p->RemovePacketTag (tag);
  if (tag.GetTtl () < 2)
    {
      NS_LOG_DEBUG ("TTL exceeded. Drop RREP destination " << dst << " origin " << rrepHeader.GetOrigin ());
      return;
    }

  Ptr<Packet> packet = Create<Packet> ();
  SocketIpTtlTag ttl;
  ttl.SetTtl (tag.GetTtl () - 1);
  packet->AddPacketTag (ttl);
  packet->AddHeader (rrepHeader);
  TypeHeader tHeader (MT_AODVTYPE_RREP);
  packet->AddHeader (tHeader);
  Ptr<Socket> socket = FindSocketWithInterfaceAddress (toOrigin.GetInterface ());
  NS_ASSERT (socket);
 //std::cout<<Simulator::Now()<<" recvReply END"<< " receiver "<< receiver<< " sender " << sender<<std::endl;

  socket->SendTo (packet, 0, InetSocketAddress (toOrigin.GetNextHop (), MT_AODV_PORT));

}

/*

void
RoutingProtocol::RecvReply (Ptr<Packet> p, Ipv4Address receiver, Ipv4Address sender)
{
 //std::cout<<" RoutingProtocol::RecvReply (Ptr<Packet> p, Ipv4Address receiver, Ipv4Address sender) "
  <<"receiver "<< receiver<<" sender "<<sender<<std::endl;

  NS_LOG_FUNCTION (this << " src " << sender);
  RrepHeader rrepHeader;
  p->RemoveHeader (rrepHeader);
  Ipv4Address dst = rrepHeader.GetDst ();
  NS_LOG_LOGIC ("RREP destination " << dst << " RREP origin " << rrepHeader.GetOrigin ());

  uint8_t hop = rrepHeader.GetHopCount () + 1;
  rrepHeader.SetHopCount (hop);

  // If RREP is Hello message
  if (dst == rrepHeader.GetOrigin ())
    {
      ProcessHello (rrepHeader, receiver);
      return;
    }
*/
  /*
   * If the route table entry to the destination is created or updated, then the following actions occur:
   * -  the route is marked as active,
   * -  the destination sequence number is marked as valid,
   * -  the next hop in the route entry is assigned to be the node from which the RREP is received,
   *    which is indicated by the source IP address field in the IP header,
   * -  the hop count is set to the value of the hop count from RREP message + 1
   * -  the expiry time is set to the current time plus the value of the Lifetime in the RREP message,
   * -  and the destination sequence number is the Destination Sequence Number in the RREP message.
   */
  //Ptr<NetDevice> dev = m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (receiver));
  //RoutingTableEntry newEntry (/*device=*/ dev, /*dst=*/ dst, /*validSeqNo=*/ true, /*seqno=*/ rrepHeader.GetDstSeqno (),
  //                                        /*iface=*/ m_ipv4->GetAddress (m_ipv4->GetInterfaceForAddress (receiver), 0),/*hop=*/ hop,
  //                                        /*nextHop=*/ sender, /*lifeTime=*/ rrepHeader.GetLifeTime ());
  /*RoutingTableEntry toDst;
  
  //09MAR

  for (uint i=0;i<m_routingTableList.size();i++)
  {
    if (m_routingTableList[i].LookupRoute (dst, toDst))
      {*/
        /*
         * The existing entry is updated only in the following circumstances:
         * (i) the sequence number in the routing table is marked as invalid in route table entry.
         */
        /*if (!toDst.GetValidSeqNo ())
          {
            m_routingTableList[i].Update (newEntry);
          }
        // (ii)the Destination Sequence Number in the RREP is greater than the node's copy of the destination sequence number and the known value is valid,
        else if ((int32_t (rrepHeader.GetDstSeqno ()) - int32_t (toDst.GetSeqNo ())) > 0)
          {
            m_routingTableList[i].Update (newEntry);
          }
        else
          {
            // (iii) the sequence numbers are the same, but the route is marked as inactive.
            if ((rrepHeader.GetDstSeqno () == toDst.GetSeqNo ()) && (toDst.GetFlag () != VALID))
              {
                m_routingTableList[i].Update (newEntry);
              }
            // (iv)  the sequence numbers are the same, and the New Hop Count is smaller than the hop count in route table entry.
            else if ((rrepHeader.GetDstSeqno () == toDst.GetSeqNo ()) && (hop < toDst.GetHop ()))
              {
                m_routingTableList[i].Update(newEntry);
              }

              //TEM QUE VERIFICAR SE O GATEWAY NÃO É O MESMO!

              //10MAR
             else{
                
                RoutingTable routingRicardo(m_deletePeriod);
                m_routingTableList.push_back(routingRicardo);
                m_routingTableList.back().AddRoute(newEntry);
               
               //std::cout<<" Tamanho da Tabela no RecvReply "<<m_routingTableList.size()<<std::endl; 
                  }
                }
              }
      
      }
      else
      {
        // The forward route for this destination is created if it does not already exist.
        NS_LOG_LOGIC ("add new route");
        if (i==0){
          m_routingTableList[i].AddRoute (newEntry);
        }
    
      }
    }


  if (m_routingTable.LookupRoute (dst, toDst))
    {
      
       * The existing entry is updated only in the following circumstances:
       * (i) the sequence number in the routing table is marked as invalid in route table entry.
       */

   /*   if (!toDst.GetValidSeqNo ())
        {
          m_routingTable.Update (newEntry);
        }
      // (ii)the Destination Sequence Number in the RREP is greater than the node's copy of the destination sequence number and the known value is valid,
      else if ((int32_t (rrepHeader.GetDstSeqno ()) - int32_t (toDst.GetSeqNo ())) > 0)
        {
          m_routingTable.Update (newEntry);
        }
      else
        {
          // (iii) the sequence numbers are the same, but the route is marked as inactive.
          if ((rrepHeader.GetDstSeqno () == toDst.GetSeqNo ()) && (toDst.GetFlag () != VALID))
            {
              m_routingTable.Update (newEntry);
            }
          // (iv)  the sequence numbers are the same, and the New Hop Count is smaller than the hop count in route table entry.
          else if ((rrepHeader.GetDstSeqno () == toDst.GetSeqNo ()) && (hop < toDst.GetHop ()))
            {
              //NS_LOG_UNCOND(Simulator::Now ());
              //NS_LOG_UNCOND(receiver);
              //NS_LOG_UNCOND(sender);
              //NS_LOG_UNCOND(dst);
              //NS_LOG_UNCOND(hop);

              m_routingTable.Update(newEntry);
            }
        }
    }

  else
    {
      // The forward route for this destination is created if it does not already exist.
      NS_LOG_LOGIC ("add new route");
      m_routingTable.AddRoute (newEntry);
    }
  // Acknowledge receipt of the RREP by sending a RREP-ACK message back
  if (rrepHeader.GetAckRequired ())
    {
      SendReplyAck (sender);
      rrepHeader.SetAckRequired (false);
    }
  NS_LOG_LOGIC ("receiver " << receiver << " origin " << rrepHeader.GetOrigin ());
  if (IsMyOwnAddress (rrepHeader.GetOrigin ()))
    {
      if (toDst.GetFlag () == IN_SEARCH)
        {
          m_routingTableList[0].Update (newEntry);
          //m_routingTable.Update (newEntry);
          m_addressReqTimer[dst].Remove ();
          m_addressReqTimer.erase (dst);
        }
      m_routingTableList[0].LookupRoute (dst, toDst);

      //m_routingTable.LookupRoute (dst, toDst);
      SendPacketFromQueue (dst, toDst.GetRoute ());
      return;
    }

  RoutingTableEntry toOrigin;

  //09MAR
  if (!m_routingTableList[0].LookupRoute (rrepHeader.GetOrigin (), toOrigin) || toOrigin.GetFlag () == IN_SEARCH)
    {
      return; // Impossible! drop.
    }

  if (!m_routingTable.LookupRoute (rrepHeader.GetOrigin (), toOrigin) || toOrigin.GetFlag () == IN_SEARCH)
    {
      return; // Impossible! drop.
    }
  toOrigin.SetLifeTime (std::max (m_activeRouteTimeout, toOrigin.GetLifeTime ()));

  //09MAR
  m_routingTableList[0].Update (toOrigin);

  //m_routingTable.Update (toOrigin);


  //09MAR

  // Update information about precursors
  if (m_routingTableList[0].LookupValidRoute (rrepHeader.GetDst (), toDst))
    {
      toDst.InsertPrecursor (toOrigin.GetNextHop ());
      m_routingTableList[0].Update (toDst);

      RoutingTableEntry toNextHopToDst;
      m_routingTableList[0].LookupRoute (toDst.GetNextHop (), toNextHopToDst);
      toNextHopToDst.InsertPrecursor (toOrigin.GetNextHop ());
      m_routingTableList[0].Update (toNextHopToDst);

      toOrigin.InsertPrecursor (toDst.GetNextHop ());
      m_routingTableList[0].Update (toOrigin);

      RoutingTableEntry toNextHopToOrigin;
      m_routingTableList[0].LookupRoute (toOrigin.GetNextHop (), toNextHopToOrigin);
      toNextHopToOrigin.InsertPrecursor (toDst.GetNextHop ());
      m_routingTableList[0].Update (toNextHopToOrigin);
    }

  // Update information about precursors
  if (m_routingTable.LookupValidRoute (rrepHeader.GetDst (), toDst))
    {
      toDst.InsertPrecursor (toOrigin.GetNextHop ());
      m_routingTable.Update (toDst);

      RoutingTableEntry toNextHopToDst;
      m_routingTable.LookupRoute (toDst.GetNextHop (), toNextHopToDst);
      toNextHopToDst.InsertPrecursor (toOrigin.GetNextHop ());
      m_routingTable.Update (toNextHopToDst);

      toOrigin.InsertPrecursor (toDst.GetNextHop ());
      m_routingTable.Update (toOrigin);

      RoutingTableEntry toNextHopToOrigin;
      m_routingTable.LookupRoute (toOrigin.GetNextHop (), toNextHopToOrigin);
      toNextHopToOrigin.InsertPrecursor (toDst.GetNextHop ());
      m_routingTable.Update (toNextHopToOrigin);
    }
  SocketIpTtlTag tag;
  p->RemovePacketTag (tag);
  if (tag.GetTtl () < 2)
    {
      NS_LOG_DEBUG ("TTL exceeded. Drop RREP destination " << dst << " origin " << rrepHeader.GetOrigin ());
      return;
    }

  Ptr<Packet> packet = Create<Packet> ();
  SocketIpTtlTag ttl;
  ttl.SetTtl (tag.GetTtl () - 1);
  packet->AddPacketTag (ttl);
  packet->AddHeader (rrepHeader);
  TypeHeader tHeader (MT_AODVTYPE_RREP);
  packet->AddHeader (tHeader);
  Ptr<Socket> socket = FindSocketWithInterfaceAddress (toOrigin.GetInterface ());
  NS_ASSERT (socket);
  socket->SendTo (packet, 0, InetSocketAddress (toOrigin.GetNextHop (), MT_AODV_PORT));
}

*/

void
RoutingProtocol::RecvReplyAck (Ipv4Address neighbor)
{
  //std::cout<<" RoutingProtocol::RecvReplyAck (Ipv4Address neighbor) "<<neighbor<<std::endl;

  NS_LOG_FUNCTION (this);
//  RoutingTableEntry rt;

 //for (uint i =0; i< m_routingTableList.size();i++)
 //{
  RoutingTableEntry rt;

   if (m_routingTableList[0].LookupRoute (neighbor, rt))
    {
      rt.m_ackTimer.Cancel ();
      rt.SetFlag (VALID);
      m_routingTableList[0].Update (rt);
    }
 // }
}

void
RoutingProtocol::ProcessHello (RrepHeader const & rrepHeader, Ipv4Address receiver )
{
  //std::cout<<" RoutingProtocol::ProcessHello () receiver "<<receiver<<std::endl;

  NS_LOG_FUNCTION (this << "from " << rrepHeader.GetDst ());
  /*
   *  Whenever a node receives a Hello message from a neighbor, the node
   * SHOULD make sure that it has an active route to the neighbor, and
   * create one if necessary.
   */
  RoutingTableEntry toNeighbor;
  if (!m_routingTableList[0].LookupRoute (rrepHeader.GetDst (), toNeighbor))
    {
      Ptr<NetDevice> dev = m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (receiver));
      RoutingTableEntry newEntry (/*device=*/ dev, /*dst=*/ rrepHeader.GetDst (), /*validSeqNo=*/ true, /*seqno=*/ rrepHeader.GetDstSeqno (),
                                              /*iface=*/ m_ipv4->GetAddress (m_ipv4->GetInterfaceForAddress (receiver), 0),
                                              /*hop=*/ 1, /*nextHop=*/ rrepHeader.GetDst (), /*lifeTime=*/ rrepHeader.GetLifeTime ());
      //m_routingTable.AddRoute (newEntry);
      m_routingTableList[0].AddRoute(newEntry);

      //std::cout<<" RoutingProtocol::ProcessHello - Adicionou rota na tabela 0"<< " dst "<< rrepHeader.GetDst ()<<" receiver "<<receiver <<std::endl;
    }
  else
    {
      toNeighbor.SetLifeTime (std::max (Time (m_allowedHelloLoss * m_helloInterval), toNeighbor.GetLifeTime ()));
      toNeighbor.SetSeqNo (rrepHeader.GetDstSeqno ());
      toNeighbor.SetValidSeqNo (true);
      toNeighbor.SetFlag (VALID);
      toNeighbor.SetOutputDevice (m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (receiver)));
      toNeighbor.SetInterface (m_ipv4->GetAddress (m_ipv4->GetInterfaceForAddress (receiver), 0));
      toNeighbor.SetHop (1);
      toNeighbor.SetNextHop (rrepHeader.GetDst ());
      //m_routingTable.Update (toNeighbor);
      m_routingTableList[0].Update(toNeighbor);
      
      //std::cout<<" RoutingProtocol::ProcessHello - Atualiza rota na tabela 0"<< std::endl;
    }
  if (m_enableHello)
    {
      m_nb.Update (rrepHeader.GetDst (), Time (m_allowedHelloLoss * m_helloInterval));
    }
}

void
RoutingProtocol::RecvError (Ptr<Packet> p, Ipv4Address src )
{
  //std::cout<<Simulator::Now()<<" RoutingProtocol::RecvError (Ptr<Packet> p, Ipv4Address src ) "<<src<<std::endl;

  NS_LOG_FUNCTION (this << " from " << src);
  RerrHeader rerrHeader;
  p->RemoveHeader (rerrHeader);
  //std::pair<Ipv4Address, uint32_t> un;
  //rerrHeader.RemoveUnDestination (un);

  for(uint j=0;j<m_routingTableList.size();j++)
  {
    RerrHeader rerrHeader0;
    rerrHeader0 = rerrHeader;
    
    std::pair<Ipv4Address, uint32_t> un;
    std::map<Ipv4Address, uint32_t> dstWithNextHopSrc;
    std::map<Ipv4Address, uint32_t> unreachable;

    //std::cout<<"RecvError src "<<src<<std::endl;
    //std::cout<<"un " <<un.first<<std::endl;

    //09MAR
    m_routingTableList[j].GetListOfDestinationWithNextHop (src, dstWithNextHopSrc);

      while (rerrHeader0.RemoveUnDestination (un))
    {
        //{ 
        //std::cout<< "UN - destino " <<un.first<< " j " <<j<<std::endl;
        for (std::map<Ipv4Address, uint32_t>::const_iterator i =
               dstWithNextHopSrc.begin (); i != dstWithNextHopSrc.end (); ++i)
          { //std::cout<<" valor de i first - destino para o src"<<i->first <<" j "<<j<<std::endl;  
            if (i->first == un.first)
              { //std::cout<<" valor de un first"<<un.first <<" j "<<j<<std::endl;  
                unreachable.insert (un);
                m_routingTableList[j].InvalidateRoutesWithDst (unreachable);
              }
          }
          
      }

    std::vector<Ipv4Address> precursors;
    for (std::map<Ipv4Address, uint32_t>::const_iterator i = unreachable.begin ();
         i != unreachable.end (); )
      {
        if (!rerrHeader0.AddUnDestination (i->first, i->second))
          {
            TypeHeader typeHeader (MT_AODVTYPE_RERR);
            Ptr<Packet> packet = Create<Packet> ();
            SocketIpTtlTag tag;
            tag.SetTtl (1);
            packet->AddPacketTag (tag);
            packet->AddHeader (rerrHeader);
            packet->AddHeader (typeHeader);
            SendRerrMessage (packet, precursors);
            rerrHeader0.Clear ();
          }
        else
          {
            RoutingTableEntry toDst;
            //m_routingTable.LookupRoute (i->first, toDst);
            
            //09MAR
            m_routingTableList[j].LookupRoute (i->first, toDst);
            toDst.GetPrecursors (precursors);
            ++i;
          }
      }
    if (rerrHeader0.GetDestCount () != 0)
      {
        TypeHeader typeHeader (MT_AODVTYPE_RERR);
        Ptr<Packet> packet = Create<Packet> ();
        SocketIpTtlTag tag;
        tag.SetTtl (1);
        packet->AddPacketTag (tag);
        packet->AddHeader (rerrHeader0);
        packet->AddHeader (typeHeader);
        SendRerrMessage (packet, precursors);
      }

    m_routingTableList[j].InvalidateRoutesWithDst (unreachable);
    //std::cout<<" FIM DO FOR DO RECVERROR "<<std::endl;
    
  }
}


void
RoutingProtocol::RouteRequestTimerExpire (Ipv4Address dst)
{
  NS_LOG_LOGIC (this);
  RoutingTableEntry toDst;
  if (m_routingTableList[0].LookupValidRoute (dst, toDst))
    {
      SendPacketFromQueue (dst, toDst.GetRoute ());
      NS_LOG_LOGIC ("route to " << dst << " found");
      return;
    }
  /*
   *  If a route discovery has been attempted RreqRetries times at the maximum TTL without
   *  receiving any RREP, all data packets destined for the corresponding destination SHOULD be
   *  dropped from the buffer and a Destination Unreachable message SHOULD be delivered to the application.
   */
  if (toDst.GetRreqCnt () == m_rreqRetries)
    {
      NS_LOG_LOGIC ("route discovery to " << dst << " has been attempted RreqRetries (" << m_rreqRetries << ") times with ttl " << m_netDiameter);
      m_addressReqTimer.erase (dst);
      m_routingTableList[0].DeleteRoute (dst);
      NS_LOG_DEBUG ("Route not found. Drop all packets with dst " << dst);
      m_queue.DropPacketWithDst (dst);
      return;
    }

  if (toDst.GetFlag () == IN_SEARCH)
    {
      NS_LOG_LOGIC ("Resend RREQ to " << dst << " previous ttl " << toDst.GetHop ());
      SendRequest (dst);
    }
  else
    {
      NS_LOG_DEBUG ("Route down. Stop search. Drop packet with destination " << dst);
      m_addressReqTimer.erase (dst);
      m_routingTableList[0].DeleteRoute (dst);
      m_queue.DropPacketWithDst (dst);
    }
}


void
RoutingProtocol::HelloTimerExpire ()
{
  //std::cout<<" RoutingProtocol::HelloTimerExpire () "<<std::endl;

  NS_LOG_FUNCTION (this);
  Time offset = Time (Seconds (0));
  if (m_lastBcastTime > Time (Seconds (0)))
    {
      offset = Simulator::Now () - m_lastBcastTime;
      NS_LOG_DEBUG ("Hello deferred due to last bcast at:" << m_lastBcastTime);
    }
  else
    {
      SendHello ();
    }
  m_htimer.Cancel ();
  Time diff = m_helloInterval - offset;
  m_htimer.Schedule (std::max (Time (Seconds (0)), diff));
  m_lastBcastTime = Time (Seconds (0));
}

void
RoutingProtocol::RreqRateLimitTimerExpire ()
{
 //std::cout<<" RoutingProtocol::RreqRateLimitTimerExpire () "<<std::endl;

  NS_LOG_FUNCTION (this);
  m_rreqCount = 0;
  m_rreqRateLimitTimer.Schedule (Seconds (0.5));
}

void
RoutingProtocol::RerrRateLimitTimerExpire ()
{
  //std::cout<<" RoutingProtocol::RerrRateLimitTimerExpire () "<<std::endl;

  NS_LOG_FUNCTION (this);
  m_rerrCount = 0;
  m_rerrRateLimitTimer.Schedule (Seconds (1));
}

void
RoutingProtocol::AckTimerExpire (Ipv4Address neighbor, Time blacklistTimeout)
{
 //std::cout<<" RoutingProtocol::AckTimerExpire (Ipv4Address neighbor, Time blacklistTimeout) "<<std::endl;

  NS_LOG_FUNCTION (this);
  m_routingTableList[0].MarkLinkAsUnidirectional (neighbor, blacklistTimeout);

}

void
RoutingProtocol::SendHello ()
{
  //std::cout<<" RoutingProtocol::SendHello () "<<std::endl;

  NS_LOG_FUNCTION (this);
  /* Broadcast a RREP with TTL = 1 with the RREP message fields set as follows:
   *   Destination IP Address         The node's IP address.
   *   Destination Sequence Number    The node's latest sequence number.
   *   Hop Count                      0
   *   Lifetime                       AllowedHelloLoss * HelloInterval
   */
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j = m_socketAddresses.begin (); j != m_socketAddresses.end (); ++j)
    {
      Ptr<Socket> socket = j->first;
      Ipv4InterfaceAddress iface = j->second;
      RrepHeader helloHeader (/*prefix size=*/ 0, /*hops=*/ 0, /*dst=*/ iface.GetLocal (), /*dst seqno=*/ m_seqNo,
                                               /*origin=*/ iface.GetLocal (),
                                               /*lifetime=*/ Time (m_allowedHelloLoss * m_helloInterval));
      Ptr<Packet> packet = Create<Packet> ();
      SocketIpTtlTag tag;
      tag.SetTtl (1);
      packet->AddPacketTag (tag);
      packet->AddHeader (helloHeader);
      TypeHeader tHeader (MT_AODVTYPE_RREP);
      packet->AddHeader (tHeader);
      // Send to all-hosts broadcast if on /32 addr, subnet-directed otherwise
      Ipv4Address destination;
      if (iface.GetMask () == Ipv4Mask::GetOnes ())
        {
          destination = Ipv4Address ("255.255.255.255");
        }
      else
        {
          destination = iface.GetBroadcast ();
        }

      Time jitter = Time (MilliSeconds (m_uniformRandomVariable->GetInteger (0, 10)));
      Simulator::Schedule (jitter, &RoutingProtocol::SendTo, this, socket, packet, destination);
    }
}

void
RoutingProtocol::SendPacketFromQueue (Ipv4Address dst, Ptr<Ipv4Route> route)
{
 //std::cout<<" RoutingProtocol::SendPacketFromQueue (Ipv4Address dst, Ptr<Ipv4Route> route) " <<"dst "<< dst<<std::endl;
  NS_LOG_FUNCTION (this);
  QueueEntry queueEntry;
  while (m_queue.Dequeue (dst, queueEntry))
    {
      DeferredRouteOutputTag tag;
      Ptr<Packet> p = ConstCast<Packet> (queueEntry.GetPacket ());
      if (p->RemovePacketTag (tag)
          && tag.GetInterface () != -1
          && tag.GetInterface () != m_ipv4->GetInterfaceForDevice (route->GetOutputDevice ()))
        { 
          NS_LOG_DEBUG ("Output device doesn't match. Dropped.");
          return;
        }
      UnicastForwardCallback ucb = queueEntry.GetUnicastForwardCallback ();
      Ipv4Header header = queueEntry.GetIpv4Header ();
      header.SetSource (route->GetSource ());
      header.SetTtl (header.GetTtl () + 1); // compensate extra TTL decrement by fake loopback routing    
      ucb (route, p, header);
    }
}

void
RoutingProtocol::SendRerrWhenBreaksLinkToNextHop (Ipv4Address nextHop)
{
  //std::cout<<Simulator::Now()<<"SendRerrWhenBreaksLinkToNextHop"<<std::endl;
 NS_LOG_FUNCTION (this << nextHop);
  RerrHeader rerrHeader;
  std::vector<Ipv4Address> precursors;
  std::map<Ipv4Address, uint32_t> unreachable;

  RoutingTableEntry toNextHop;
  
  /*if (!m_routingTable.LookupRoute (nextHop, toNextHop))
    {
      return;
    }
    */

  toNextHop.GetPrecursors (precursors);
  rerrHeader.AddUnDestination (nextHop, toNextHop.GetSeqNo ());

  for (uint j=0; j<m_routingTableList.size();j++){
    m_routingTableList[j].GetListOfDestinationWithNextHop (nextHop, unreachable);
    for (std::map<Ipv4Address, uint32_t>::const_iterator i = unreachable.begin (); i
       != unreachable.end (); )
      {
        if (!rerrHeader.AddUnDestination (i->first, i->second))
          {
            NS_LOG_LOGIC ("Send RERR message with maximum size.");
            TypeHeader typeHeader (MT_AODVTYPE_RERR);
            Ptr<Packet> packet = Create<Packet> ();
            SocketIpTtlTag tag;
            tag.SetTtl (1);
            packet->AddPacketTag (tag);
            packet->AddHeader (rerrHeader);
            packet->AddHeader (typeHeader);
            SendRerrMessage (packet, precursors);
            rerrHeader.Clear ();
          }
        else
          {
            RoutingTableEntry toDst;
            m_routingTable.LookupRoute (i->first, toDst);
            toDst.GetPrecursors (precursors);
            ++i;
          }
      }
    if (rerrHeader.GetDestCount () != 0)
      {
        TypeHeader typeHeader (MT_AODVTYPE_RERR);
        Ptr<Packet> packet = Create<Packet> ();
        SocketIpTtlTag tag;
        tag.SetTtl (1);
        packet->AddPacketTag (tag);
        packet->AddHeader (rerrHeader);
        packet->AddHeader (typeHeader);
        SendRerrMessage (packet, precursors);
      }
    unreachable.insert (std::make_pair (nextHop, toNextHop.GetSeqNo ()));
    m_routingTableList[j].InvalidateRoutesWithDst (unreachable);
  }
}

void
RoutingProtocol::SendRerrWhenNoRouteToForward (Ipv4Address dst,
                                               uint32_t dstSeqNo, Ipv4Address origin)
{
 //std::cout<<" RoutingProtocol::SendRerrWhenNoRouteToForward (Ipv4Address dst, uint32_t dstSeqNo, Ipv4Address origin) "<<"dst "<<dst<<" origin "<<origin<<std::endl;

 NS_LOG_FUNCTION (this);
  // A node SHOULD NOT originate more than RERR_RATELIMIT RERR messages per second.
  if (m_rerrCount == m_rerrRateLimit)
    {
      // Just make sure that the RerrRateLimit timer is running and will expire
      NS_ASSERT (m_rerrRateLimitTimer.IsRunning ());
      // discard the packet and return
      NS_LOG_LOGIC ("RerrRateLimit reached at " << Simulator::Now ().GetSeconds () << " with timer delay left "
                                                << m_rerrRateLimitTimer.GetDelayLeft ().GetSeconds ()
                                                << "; suppressing RERR");
      return;
    }
  bool achou=false;
  for (uint i=0;i<m_routingTableList.size();i++){
    RerrHeader rerrHeader;
    rerrHeader.AddUnDestination (dst, dstSeqNo);
    RoutingTableEntry toOrigin;
    Ptr<Packet> packet = Create<Packet> ();
    SocketIpTtlTag tag;
    tag.SetTtl (1);
    packet->AddPacketTag (tag);
    packet->AddHeader (rerrHeader);
    packet->AddHeader (TypeHeader (MT_AODVTYPE_RERR));
    if (m_routingTableList[i].LookupValidRoute (origin, toOrigin))
      {
        Ptr<Socket> socket = FindSocketWithInterfaceAddress (
            toOrigin.GetInterface ());
        NS_ASSERT (socket);
        NS_LOG_LOGIC ("Unicast RERR to the source of the data transmission");
        socket->SendTo (packet, 0, InetSocketAddress (toOrigin.GetNextHop (), MT_AODV_PORT));
        achou=true;
      }
    }
  if(!achou)
    {
      RerrHeader rerrHeader;
      rerrHeader.AddUnDestination (dst, dstSeqNo);
      RoutingTableEntry toOrigin;
      Ptr<Packet> packet = Create<Packet> ();
      SocketIpTtlTag tag;
      tag.SetTtl (1);
      packet->AddPacketTag (tag);
      packet->AddHeader (rerrHeader);
      packet->AddHeader (TypeHeader (MT_AODVTYPE_RERR));
      for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator i =
             m_socketAddresses.begin (); i != m_socketAddresses.end (); ++i)
        {
          Ptr<Socket> socket = i->first;
          Ipv4InterfaceAddress iface = i->second;
          NS_ASSERT (socket);
          NS_LOG_LOGIC ("Broadcast RERR message from interface " << iface.GetLocal ());
          // Send to all-hosts broadcast if on /32 addr, subnet-directed otherwise
          Ipv4Address destination;
          if (iface.GetMask () == Ipv4Mask::GetOnes ())
            {
              destination = Ipv4Address ("255.255.255.255");
            }
          else
            {
              destination = iface.GetBroadcast ();
            }
          socket->SendTo (packet->Copy (), 0, InetSocketAddress (destination, MT_AODV_PORT));
        }
    }
}

void
RoutingProtocol::SendRerrMessage (Ptr<Packet> packet, std::vector<Ipv4Address> precursors)
{
 //std::cout<<" RoutingProtocol::SendRerrMessage (Ptr<Packet> packet, std::vector<Ipv4Address> precursors) "<<std::endl;

  NS_LOG_FUNCTION (this);

  if (precursors.empty ())
    {
      NS_LOG_LOGIC ("No precursors");
      //std::cout<<"No precursors 3214"<<std::endl;
       return;
    }
  // A node SHOULD NOT originate more than RERR_RATELIMIT RERR messages per second.
  if (m_rerrCount == m_rerrRateLimit)
    {
      // Just make sure that the RerrRateLimit timer is running and will expire
      NS_ASSERT (m_rerrRateLimitTimer.IsRunning ());
      // discard the packet and return
      NS_LOG_LOGIC ("RerrRateLimit reached at " << Simulator::Now ().GetSeconds () << " with timer delay left "
                                                << m_rerrRateLimitTimer.GetDelayLeft ().GetSeconds ()
                                                << "; suppressing RERR");
      //std::cout<<"ratelimit 3227"<<std::endl;

      return;
    }
  // If there is only one precursor, RERR SHOULD be unicast toward that precursor
  if (precursors.size () == 1)
    {
      RoutingTableEntry toPrecursor;
      for (uint j=0;j<m_routingTableList.size();j++){
        if (m_routingTableList[j].LookupValidRoute (precursors.front (), toPrecursor))
        { 
          Ptr<Socket> socket = FindSocketWithInterfaceAddress (toPrecursor.GetInterface ());
          NS_ASSERT (socket);
          NS_LOG_LOGIC ("one precursor => unicast RERR to " << toPrecursor.GetDestination () << " from " << toPrecursor.GetInterface ().GetLocal ());
          //std::cout<<"SendTo 3241"<<std::endl;
          
          Simulator::Schedule (Time (MilliSeconds (m_uniformRandomVariable->GetInteger (0, 10))), &RoutingProtocol::SendTo, this, socket, packet, precursors.front ());
          m_rerrCount++;
        }
      
    }
    return;
  }

  //  Should only transmit RERR on those interfaces which have precursor nodes for the broken route
  for (uint j=0;j<m_routingTableList.size();j++){
    std::vector<Ipv4InterfaceAddress> ifaces;
    RoutingTableEntry toPrecursor;
    for (std::vector<Ipv4Address>::const_iterator i = precursors.begin (); i != precursors.end (); ++i)
      {
        if (m_routingTableList[j].LookupValidRoute (*i, toPrecursor)
          && std::find (ifaces.begin (), ifaces.end (), toPrecursor.GetInterface ()) == ifaces.end ())
        {
          ifaces.push_back (toPrecursor.GetInterface ());
        }
    }

    for (std::vector<Ipv4InterfaceAddress>::const_iterator i = ifaces.begin (); i != ifaces.end (); ++i)
    {
      Ptr<Socket> socket = FindSocketWithInterfaceAddress (*i);
      NS_ASSERT (socket);
      NS_LOG_LOGIC ("Broadcast RERR message from interface " << i->GetLocal ());
      //std::cout << "Broadcast RERR message from interface " << i->GetLocal () << std::endl;
      // Send to all-hosts broadcast if on /32 addr, subnet-directed otherwise
      Ptr<Packet> p = packet->Copy ();
      Ipv4Address destination;
      if (i->GetMask () == Ipv4Mask::GetOnes ())
        {
          destination = Ipv4Address ("255.255.255.255");
        }
      else
        {
          destination = i->GetBroadcast ();
        }
      //std::cout<<"SendTo 3280"<<std::endl;

      Simulator::Schedule (Time (MilliSeconds (m_uniformRandomVariable->GetInteger (0, 10))), &RoutingProtocol::SendTo, this, socket, p, destination);
    }

  }
}

Ptr<Socket>
RoutingProtocol::FindSocketWithInterfaceAddress (Ipv4InterfaceAddress addr ) const
{
  //std::cout<<" RoutingProtocol::FindSocketWithInterfaceAddress (Ipv4InterfaceAddress addr ) const "<<"addr "<<addr<<std::endl;

  NS_LOG_FUNCTION (this << addr);
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j =
         m_socketAddresses.begin (); j != m_socketAddresses.end (); ++j)
    {
      Ptr<Socket> socket = j->first;
      Ipv4InterfaceAddress iface = j->second;
      if (iface == addr)
        {
          return socket;
        }
    }
  Ptr<Socket> socket;
  return socket;
}

Ptr<Socket>
RoutingProtocol::FindSubnetBroadcastSocketWithInterfaceAddress (Ipv4InterfaceAddress addr ) const
{
  //std::cout<<" FindSubnetBroadcastSocketWithInterfaceAddress "<<std::endl;

  NS_LOG_FUNCTION (this << addr);
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j =
         m_socketSubnetBroadcastAddresses.begin (); j != m_socketSubnetBroadcastAddresses.end (); ++j)
    {
      Ptr<Socket> socket = j->first;
      Ipv4InterfaceAddress iface = j->second;
      if (iface == addr)
        {
          return socket;
        }
    }
  Ptr<Socket> socket;
  return socket;
}

void
RoutingProtocol::DoInitialize (void)
{
  //std::cout<<" RoutingProtocol::DoInitialize (void) - Inicia as interfaces "<<std::endl;

  NS_LOG_FUNCTION (this);
  /*uint32_t startTime;
  if (m_enableHello)
    {
      m_htimer.SetFunction (&RoutingProtocol::HelloTimerExpire, this);
      startTime = m_uniformRandomVariable->GetInteger (0, 100);
      NS_LOG_DEBUG ("Starting at time " << startTime << "ms");
      m_htimer.Schedule (MilliSeconds (startTime));
    }*/
  Ipv4RoutingProtocol::DoInitialize ();
}

} //namespace mt_aodv
} //namespace ns3
