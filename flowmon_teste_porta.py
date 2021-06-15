from xml.etree import ElementTree as ET
import sys
import matplotlib.pyplot as pylab
import numpy as np
et=ET.parse(sys.argv[1])
bitrates=[]
losses=[]
delays=[]
RxPackets =[]
TxPackets = []

for flow in et.findall("FlowStats/Flow"):
	for tpl in et.findall("Ipv4FlowClassifier/Flow"):
		if tpl.get('flowId')==flow.get('flowId'):
			break
	if tpl.get('destinationPort')=='9':
		
		losses.append(int(flow.get('lostPackets')))
		rxPackets=int(flow.get('rxPackets'))
		RxPackets.append(rxPackets)
		TxPackets.append(int(flow.get('txPackets')))

		if rxPackets==0:
			bitrates.append(0)
		else:
			t0=float(flow.get('timeFirstTxPacket')[:-2])
			t1=float(flow.get("timeLastRxPacket")[:-2])
			duration=(t1-t0)*1024e-9
			bitrates.append(long(flow.get("rxPackets"))*256*8/duration)
			#print bitrates
			delays.append(float(flow.get('delaySum')[:-2])*1e-9/rxPackets)



SumTxPackets = float(np.sum(TxPackets))
SumRxPackets = float(np.sum(RxPackets))
SumLossPackets = float(np.sum(losses))


print "-------------"
print sys.argv[1]
print "TxPackets Total =", int(SumTxPackets)
print "RxPackets Total =", int(SumRxPackets)
print "PacketsLoss Total =", int(SumLossPackets)
print "% Average Delivery Packets Rate =", round(SumRxPackets/SumTxPackets*100,2), "%"
print "% PacketsLoss =", round(SumLossPackets/SumTxPackets*100,2), "%"
print "Throughput =", round(np.mean(bitrates),2), "Kbps"
print "Average Delay = ", round(np.mean(delays)*1000,3), "ms"

resultados = [sys.argv[1],int(SumTxPackets),int(SumRxPackets),int(SumLossPackets),round(SumRxPackets/SumTxPackets*100,2),round(SumLossPackets/SumTxPackets*100,2),round(np.mean(bitrates),2),round(np.mean(delays)*1000,3)]
print resultados
f=open("resultados.txt","a")
f.write(str(resultados)+"\n")
