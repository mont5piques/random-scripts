#!/usr/bin/python
import pcap
import libvirt
import commands

vm_macs = {}
vms = commands.getoutput("virsh list --all|awk '{print $2}'|grep -v 'Name'").split('\n')

for vm in vms:
    if not vm:
        continue
    mac = commands.getoutput("virsh domiflist %s|head -n3|tail -n1|awk '{print $5}'" % vm)
    vm_macs[mac] = vm


def toHex(s):
    lst = []
    for ch in s:
        hv = hex(ord(ch)).replace('0x', '')
        if len(hv) == 1:
            hv = '0'+hv
        lst.append(hv)

    return reduce(lambda x,y:x+y, lst)

def analyze(id, data, timestamp):
    strdata = toHex(data)
    for mac, vm in vm_macs.iteritems():
        # Skip nytrio vm
        if vm == 'NDEMO_NYTRIO':
            continue
        if mac.replace(':', '') in strdata:
            commands.getoutput('virsh start %s' % vm)


if __name__ == '__main__':
    interface = 'virbr1'
    p = pcap.pcapObject()
    net, mask = pcap.lookupnet(interface)
    p.open_live(interface, 1600, 0, 100)
    p.setfilter('udp and port 7 or port 9', 0, 0)

    try:
        while 1:
            p.dispatch(1, analyze)
    except KeyboardInterrupt:
        pass
