import socket
import sys
import struct

if len(sys.argv) == 1:
  out = sys.stdout
else:
  try:
    out = open(sys.argv[1], 'x')
  except FileExistsError:
    out = open(sys.argv[1], 'w')

ifaces = {}

# windows interface listing
if sys.platform.startswith('win'):
  import subprocess
  netsh = subprocess.run('netsh interface ipv4 show addresses', capture_output=True, text=True)
  netsh = netsh.stdout.split('\n\n')[:-1]
  for item in netsh:
    lines = item.split('\n')[1:]
    name = item.split('"')[1]
    ip = -1
    for entry in lines:
      if entry.find('IP Address') != -1:
        ip = entry.split(':')[1].strip()
    if ip != -1:
      ifaces[name] = ip
# linux interface listing
if sys.platform.startswith('linux'):
  import array
  import fcntl
  MAX_BYTES = 4096
  FILL_CHAR = b'\0'
  SIOCGIFCONF = 0x8912
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  names = array.array('B', MAX_BYTES*FILL_CHAR)
  n_addr, _ = names.buffer_info()
  mut = struct.pack('iL', MAX_BYTES, n_addr)
  fcntl.ioctl(sock.fileno(), SIOCGIFCONF, mut)
  bytes, _ = struct.unpack('iL', mut)
  n_bytes = names.tobytes()[:bytes]
  for i in range(0, bytes, 40):
    name = n_bytes[i:i+16].split(FILL_CHAR, 1)[0].decode('utf-8')
    ip_bytes = n_bytes[i+20:i+24]
    full_addr = '.'.join([str(ip) if isinstance(ip, int) else str(ord(ip)) for ip in ip_bytes])
    if name != '':
      ifaces[name] = full_addr
  sock.close()

print("Interfaces")
iface_idx = {}
length = 0
for idx,name in enumerate(ifaces.keys()):
  print(idx+1, name)
  iface_idx[idx] = name
  length+=1

try:
  iface_select = int(input(f'[1-{length}]: '))
  iface_select = iface_idx[iface_select-1]
  ip = ifaces[iface_select]
except KeyError:
  exit(1)

packets = ['TCP', 'UDP', 'ICMP']
packets_idx = {}
length = 0
print('Packet Types')
for idx,name in enumerate(packets):
  print(idx+1, name)
  packets_idx[idx] = name
  length += 1

packets_select = packets
try:
  packets_select = list(map(lambda x: packets_idx[int(x)-1],input(f'[1-{length}]: ').split(',')))
except KeyError:
  pass

sock = socket.socket(socket.AF_INET, socket.SOCK_RAW)
sock.bind((ip, 0))
sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
while True:
  data, _ = sock.recvfrom(65535)
  # IP packet
  ver_ihl, total_len, ttl, proto, src, dest = struct.unpack('! B 1x h 4x B B 2x 4s 4s', data[:20])
  ver_ihl = ver_ihl
  ihl = (ver_ihl & 0b1111) * 4
  ver = ver_ihl >> 4
  if proto == 1:
    proto_name = 'ICMP'
    icmp_type, icmp_code = struct.unpack('! B B', data[ihl:ihl+2])
    if icmp_type == 0: icmp_type_name = "Echo Reply"
    elif icmp_type == 3: icmp_type_name = "Destination Unreachable"
    elif icmp_type == 4: icmp_type_name = "Source Quench"
    elif icmp_type == 5: icmp_type_name = "Redirect Message"
    elif icmp_type == 8: icmp_type_name = "Echo Request"
    elif icmp_type == 9: icmp_type_name = "Router Advertisement"
    elif icmp_type == 10: icmp_type_name = "Router Solicitation"
    elif icmp_type == 11: icmp_type_name = "Time Exceeded"
    elif icmp_type == 12: icmp_type_name = "Parameter Problem: Bad IP header"
    elif icmp_type == 13: icmp_type_name = "Timestamp"
    elif icmp_type == 14: icmp_type_name = "Timestamp Reply"
    elif icmp_type == 15: icmp_type_name = "Information Request"
    elif icmp_type == 16: icmp_type_name = "Information Reply"
    elif icmp_type == 17: icmp_type_name = "Address Mask Request"
    elif icmp_type == 18: icmp_type_name = "Address Mask Reply"
    elif icmp_type == 30: icmp_type_name = "Traceroute"
    elif icmp_type == 42: icmp_type_name = "Extended Echo Request"
    elif icmp_type == 43: icmp_type_name = "Extended Echo Reply"
  elif proto == 6:
    proto_name = 'TCP'
    reserved_flag, = struct.unpack('! 8x H 6x', data[ihl:ihl+16])
    flags = reserved_flag>>7
    flags_active = []
    if flags & 1: flags_active.append('NS')
    if flags & 2: flags_active.append('CWR')
    if flags & 4: flags_active.append('ECE')
    if flags & 8: flags_active.append('URG')
    if flags & 16: flags_active.append('ACK')
    if flags & 32: flags_active.append('PSH')
    if flags & 64: flags_active.append('RST')
    if flags & 128: flags_active.append('SYN')
    if flags & 256: flags_active.append('FIN')
    flags_active = ' '.join(flags_active)
  elif proto == 17: proto_name = 'UDP'
  else: continue
  if proto_name not in packets_select: continue
  print('--------------')
  print(f'Header Length: {ihl} bytes', file=out)
  print(f'Total Length: {total_len} bytes', file=out)
  print(f'Data Length: {total_len-ihl} bytes', file=out)
  dot_ip_src = '.'.join(map(str, src))
  print(f'protocol: {proto_name}', file=out)
  if proto_name == 'TCP':
    print(f'flags: {flags_active}', file=out)
  if proto_name == 'ICMP':
    print(f'ICMP type: {icmp_type_name}')
  print(f'source IP: {dot_ip_src}', file=out)
  print(f'TTL: {ttl}', file=out)
  print('--------------')