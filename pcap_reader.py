import pyshark

def read_all_packets(self, filepath):
    packets = []
    try:
        cap = pyshark.FileCapture(filepath, keep_packets=False)
        for pkt in cap:
            ip_src = pkt.ip.src if hasattr(pkt, 'ip') and hasattr(pkt.ip, 'src') else 'N/A'
            ip_dst = pkt.ip.dst if hasattr(pkt, 'ip') and hasattr(pkt.ip, 'dst') else 'N/A'

            tcp_flags = "N/A"
            if hasattr(pkt, 'tcp'):
                flags = getattr(pkt.tcp, 'flags_str', '')
                tcp_flags = flags if flags else "N/A"

            packets.append({
                'number': pkt.number,
                'time': pkt.sniff_time.strftime('%H:%M:%S.%f')[:-3],
                'proto': pkt.highest_layer,
                'length': pkt.length,
                'ip_src': ip_src,
                'ip_dst': ip_dst,
                'tcp_flags': tcp_flags
            })
        cap.close()
    except Exception as e:
        print(f"[ERROR] Excepción leyendo archivo '{filepath}': {e}")
    return packets
