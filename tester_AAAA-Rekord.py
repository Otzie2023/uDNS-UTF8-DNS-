import socket
import struct
import ipaddress
import binascii

# DNS-Server und Domain
dns_server = '127.0.0.1'
dns_port = 1025
domain = 'ä.dkr'

# --- DNS Header ---
transaction_id = 0x1234  # zufällige Transaktions-ID
flags = 0x0100           # Standard Query, Rekursion gewünscht
qdcount = 1              # 1 Frage
ancount = 0
nscount = 0
arcount = 0

header = struct.pack('>HHHHHH', transaction_id, flags, qdcount, ancount, nscount, arcount)

# --- Domainname in DNS-Format kodieren ---
def encode_domain(domain):
    parts = domain.split('.')
    encoded = b''
    for part in parts:
        # UTF-8 kodieren und Länge davor setzen
        part_bytes = part.encode('utf-8')
        encoded += struct.pack('B', len(part_bytes)) + part_bytes
    encoded += b'\x00'  # Ende des Namens
    return encoded

qname = encode_domain(domain)

# --- Fragebereich ---
QTYPE = 28   # AAAA-Record (statt 1 für A)
QCLASS = 1   # IN (Internet)
question = qname + struct.pack('>HH', QTYPE, QCLASS)

# --- DNS Anfrage zusammensetzen ---
dns_request = header + question

# --- Anfrage senden ---
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(dns_request, (dns_server, dns_port))
print(f"sending: sock.sendto({dns_request}, ({dns_server}, {dns_port}))")

# Antwort empfangen
response, _ = sock.recvfrom(4096)
print("Antwort (raw bytes):", response)
sock.close()

# ---------------------------
# UTF-8 DNS-Antwort-Parser
# ---------------------------

def parse_name(data: bytes, offset: int):
    """
    Parse a domain name from `data` starting at `offset`.
    Handles pointer compression. Returns (name_str, next_offset).
    Name labels decoded with utf-8 (errors='replace').
    """
    labels = []
    orig_offset = offset
    jumped = False
    max_jumps = 50  # safety
    jumps = 0

    while True:
        if offset >= len(data):
            # malformed
            return ("<truncated>", offset + 1)

        length = data[offset]
        # pointer?
        if (length & 0xC0) == 0xC0:
            # two byte pointer
            if offset + 1 >= len(data):
                return ("<truncated-pointer>", offset + 2)
            pointer = struct.unpack('>H', data[offset:offset+2])[0] & 0x3FFF
            if jumps > max_jumps:
                return ("<too-many-pointers>", offset+2)
            jumps += 1
            # follow pointer (but only advance original offset by 2)
            if not jumped:
                next_offset = offset + 2
                jumped = True
            offset = pointer
            continue
        elif length == 0:
            # end of name
            if not jumped:
                next_offset = offset + 1
            break
        else:
            offset += 1
            if offset + length > len(data):
                # truncated label
                label_bytes = data[offset:len(data)]
                offset = len(data)
            else:
                label_bytes = data[offset:offset+length]
                offset += length
            try:
                label = label_bytes.decode('utf-8', errors='replace')
            except Exception:
                label = label_bytes.decode('utf-8', errors='replace')
            labels.append(label)
    # join with dots; empty name becomes '.'
    name = ".".join(labels) if labels else "."
    return (name, next_offset)

def hexify(b: bytes):
    return binascii.hexlify(b).decode('ascii')

def parse_dns_response(data: bytes) -> str:
    """
    Parse the DNS response bytes and return a human-readable UTF-8 text.
    Keeps `data` unchanged.
    """
    out_lines = []
    if len(data) < 12:
        return "Antwort zu kurz (<12 bytes)\n"

    (tid, flags, qdcount, ancount, nscount, arcount) = struct.unpack('>HHHHHH', data[:12])
    out_lines.append(f"Transaction ID: 0x{tid:04x}")
    out_lines.append(f"Flags: 0x{flags:04x} ({flags:016b})")
    out_lines.append(f"QDCOUNT: {qdcount}, ANCOUNT: {ancount}, NSCOUNT: {nscount}, ARCOUNT: {arcount}")
    out_lines.append("")

    offset = 12

    # Fragen
    out_lines.append(";; QUESTION SECTION:")
    for i in range(qdcount):
        name, offset = parse_name(data, offset)
        if offset + 4 > len(data):
            out_lines.append(f"  {name} <malformed question>")
            break
        qtype, qclass = struct.unpack('>HH', data[offset:offset+4])
        offset += 4
        out_lines.append(f"  {name}\tTYPE {qtype}\tCLASS {qclass}")
    out_lines.append("")

    def parse_rr_section(count, section_name, offset):
        lines = []
        for i in range(count):
            if offset >= len(data):
                lines.append(f"  <truncated {section_name} at entry {i}>")
                return lines, offset
            rr_name, offset = parse_name(data, offset)
            if offset + 10 > len(data):
                lines.append(f"  {rr_name}\t<malformed RR header>")
                return lines, len(data)
            rtype, rclass, ttl, rdlength = struct.unpack('>HHIH', data[offset:offset+10])
            offset += 10
            if offset + rdlength > len(data):
                rdata = data[offset:len(data)]
                offset = len(data)
            else:
                rdata = data[offset:offset+rdlength]
                offset += rdlength

            # Interpret rdata based on type
            rdata_str = ""
            try:
                if rtype == 1 and rdlength == 4:  # A
                    rdata_str = socket.inet_ntoa(rdata)
                elif rtype == 28 and rdlength == 16:  # AAAA
                    rdata_str = str(ipaddress.IPv6Address(rdata))
                elif rtype in (2, 5, 12):  # NS(2), CNAME(5), PTR(12) - domain names (may use pointers)
                    name2, _ = parse_name(data, offset - rdlength)
                    rdata_str = name2
                elif rtype == 16:  # TXT
                    # TXT is a sequence of length-prefixed strings
                    txts = []
                    idx = 0
                    while idx < len(rdata):
                        length = rdata[idx]
                        idx += 1
                        txts.append(rdata[idx:idx+length].decode('utf-8', errors='replace'))
                        idx += length
                    rdata_str = " ".join(f'"{t}"' for t in txts)
                else:
                    # Default: show hex and also attempt to decode as utf-8 (safe)
                    try:
                        rdata_str = rdata.decode('utf-8', errors='replace')
                    except Exception:
                        rdata_str = hexify(rdata)
                    # also include hex for clarity if non-printable
                    if any(c < 32 or c > 126 for c in rdata):
                        rdata_str += f" (hex: {hexify(rdata)})"
            except Exception as e:
                rdata_str = f"<error decoding rdata: {e}> (hex: {hexify(rdata)})"

            lines.append(f"  {rr_name}\tTYPE {rtype}\tCLASS {rclass}\tTTL {ttl}\tRDLENGTH {rdlength}\tRDATA {rdata_str}")
        return lines, offset

    # ANS
    out_lines.append(";; ANSWER SECTION:")
    ans_lines, offset = parse_rr_section(ancount, "ANSWER", offset)
    out_lines.extend(ans_lines)
    out_lines.append("")

    # AUTHORITY
    out_lines.append(";; AUTHORITY SECTION:")
    auth_lines, offset = parse_rr_section(nscount, "AUTHORITY", offset)
    out_lines.extend(auth_lines)
    out_lines.append("")

    # ADDITIONAL
    out_lines.append(";; ADDITIONAL SECTION:")
    add_lines, offset = parse_rr_section(arcount, "ADDITIONAL", offset)
    out_lines.extend(add_lines)
    out_lines.append("")

    # Raw dump (hex) for reference
    out_lines.append(";; RAW (hex) of response head 64 bytes (for reference):")
    out_lines.append(hexify(data[:64]) + ("..." if len(data) > 64 else ""))
    out_lines.append("")
    return "\n".join(out_lines)

# Erzeuge den parsed_text (UTF-8 lesbar) ohne `response` zu verändern
parsed_text = parse_dns_response(response)

# Ausgabe
print("\n----- PARSED (UTF-8) -----\n")
print(parsed_text)
