#!/usr/bin/env python3
import sys
import argparse

def leer_ts(ruta):
    try:
        with open(ruta, "rb") as f:
            buf = bytearray(f.read())
    except Exception as e:
        print(f"error al leer {ruta}: {e}")
        sys.exit(2)
    if len(buf) % 188 != 0:
        print(f"error: {ruta} no mide un múltiplo de 188 bytes")
        sys.exit(2)
    for i in range(0, len(buf), 188):
        if buf[i] != 0x47:
            print(f"error: paquete sin sincronía en pos {i}")
            sys.exit(2)
    return buf

def paquete(buf, n):
    pos = n * 188
    pid = ((buf[pos+1] & 0x1F) << 8) | buf[pos+2]
    pusi = bool(buf[pos+1] & 0x40)
    afc = (buf[pos+3] >> 4) & 0x03
    inicio = 4
    if afc in (2, 3):
        inicio = 5 + buf[pos+4]
    if inicio > 188 or afc in (0, 2):
        return pid, pusi, 188
    return pid, pusi, inicio

def montar_pes(buf, pid_buscado):
    pes_list = []
    actual = None
    for n in range(len(buf) // 188):
        pid, pusi, inicio = paquete(buf, n)
        if pid == pid_buscado:
            if pusi:
                if actual is not None:
                    pes_list.append(actual)
                actual = []
            if actual is not None and inicio < 188:
                actual.append((n * 188 + inicio, 188 - inicio))
    if actual is not None:
        pes_list.append(actual)
    return pes_list

def es_bytes(buf, pes):
    out = bytearray()
    for pos, long in pes:
        out.extend(buf[pos:pos+long])
    return out

def posicion(pes, i):
    for pos, long in pes:
        if i < long:
            return pos + i
        i -= long
    return -1

def datos_pes(b):
    if len(b) < 9: return 0
    return 9 + b[8]

def tramas_adts(b, inicio):
    tramas = []
    pos = inicio
    while pos + 7 <= len(b):
        if ((b[pos] << 4) | (b[pos+1] >> 4)) != 0xFFF:
            break
        protection_absent = b[pos+1] & 0x01
        hdr_len = 7 if protection_absent == 1 else 9
        frame_length = ((b[pos+3] & 0x03) << 11) | (b[pos+4] << 3) | (b[pos+5] >> 5)

        if frame_length < hdr_len or pos + frame_length > len(b):
            break

        tramas.append((pos, frame_length, hdr_len))
        pos += frame_length
    return tramas

def cambiar(buf, pos, vigilar_inicio):
    buf[pos] ^= 0xFF
    if vigilar_inicio:
        inicio_ventana = max(0, pos - 2)
        fin_ventana = min(len(buf) - 2, pos + 1)
        for i in range(inicio_ventana, fin_ventana):
            if buf[i] == 0x00 and buf[i+1] == 0x00 and buf[i+2] <= 0x03:
                buf[pos] ^= 0xFF
                return False
    return True

def sub_audio(args):
    print("no implementado", file=sys.stderr)
    return 1

def sub_video(args):
    print("no implementado", file=sys.stderr)
    return 1

def sub_anchor_sig(args):
    print("no implementado", file=sys.stderr)
    return 1

def sub_compare(args):
    try:
        buf1 = leer_ts(args.in_ts)
        buf2 = leer_ts(args.other_ts)
    except SystemExit:
        sys.exit(2)

    n1 = len(buf1) // 188
    n2 = len(buf2) // 188
    min_n = min(n1, n2)

    iguales = 0
    distintos = {}

    for n in range(min_n):
        p1 = buf1[n*188 : (n+1)*188]
        p2 = buf2[n*188 : (n+1)*188]
        if p1 == p2:
            iguales += 1
        else:
            pid1 = ((p1[1] & 0x1F) << 8) | p1[2]
            pid2 = ((p2[1] & 0x1F) << 8) | p2[2]
            k = (pid1, pid2)
            distintos[k] = distintos.get(k, 0) + 1

    print(f"paquetes: in={n1} other={n2}")
    print(f"iguales: {iguales}")

    if distintos:
        print("distintos (PID en in -> PID en other):")
        for (pid1, pid2) in sorted(distintos.keys()):
            print(f"  0x{pid1:04X} -> 0x{pid2:04X}: {distintos[(pid1, pid2)]}")

    if n1 != n2:
        solo_en = "other" if n2 > n1 else "in"
        buf_extra = buf2 if n2 > n1 else buf1
        start = min_n
        end = max(n1, n2)

        extra = {}
        for n in range(start, end):
            p = buf_extra[n*188 : (n+1)*188]
            pid = ((p[1] & 0x1F) << 8) | p[2]
            extra[pid] = extra.get(pid, 0) + 1

        parts = [f"0x{pid:04X}: {count}" for pid, count in sorted(extra.items())]
        print(f"solo en {solo_en}: {end - start} ({', '.join(parts)})")

    return 0

def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="cmd", required=True)

    p_aud = subparsers.add_parser("audio")
    p_aud.add_argument("--in", dest="in_ts", required=True)
    p_aud.add_argument("--out", dest="out_ts", required=True)
    p_aud.add_argument("--from-frame", type=int, required=True)
    p_aud.add_argument("--count", type=int, required=True)
    p_aud.add_argument("--pid", default="0x0101")

    p_vid = subparsers.add_parser("video")
    p_vid.add_argument("--in", dest="in_ts", required=True)
    p_vid.add_argument("--out", dest="out_ts", required=True)
    p_vid.add_argument("--au", type=int, required=True)
    p_vid.add_argument("--pid", default="0x0100")

    p_anc = subparsers.add_parser("anchor-sig")
    p_anc.add_argument("--in", dest="in_ts", required=True)
    p_anc.add_argument("--out", dest="out_ts", required=True)
    p_anc.add_argument("--anchor", type=int, required=True)
    p_anc.add_argument("--pid", default="0x1FF0")

    p_cmp = subparsers.add_parser("compare")
    p_cmp.add_argument("--in", dest="in_ts", required=True)
    p_cmp.add_argument("--other", dest="other_ts", required=True)

    args = parser.parse_args()

    if args.cmd == "audio": sys.exit(sub_audio(args))
    elif args.cmd == "video": sys.exit(sub_video(args))
    elif args.cmd == "anchor-sig": sys.exit(sub_anchor_sig(args))
    elif args.cmd == "compare": sys.exit(sub_compare(args))

if __name__ == "__main__":
    main()
