#!/usr/bin/env bash
# Uso: scripts/make_input.sh [segundos] [salida]
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -x "./target/release/pqav-verify" ] || [ ! -f "testdata/firmado.ts" ]; then
    echo "Error: ejecuta antes scripts/run_tests.sh"
    exit 2
fi

if [ ! -f "testdata/solo_video_firmado.ts" ] || [ ! -f "results/solo_video_firmado_stats.json" ]; then
    scripts/sign.sh testdata/fuente.seed testdata/solo_video.ts testdata/solo_video_firmado.ts
fi

tsp -I file testdata/firmado.ts -P analyze -O drop > results/firmado_analyze.txt
tsp -I file testdata/solo_video_firmado.ts -P analyze -O drop > results/solo_video_firmado_analyze.txt

for i in {1..5}; do
    /usr/bin/time -v ./target/release/pqav-verify --pub testdata/fuente.pub --in testdata/firmado.ts --quiet > /dev/null 2> "results/verify_time_$i.txt"
done

python3 << 'EOF'
import json
import statistics
import re
import sys

tiempos = []
memoria_max = 0

for i in range(1, 6):
    with open(f"results/verify_time_{i}.txt") as f:
        texto = f.read()
        m_time = re.search(r'm:ss\):\s*(?:(\d+):)?(\d+):(\d+\.\d+)', texto)
        if m_time:
            h = int(m_time.group(1)) if m_time.group(1) else 0
            m = int(m_time.group(2))
            s = float(m_time.group(3))
            tiempos.append(h * 3600 + m * 60 + s)

        m_mem = re.search(r'Maximum resident set size \(kbytes\):\s*(\d+)', texto)
        if m_mem:
            memoria_max = max(memoria_max, int(m_mem.group(1)))

if not tiempos:
    print("Error: No se han podido extraer los tiempos.")
    sys.exit(1)

mediana_s = statistics.median(tiempos)

with open("results/verify_time.txt", "w") as f:
    f.write("Tiempos (s): " + ", ".join(f"{t:.2f}" for t in tiempos) + "\n")
    f.write(f"Mediana (s): {mediana_s:.2f}\n")
    f.write(f"Memoria max (KB): {memoria_max}\n")

try:
    f_stats = json.load(open("results/firmado_stats.json"))
    sv_stats = json.load(open("results/solo_video_firmado_stats.json"))
    p1_stats = json.load(open("results/P1.json"))
except Exception as e:
    print(f"Error cargando JSONs: {e}")
    sys.exit(1)

m1_media = f_stats["cose_bytes"]["mean"]
m1_min = f_stats["cose_bytes"]["min"]
m1_max = f_stats["cose_bytes"]["max"]

m2_sv = sv_stats["cose_bytes"]["mean"] / 6.0
m2_a = f_stats["cose_bytes"]["mean"] / 6.0
m3 = (f_stats["ts_packets_per_anchor"]["mean"] * 188) / 6.0

pkts_1ff0 = f_stats["null_packets_used"] + f_stats["appended_packets"]
duracion = (f_stats["input_packets"] * 1504) / 8000000.0
m4 = ((pkts_1ff0 * 1504) / duracion) / 1000.0 
m5 = m2_a - m2_sv

with open("results/medidas.csv", "w") as out:
    out.write("id,valor,unidad,estado,fichero\n")
    out.write(f"M1_media,{m1_media:.2f},B,M,results/firmado_stats.json\n")
    out.write(f"M1_min,{m1_min},B,M,results/firmado_stats.json\n")
    out.write(f"M1_max,{m1_max},B,M,results/firmado_stats.json\n")
    out.write(f"M2_solo_video,{m2_sv:.2f},B/frame,M,results/solo_video_firmado_stats.json\n")
    out.write(f"M2_con_audio,{m2_a:.2f},B/frame,M,results/firmado_stats.json\n")
    out.write(f"M3,{m3:.2f},B/frame,M,results/firmado_stats.json\n")
    out.write(f"M4,{m4:.2f},kb/s,M,testdata/firmado.ts\n")
    out.write(f"M5,{m5:.2f},B/frame,M,results/firmado_stats.json y results/solo_video_firmado_stats.json\n")
    out.write(f"M6_p50,{f_stats['insert_delay_ms']['p50']:.2f},ms,M,results/firmado_stats.json\n")
    out.write(f"M6_p99,{f_stats['insert_delay_ms']['p99']:.2f},ms,M,results/firmado_stats.json\n")
    out.write(f"M7_p50,{f_stats['sign_us']['p50']},us,M,results/firmado_stats.json\n")
    out.write(f"M7_p99,{f_stats['sign_us']['p99']},us,M,results/firmado_stats.json\n")
    out.write(f"M8_p50,{p1_stats['verify_us']['p50']},us,M,results/P1.json\n")
    out.write(f"M8_p99,{p1_stats['verify_us']['p99']},us,M,results/P1.json\n")
    out.write(f"M9,{mediana_s:.2f},s,M,results/verify_time.txt\n")
    out.write(f"M10,{f_stats['appended_packets']},paquetes,M,results/firmado_stats.json\n")
EOF

{
    lscpu | grep "Model name" || true
    echo "$(nproc) hilos"
    free -h | grep Mem || true
    uname -sr
    rustc --version
    echo "compilado con cargo build --release"
} > results/maquina.txt

cat results/medidas.csv
