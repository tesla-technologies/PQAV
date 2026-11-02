#!/usr/bin/env bash
# Uso: scripts/run_tests.sh
set -euo pipefail
cd "$(dirname "$0")/.."

BIN=./target/release
CSV=results/tests.csv
TOTAL=0
PASAN=0

necesita() {
    if ! command -v "$1" > /dev/null; then
        echo "falta $1"
        exit 2
    fi
}

preparar() {
    [ -f testdata/entrada.ts ] || scripts/make_input.sh 60 testdata/entrada.ts
    [ -f testdata/solo_video.ts ] || scripts/make_input.sh 60 testdata/solo_video.ts
    [ -f testdata/fuente.pub ] || "$BIN/pqav-keygen" --out testdata/fuente
    [ -f testdata/otra.pub ] || "$BIN/pqav-keygen" --out testdata/otra

    scripts/sign.sh testdata/fuente.seed testdata/entrada.ts testdata/firmado.ts
    scripts/sign.sh testdata/fuente.seed testdata/entrada.ts testdata/firmado_b.ts
    scripts/sign.sh testdata/fuente.seed testdata/solo_video.ts testdata/solo_video_firmado.ts

    python3 scripts/ts_tamper.py compare --in testdata/firmado.ts --other testdata/firmado_b.ts > results/p8_previo.txt
    if grep -q "solo en" results/p8_previo.txt || grep -q -v "0x1FF0 -> 0x1FF0" results/p8_previo.txt; then
        echo "AVISO: firmado.ts y firmado_b.ts difieren en algo más que las firmas. P8 podría no ser válida."
    fi
}

verificar() {
    local id="$1"
    local fichero="$2"
    shift 2
    local pub="${PUB:-testdata/fuente.pub}"
    RC=0
    "$BIN/pqav-verify" --pub "$pub" --json "results/$id.json" --quiet --in "$fichero" "$@" > "results/$id.txt" || RC=$?
}

leer_json() {
    python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("global","") + "|" + ";".join(d.get("reasons",[])))' "results/$1.json"
}

detalle() {
    python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("si" if eval(sys.argv[2]) else "no")' "results/$1.json" "$2"
}

anotar() {
    local id="$1" desc="$2" exp_glob="$3" exp_code="$4" modo="$5" exp_motivos="$6" expr_det="$7" obt_glob="$8" obt_code="$9" obt_motivos="${10}"
    local eval_det="n/a"
    local pasa="no"

    if [ "$expr_det" != "n/a" ] && [ -f "results/$id.json" ]; then
        eval_det=$(detalle "$id" "$expr_det")
    fi

    if [ "$id" = "P4" ]; then
        pasa="n/a"
    else
        local motivos_ok="no"
        if [ "$modo" = "exacto" ] && [ "$exp_motivos" = "$obt_motivos" ]; then motivos_ok="si"; fi
        if [ "$modo" = "contiene" ] && [[ "$obt_motivos" == *"$exp_motivos"* ]]; then motivos_ok="si"; fi
        if [ "$modo" = "vacio" ] && [ -z "$obt_motivos" ]; then motivos_ok="si"; fi

        if [ "$exp_glob" = "$obt_glob" ] && [ "$exp_code" = "$obt_code" ] && [ "$motivos_ok" = "si" ]; then
            if [ "$expr_det" = "n/a" ] || [ "$eval_det" = "si" ]; then
                pasa="si"
                PASAN=$((PASAN + 1))
            fi
        fi
        TOTAL=$((TOTAL + 1))
    fi

    echo "$id,$desc,$exp_glob,$exp_code,$obt_glob,$obt_code,$obt_motivos,$pasa" >> "$CSV"
}

cortes() {
    local N H K
    N=$(($(stat -c %s testdata/firmado.ts) / 188))
    H=$((N / 2))
    K=5319

    head -c $((188 * H)) testdata/firmado.ts > testdata/p8.ts
    tail -c +$((188 * H + 1)) testdata/firmado_b.ts >> testdata/p8.ts

    head -c $((188 * H)) testdata/firmado.ts > testdata/p9.ts
    tail -c +$((188 * (H + K) + 1)) testdata/firmado.ts >> testdata/p9.ts
}

guardar() {
    local D="results/runs/$(date +%F_%H%M)_$(git rev-parse --short HEAD 2>/dev/null || echo sin-git)"
    mkdir -p "$D"
    find results -maxdepth 1 -type f -exec cp {} "$D" \;
}

#EJECUCION

for p in ffmpeg tsp python3; do necesita "$p"; done
for b in pqav-keygen pqav-sign pqav-verify; do 
    [ -x "$BIN/$b" ] || { echo "falta $BIN/$b: ejecuta cargo build --release"; exit 2; }
done

preparar

echo "id,descripcion,esperado_global,esperado_codigo,obtenido_global,obtenido_codigo,motivos,pasa" > "$CSV"

#P1
verificar P1 testdata/firmado.ts
IFS='|' read -r G M <<< "$(leer_json P1)"
anotar P1 "fichero intacto" "AUTENTICO" 0 "exacto" "" "len(d['intervals']) == 250 and d['final_anchor'] and d['unsigned_units'] == 0" "$G" "$RC" "$M"

#P2
tsp -I file testdata/firmado.ts -P remap 0x0100=0x0200 0x0101=0x0201 0x1FF0=0x1FE0 -O file testdata/p2.ts || echo "falló la preparación de P2"
verificar P2 testdata/p2.ts
IFS='|' read -r G M <<< "$(leer_json P2)"
anotar P2 "remapeo de PID" "AUTENTICO" 0 "exacto" "" "n/a" "$G" "$RC" "$M"

#P3
tsp -I file testdata/firmado.ts -P filter --negate --pid 0x1FFF -O file testdata/p3.ts || echo "falló la preparación de P3"
verificar P3 testdata/p3.ts
IFS='|' read -r G M <<< "$(leer_json P3)"
anotar P3 "quitar nulos" "AUTENTICO" 0 "exacto" "" "n/a" "$G" "$RC" "$M"

#P4
ffmpeg -hide_banner -y -i testdata/firmado.ts -map 0 -c copy -f mpegts testdata/p4.ts 2> results/P4_ffmpeg.txt || echo "falló la preparación de P4"
verificar P4 testdata/p4.ts
IFS='|' read -r G M <<< "$(leer_json P4)"
anotar P4 "ffmpeg -c copy" "n/a" "n/a" "n/a" "n/a" "n/a" "$G" "$RC" "$M"

#P5
python3 scripts/ts_tamper.py audio --in testdata/firmado.ts --out testdata/p5.ts --from-frame 1000 --count 47 || echo "falló la preparación de P5"
verificar P5 testdata/p5.ts
IFS='|' read -r G M <<< "$(leer_json P5)"
anotar P5 "audio cambiado 1 s" "RECHAZADO" 1 "exacto" "MANIPULADO" "sum(len(i['modified']) for i in d['intervals']) == 47 and all(m['comp'] == 1 for i in d['intervals'] for m in i['modified']) and 4 <= sum(i['verdict'] == 'MANIPULADO' for i in d['intervals']) <= 6" "$G" "$RC" "$M"

#P6
tsp -I file testdata/firmado.ts -P pmt --audio-language eng -O file testdata/p6.ts || echo "falló la preparación de P6"
verificar P6 testdata/p6.ts
IFS='|' read -r G M <<< "$(leer_json P6)"
anotar P6 "etiqueta idioma cambiada" "RECHAZADO" 1 "exacto" "MAPA_ALTERADO" "all(i['verdict'] == 'MAPA_ALTERADO' for i in d['intervals'])" "$G" "$RC" "$M"

#P7
python3 scripts/ts_tamper.py video --in testdata/firmado.ts --out testdata/p7.ts --au 300 || echo "falló la preparación de P7"
verificar P7 testdata/p7.ts
IFS='|' read -r G M <<< "$(leer_json P7)"
anotar P7 "un frame cambiado" "RECHAZADO" 1 "exacto" "MANIPULADO" "[i['index'] for i in d['intervals'] if i['verdict'] != 'AUTENTICO'] == [50] and d['intervals'][50]['modified'][0]['comp'] == 0" "$G" "$RC" "$M"

#P8
cortes || echo "falló la preparación de P8"
verificar P8 testdata/p8.ts
IFS='|' read -r G M <<< "$(leer_json P8)"
anotar P8 "empalme con otra sesion" "RECHAZADO" 1 "contiene" "EMPALME" "n/a" "$G" "$RC" "$M"

#P9
verificar P9 testdata/p9.ts
IFS='|' read -r G M <<< "$(leer_json P9)"
anotar P9 "un segundo borrado" "RECHAZADO" 1 "contiene" "HUECO" "n/a" "$G" "$RC" "$M"

#P10a
tsp -I file testdata/firmado.ts -P filter --negate --pid 0x1FF0 -P pmt --remove-pid 0x1FF0 -O file testdata/p10a.ts || echo "falló la preparación de P10a"
verificar P10a testdata/p10a.ts
IFS='|' read -r G M <<< "$(leer_json P10a)"
anotar P10a "firmas quitadas y PMT limpia" "SIN_FIRMAR" 3 "vacio" "" "n/a" "$G" "$RC" "$M"

#P10b
tsp -I file testdata/firmado.ts -P filter --negate --pid 0x1FF0 -O file testdata/p10b.ts || echo "falló la preparación de P10b"
verificar P10b testdata/p10b.ts
IFS='|' read -r G M <<< "$(leer_json P10b)"
anotar P10b "firmas quitadas PMT sucia" "SIN_FIRMAR" 3 "vacio" "" "n/a" "$G" "$RC" "$M"

#P10c
verificar P10c testdata/p10a.ts --no-expect-signed
IFS='|' read -r G M <<< "$(leer_json P10c)"
anotar P10c "firmas quitadas sin esperar firma" "SIN_FIRMAR" 0 "vacio" "" "n/a" "$G" "$RC" "$M"

#P11
PUB=testdata/otra.pub verificar P11 testdata/firmado.ts
IFS='|' read -r G M <<< "$(leer_json P11)"
anotar P11 "otra clave" "RECHAZADO" 1 "exacto" "FIRMA_INVALIDA;NO_FIRMADA;SIN_FINAL" "all(i['verdict'] == 'FIRMA_INVALIDA' and i['detail'] == 'kid desconocido' for i in d['intervals'])" "$G" "$RC" "$M"

#P12
python3 scripts/ts_tamper.py anchor-sig --in testdata/firmado.ts --out testdata/p12.ts --anchor 10 || echo "falló la preparación de P12"
verificar P12 testdata/p12.ts
IFS='|' read -r G M <<< "$(leer_json P12)"
anotar P12 "firma corrupta" "RECHAZADO" 1 "exacto" "FIRMA_INVALIDA;NO_FIRMADA" "[i['index'] for i in d['intervals'] if i['verdict'] != 'AUTENTICO'] == [10] and d['intervals'][11]['gap_before'] == 0" "$G" "$RC" "$M"

guardar

echo -e "\nP1-P12: $PASAN/$TOTAL pasan. CSV guardado en $CSV"
if [ "$PASAN" -lt "$TOTAL" ]; then
    exit 1
fi
