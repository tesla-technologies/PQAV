#!/bin/bash
set -euo pipefail

mkdir -p testdata

ffmpeg -y -f lavfi -i testsrc=size=1280x720:rate=25 -f lavfi -i sine=frequency=1000:sample_rate=48000 \
    -c:v libx264 -g 12 -bf 2 -c:a aac -ar 48000 -ac 2 -t 60 \
    -muxrate 10000000 \
    testdata/entrada.ts

ffmpeg -y -f lavfi -i testsrc=size=1280x720:rate=25 \
    -c:v libx264 -g 12 -bf 2 -t 60 \
    -muxrate 10000000 \
    testdata/solo_video.ts
