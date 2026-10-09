#!/bin/sh
# JobShield Java backend — build + run (JDK 17+, no Maven needed)
cd "$(dirname "$0")"
mkdir -p out
find src -name '*.java' > out/sources.txt
javac -encoding UTF-8 -d out @out/sources.txt || exit 1
cp data/employers.json out/employers.json 2>/dev/null
java -cp out com.jobshield.App
