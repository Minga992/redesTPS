# Parametros generales
set terminal pngcairo  background "#ffffff" enhanced font "courier,12" fontscale 1.0 size 800,600
set output filename.'-standarized.png'
set title "Hops RTTs standarized"

set grid
set style data histogram
set style histogram cluster gap 1
set style fill solid border -1
set boxwidth 0.9

# Rangos y Labels
set yrange [0:3]
set ylabel "HOP RTT standarized (ms)"
set xlabel "HOP (TTL) IP"
set ytics 0.2
set xtics 1 rotate by -90

set datafile separator "\t"
plot filename using 4:xticlabels('('.stringcolumn(1).') '.stringcolumn(2)) notitle with linespoints pt 7 ps 1