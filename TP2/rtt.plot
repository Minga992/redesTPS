# Parametros generales
set terminal pngcairo  background "#ffffff" enhanced font "courier,12" fontscale 1.0 size 800,600
set output filename.'.png'
set title "Hops RTTs"

set grid
set style data histogram
set style histogram cluster gap 1
set style fill solid border -1
set boxwidth 0.9

# Rangos y Labels
set yrange [0:200]
set ylabel "HOP RTT (ms)"
set xlabel "Hop IP"
set ytics 10
set xtics 1 rotate by -90

set datafile separator "\t"
plot filename using 2:xticlabels(1) notitle