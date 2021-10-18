all: performance.png performance.svg

.PHONY: clean
clean:
	rm -f *.png *.svg

performance.png: performance.gp $(wildcard *.dat)
	gnuplot -e "set terminal png background '#c0c0c0' ; set output \"$@\"" $<

performance.svg: performance.gp $(wildcard *.dat)
	gnuplot -e "set terminal svg background '#c0c0c0' ; set output \"$@\"" $<
