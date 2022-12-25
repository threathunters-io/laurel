# Generate benchmark flamegraph like this:
#
# $ make -f benches/Makefile binary=./target/release/deps/coalesce_execve-76764715a5348906

binary ?= $(error "Set binary variable")
FG_DIR ?= ~/src/flamegraph

.PHONY: all
all: $(binary).svg

.PHONY: clean
clean:
	rm -f $(binary).prof $(binary).stacks $(binary).svg

.PHONY: view
view: $(binary).svg
	firefox $^

%.svg: %.stacks
	$(FG_DIR)/flamegraph.pl < $^ > $@.t
	mv $@.t $@

%.prof: %
	$<

%.stacks: % %.prof
	google-pprof --collapsed $^ > $@.t
	mv $@.t $@
