TGTS := laurel.8
SRCS := $(patsibst %,%.md,$(TGTS))

.PHONY: all
all: $(TGTS)

%: %.md
	pandoc -s -t man -o $@ $^

.PHONY: clean
clean:
	rm -f $(TGTS)
