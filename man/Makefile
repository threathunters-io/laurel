TGTS := laurel.8 laurel-about.7 laurel-audit-rules.7 laurel2audit.8
SRCS := $(patsibst %,%.md,$(TGTS))

.PHONY: all
all: $(TGTS)

%: %.md
	pandoc -s -t man -o $@ $^

%.html: %.md
	pandoc -s -t html -o $@ $^

.PHONY: clean
clean:
	rm -f $(TGTS)
