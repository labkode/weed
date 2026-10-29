# Makes the administration guide from its pages in Markdown, with pandoc, as
# DavUtils makes its documentation: header.html (the header and the sidebar) goes
# before every page, footer.html after. options.md is made from weed config, by
# options.awk. The pages are kept in ../html, which make dist replaces: they are
# never edited by hand.
#
#   make          the pages, in build/
#   make dist     the pages, in ../html
#   make clean

PANDOC = pandoc
# the version that made ../html (docs/docs_test.go checks it with this one)
PANDOC_VERSION = 3.8.3
PFLAGS = -s -f markdown-smart-tex_math_dollars --wrap=none --columns=10000 -M lang=en \
	--title-prefix='weed administration guide' -c weed.css -B header.html -A footer.html
PDEPEND = header.html footer.html Makefile

# the weed whose configuration options options.md lists
WEED = ../../weed

BUILD = build
DISTHTML = ../html

SRC = index.md
SRC += installation.md
SRC += getting-started.md
SRC += configuration.md
SRC += authentication.md
SRC += unix-accounts.md
SRC += tpc.md
SRC += storage.md
SRC += what-runs.md
SRC += upgrading.md
SRC += reloading.md
SRC += logging.md
SRC += monitoring.md
SRC += banning.md
SRC += troubleshooting.md
SRC += commands.md
SRC += metrics.md
SRC += http.md
SRC += files.md

HTML = $(SRC:%.md=$(BUILD)/%.html) $(BUILD)/options.html

all: doc

doc: $(BUILD) $(HTML) $(BUILD)/weed.css

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/%.html: %.md $(PDEPEND)
	$(PANDOC) $(PFLAGS) $< -o $@

$(BUILD)/options.html: $(BUILD)/options.md $(PDEPEND)
	$(PANDOC) $(PFLAGS) $(BUILD)/options.md -o $@

$(BUILD)/options.md: options.awk $(WEED)
	$(WEED) config >$(BUILD)/weed.toml
	awk -f options.awk $(BUILD)/weed.toml >$@

$(BUILD)/weed.css: weed.css
	cp weed.css $(BUILD)

dist: doc
	@$(PANDOC) --version | head -1 | grep -qx 'pandoc $(PANDOC_VERSION)' || \
		echo "warning: ../html was made with pandoc $(PANDOC_VERSION), not $$($(PANDOC) --version | head -1)"
	rm -Rf $(DISTHTML)
	mkdir -p $(DISTHTML)
	cp $(BUILD)/*.html $(BUILD)/weed.css $(DISTHTML)/

clean:
	rm -Rf $(BUILD)

.PHONY: all doc dist clean
