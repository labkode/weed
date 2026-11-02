# Makes the administration guide from its pages in Markdown, with pandoc, as
# DavUtils makes its documentation: header.html (the header and the sidebar) goes
# before every page, footer.html after. options.md is made from weed config, by
# options.awk, and changelog.md from ../../CHANGELOG.md, whose first section names the
# version that the header says the guide is for. The pages are kept in ../html, which
# make dist replaces: they are never edited by hand.
#
#   make          the pages, in build/
#   make dist     the pages, in ../html
#   make clean

PANDOC = pandoc
# the version that made ../html (docs/docs_test.go checks it with this one)
PANDOC_VERSION = 3.8.3
PFLAGS = -s -f markdown-smart-tex_math_dollars --wrap=none --columns=10000 -M lang=en \
	--title-prefix='weed administration guide' -c weed.css -B $(BUILD)/header.inc -A footer.html
PDEPEND = $(BUILD)/header.inc footer.html Makefile

# the weed whose configuration options options.md lists
WEED = ../../weed

# The changelog: its first section is a release (## v1.2.0 (2026-11-20)), which the
# guide is then for, or Unreleased, the development version (see header.html)
CHANGELOG = ../../CHANGELOG.md

BUILD = build
DISTHTML = ../html

SRC = index.md
SRC += installation.md
SRC += getting-started.md
SRC += configuration.md
SRC += authentication.md
SRC += unix-accounts.md
SRC += limits.md
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

HTML = $(SRC:%.md=$(BUILD)/%.html) $(BUILD)/options.html $(BUILD)/changelog.html

all: doc

doc: $(BUILD) $(HTML) $(BUILD)/weed.css

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/%.html: %.md $(PDEPEND)
	$(PANDOC) $(PFLAGS) $< -o $@

$(BUILD)/options.html: $(BUILD)/options.md $(PDEPEND)
	$(PANDOC) $(PFLAGS) $(BUILD)/options.md -o $@

$(BUILD)/changelog.html: $(BUILD)/changelog.md $(PDEPEND)
	$(PANDOC) $(PFLAGS) $(BUILD)/changelog.md -o $@

# The changelog, whose title, # Changelog, becomes the page's
$(BUILD)/changelog.md: $(CHANGELOG) | $(BUILD)
	@test "$$(head -1 $(CHANGELOG))" = "# Changelog" || { echo "$(CHANGELOG) does not begin with # Changelog" >&2; exit 1; }
	printf -- "---\ntitle: 'Changelog'\n---\n" >$@
	tail -n +2 $(CHANGELOG) >>$@

# The header, with the version that the first section of the changelog names (not
# .html, which make dist copies)
$(BUILD)/header.inc: header.html $(CHANGELOG) | $(BUILD)
	@v=$$(awk '$$1 == "##" { print ($$2 == "Unreleased" ? "for the development version" : "for weed " $$2); exit }' $(CHANGELOG)) && \
	test -n "$$v" || { echo "$(CHANGELOG) has no section (## Unreleased, or ## v1.2.0 ...)" >&2; exit 1; }; \
	sed "s/@VERSION@/$$v/" header.html >$@

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
