# Writes options.md, the page of every configuration option, from the output of
# weed config: the comment lines above a [section] or an option describe it.
#
#   weed config | awk -f options.awk >options.md

BEGIN {
	# where the guide explains each section
	guide["server"] = "[Configuration](configuration.html)"
	guide["tls"] = "[Installation](installation.html#network)"
	guide["x509"] = "[Authentication](authentication.html#x509)"
	guide["basic"] = "[Authentication](authentication.html#basic)"
	guide["oidc"] = "[Authentication](authentication.html#oidc)"
	guide["macaroons"] = "[Authentication](authentication.html#macaroons)"
	guide["tokens"] = "[Authentication](authentication.html#tokens)"
	guide["tpc"] = "[Third-party copy](tpc.html)"
	guide["unix_users"] = "[Unix accounts](unix-accounts.html)"
	guide["admin"] = "[Banning users](banning.html)"
	sections = 0
}

/^#( |$)/ {
	line = substr($0, 3)
	doc = doc == "" ? line : doc " " line
	next
}

/^\[[a-z_0-9]+\]$/ {
	name = substr($0, 2, length($0) - 2)
	if (!(name in guide)) {
		print "options.awk: no page of the guide for [" name "]" >"/dev/stderr"
		exit 1
	}
	order[++sections] = name
	body = body "\n## \\[" name "\\] {#" name "}\n\n" sentence(doc) " See " guide[name] ".\n\n"
	body = body "| Option | Default | Meaning |\n|----|----|----|\n"
	doc = ""
	next
}

/^[a-z_]+ = / {
	key = $1
	value = substr($0, length(key) + 4)
	body = body "| [`" key "`]{#" name "." key "} | `" value "` | " cell(sentence(doc)) " |\n"
	doc = ""
	next
}

{ doc = "" }

END {
	print "---"
	print "title: 'Configuration options'"
	print "---"
	print ""
	print "Every option of the configuration file, with its default. *weed config* prints the same, as a configuration file, and this page is made from it. Without a configuration file, weed uses these defaults except `server.address = \"127.0.0.1\"` and `server.anonymous = true` (see [Configuration](configuration.html#quickstart))."
	print ""
	print "Paths are used as written: relative ones are relative to the directory weed starts in. Durations are strings such as `\"90s\"`, `\"10m\"` or `\"24h\"`."
	print ""
	toc = "Sections:"
	for (i = 1; i <= sections; i++)
		toc = toc " [\\[" order[i] "\\]](#" order[i] ")" (i < sections ? "," : ".")
	print toc
	printf "%s", body
}

# sentence capitalizes text and ends it with a full stop
function sentence(text) {
	text = toupper(substr(text, 1, 1)) substr(text, 2)
	return text ~ /\.$/ ? text : text "."
}

# cell escapes what would end a table cell
function cell(text) {
	gsub(/\|/, "\\|", text)
	return text
}
