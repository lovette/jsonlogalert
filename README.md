# jsonlogalert - Email alerts for systemd journal and JSON log files

This tool is a modern take on the log monitoring tradition most widely implemented by [Logcheck](https://packages.debian.org/unstable/logcheck) and my take on that,
[Logalert](https://github.com/lovette/logalert).


## What does it do?

This tool scans server logs and emails interesting activity to a server administrator.
It takes advantage of structured logging to give you flexibility in how logs are filtered and alerts are formatted.
Logs can be sourced from the [systemd journal service](https://www.freedesktop.org/software/systemd/man/latest/systemd-journald.service.html), structured text files (JSON) and plain text files (with adapters that convert them into JSON.)

This tool is best suited for those managing a small number of servers with a moderate level of activity.
For everyone else, conventional wisdom says you should ship your logs off to a log analysis service using
a data collector such as [Vector](https://vector.dev/), [Filebeat](https://www.elastic.co/beats/filebeat),
or [Fluentd](https://docs.fluentd.org/). Maybe even something that focuses solely on *journald*
such as [journalpump](https://github.com/Aiven-Open/journalpump).

Other tools that help you monitor *journald* include [journal-brief](https://github.com/twaugh/journal-brief)
and [jouno](https://github.com/digitaltrails/jouno), a Freedesktop notifications forwarder.

(For the record, Debian logcheck gained support for scanning journal messages in 2021. It uses `journalctl` to follow journald with a timestamp instead of a cursor and filters log lines the same way it always has.)


## How does it work?

*jsonlogalert* reads log file messages line by line and applies a filter to determine messages that are interesting or unusual.
Expected messages are filtered out. Those remaining are formatted in an email message and sent to a server administrator.


## Installation

### Bash script

	sudo -v; curl -sSf https://raw.githubusercontent.com/lovette/jsonlogalert/main/install.sh | sudo bash

### From source

	git clone https://github.com/lovette/jsonlogalert.git
	cd jsonlogalert/
	./install.sh

### For development

	git clone https://github.com/lovette/jsonlogalert.git
	cd jsonlogalert/
	make virtualenv
	make install-dev
