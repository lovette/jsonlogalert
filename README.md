# Email alerts for systemd journal and log files

This tool is a modern take on the log monitoring tradition most widely implemented by [Logcheck](https://packages.debian.org/unstable/logcheck) and my take on that,
[Logalert](https://github.com/lovette/logalert).


## What does it do?

This tool scans server logs and emails interesting activity to a server administrator.
It takes advantage of structured logging to give you flexibility in how logs are filtered and alerts are formatted.
Logs can be sourced from the [systemd journal service](https://www.freedesktop.org/software/systemd/man/latest/systemd-journald.service.html), structured text files (JSON) and plain text files (with adapters that convert them into JSON.)

This tool is best suited for those managing a small number of servers with a moderate level of activity.
For everyone else, conventional wisdom says you should ship your logs off to a log analysis service using
a data collector such as [Vector](https://vector.dev/), [Filebeat](https://www.elastic.co/beats/filebeat),
or [Fluentd](https://docs.fluentd.org/). Maybe even something that focuses solely on *systemd journal*
such as [journalpump](https://github.com/Aiven-Open/journalpump).

Other tools that help you monitor *systemd journal* include [journal-brief](https://github.com/twaugh/journal-brief)
and [jouno](https://github.com/digitaltrails/jouno), a Freedesktop notifications forwarder.

(For the record, Debian Logcheck gained support for scanning journal messages in 2021. It uses `journalctl` to follow the systemd journal with a timestamp instead of a cursor and filters log lines the same way it always has.)


## How does it work?

*jsonlogalert* reads log file entries line by line and applies a filter to determine entries that are interesting or unusual.
Typically, expected entries are filtered out. Those remaining are composed in an email message and sent to a server administrator.

The general process:

1. Tail each log [source](#sources) (systemd journal, log files, log streams.)
2. For each log entry, iterate through [services](#services) to see if any want to [select, drop or ignore](#filters) the entry.
3. Format log entries using a [template](#templates).
4. Send content to one or more [outputs](#outputs) (/dev/null, stdout, file, SMTP.)

Services can rewrite fields to create new fields and conceal fields from templates.

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


## Command line

There are two sets of command line options. The options below control main operations. There are also command line options
for a lot of the configuration directives that apply to [sources](#sources) and [services](#services).
Options specified on the command line override those in configuration files.

| Option                     | Description |
| ------                     | ----------- |
| -c, --config-file FILE     | Read options from configuration FILE. [default: /etc/jsonlogalert.conf] |
| -d, --config-dir DIRECTORY | Set path to directory containing source and service definitions.  [default: /etc/jsonlogalert.d] |
| --print-rules              | Print rules and exit. |
| --print-conf               | Print source and service configurations and exit. |
| -v, --verbose              | Be more verbose; can specify more than once. |
| --version                  | Show the version and exit. |
| --help                     | Show usage and exit. |


## Configuration

Default configuration options can be set in a configuration file (the default is `/etc/jsonlogalert.conf`).
There are options to control main operations, sources and services, and outputs.
Options that are specified in source and service configuration files override those in the main configuration file.
Options specified on the command line override those in configuration files.

### jsonlogalert.conf

#### Sources and services

| Directive | Command line        | Description |
| --------- | ------------        | ----------- |
| sources   | -s, --source SOURCE | Enable only SOURCE; can specify more than once; prefix with `!` to negate; use `*` to enable all sources. |
| services  | --service SERVICE   | Enable only SERVICE for a SOURCE; can specify more than once; prefix with `!` to negate. |

#### General options

| Directive                 | Command line               | Description |
| ---------                 | ------------               | ----------- |
| tail_state_dir: DIRECTORY | --tail-state-dir DIRECTORY | Set path of DIRECTORY to save tail offset/cursor state. [default: /var/lib/misc] |
| tail_reset                | --tail-reset               | Delete offset/cursor state files and exit. |
| tail_debug                | --tail-debug               | Use but not update tail offset/cursor. |
| tail_ignore               | --tail-ignore              | Ignore and do not update tail offset/cursor. |

#### Journal options

| Directive                       | Command line                     | Description |
| ---------                       | ------------                     | ----------- |
| tail_journal_bin: FILE          | --tail-journal-bin FILE          | Set path of executable to tail systemd journal. [default: logtail-journal] |
| tail_journal_since: [boot, all] | --tail-journal-since [boot, all] | Read all systemd journal entries or since last boot (ignores cursor.) |

#### Log file options

| Directive           | Command line            | Description |
| ---------           | ------------            | ----------- |
| tail_file_bin: FILE | --tail-file-bin FILE    | Set path of executable to tail log files. [default: logtail2] |


#### General output options

| Directive                       | Command line                    | Description |
| ---------                       | ------------                    | ----------- |
| output_devnull                  | --output-devnull                | Output results to /dev/null; that is, output nothing!  |
| output_stdout                   | --output-stdout                 | Output results to stdout; if used with SMTP output; no email will be sent. |
| output_template_file: FILENAME  | --output-template-file FILENAME | Use FILENAME instead of default output template. |

#### File

Set either of these options to save output to file.

| Directive                  | Command line                | Description |
| ---------                  | ------------                | ----------- |
| output_file_dir: DIRECTORY | --output-file-dir DIRECTORY | Output results to file in DIRECTORY; file names will be based on source and service; default is current working directory. |
| output_file_name: FILENAME | --output-file-name FILENAME | Output results to FILENAME in `output_file_dir` when a single SERVICE is specified. |

#### SMTP

Set `output_smtp_rcpt` to compose a message and send via SMTP.

| Directive                           | Command line                         | Description |
| ---------                           | ------------                         | ----------- |
| output_smtp_rcpt: EMAIL             | --output-smtp-rcpt EMAIL             | Email recipient address. Required. |
| output_smtp_sender: EMAIL           | --output-smtp-sender EMAIL           | Email sender address. [default: recipient address] |
| output_smtp_rcpt_name: NAME         | --output-smtp-rcpt-name NAME         | Email recipient name. [default: none] |
| output_smtp_sender_name: NAME       | --output-smtp-sender-name NAME       | Email sender name. [default: recipient name] |
| output_smtp_subject: SUBJECT        | --output-smtp-subject SUBJECT        | Email subject line. [default: "Unusual %SERVICEDESC% activity"] |
| output_smtp_host: HOSTNAME          | --output-smtp-host HOSTNAME          | Mail server hostname or address. [default: localhost] |
| output_smtp_port: INTEGER           | --output-smtp-port INTEGER           | Mail server port. [default: 25] |
| output_smtp_auth_ssl                | --output-smtp-auth-ssl               | Mail server uses SSL connection. [default: no] |
| output_smtp_auth_tls                | --output-smtp-auth-tls               | Mail server uses TLS. [default: no] |
| output_smtp_auth_username: USERNAME | --output-smtp-auth-username USERNAME | Mail server authentication username. [default: none] |
| output_smtp_auth_password: PASSWORD | --output-smtp-auth-password PASSWORD | Mail server authentication password. [default: none] |


### jsonlogalert.d

[Sources](#sources) and [services](#services) are defined in a set of directories.
The default configuration root directory is `/etc/jsonlogalert.d`.

	/etc/jsonlogalert.d
	|-- <source>
	|   |-- source.yaml         < required
	|   |-- source_parser.py
	|   |-- <service>
	|   |   |-- service.yaml    < required
	|   |   |-- template.html   < required (somewhere)
	|   |   |-- select.yaml
	|   |   |-- drop.yaml
	|   |   |-- pass.yaml
	|   |-- <service>
	|   |   |-- ...
	|   |-- ...
	|-- <source>
	|   |-- ...
	|-- <service>
	|   |-- source.yaml          < required
	|   |-- service.yaml         < required
	|   |-- template.html        < required (somewhere)
	|   |-- select.yaml
	|   |-- drop.yaml
	|   |-- pass.yaml
	|-- <service>
	|   |-- ...
	|-- ...

You can see the configuration options for sources and services with `--print-conf`.

	jsonlogalert --print-conf

## Sources

Each top level directory defines a log source, either one or more log files or a systemd journal.
A source directory must contain a `source.yaml` configuration file that define the options for the source.
Source configurations inherit and override main configuration options.
(Relevant command line arguments override all options.)
If a source only has one service, the service can be defined in the source directory.
All enabled sources are processed by default.
Specific sources can be enabled with the `--source` command line option and the `sources` configuration file directive.

### General options

| Directive                   | Type   | Description |
| -------                     | ----   | ----------- |
| description                 | string | A description; can reference in SMTP subject as `%SERVICEDESC%` [default: none] |
| enabled                     | int    | Whether the source should be processed by default [default: 1] |
| blob_fields                 | list   | Set of fields that 'journalctl' may emit as blobs and should be decoded. [default: none] |
| capture_fields              | list   | If set, only captured fields are available to output templates. This takes precedence over `ignore_fields`. Merged with service directive. [default: none] |
| ignore_fields               | list   | If set, ignored fields are not captured so are not available to output templates. Merged with service directive. [default: none] |
| conceal_fields              | list   | If set, concealed fields are "concealed" to output templates when iterating fields. (All fields are accessible as 'rawfields'.) Only fields that have been captured or not ignored can be concealed. Merged with service directive. Always includes 'timestamp_field' and 'message_field' fields. [default: none] |
| rewrite_fields              | list   | If set, a set of regular expressions to create new fields with capture groups. [default: none] |
| select_rules_path           | string | Path to select rules. [default: select.yaml] |
| pass_rules_path             | string | Path to pass rules. [default: pass.yaml] |
| drop_rules_path             | string | Path to drop rules. [default: drop.yaml] |
| max_logentries              | int    | Maximum number of entries to report; everything else will be discarded. [default: 250] |
| output_content_type         | string | Output content type. [default: "html"] |
| output_template_file        | string | Output template file name. Must be in the service, source or source parent directory. [default: none] |
| output_template_minify_html | int    | True if template content is HTML and should be minified. [default: 1] |
| timestamp_field             | string | Log entry field that is the event timestamp. [default: "TIMESTAMP"] |
| message_field               | string | Log entry field that is the event message. [default: "MESSAGE"] |

### Systemd journal options

The `journal_dir` directive sets the source to be parsed as a systemd journal.
It can be set to `default` to parse the default systemd journal or another directory containing the journal.

| Directive   | Type   | Description |
| ---------   | ------ | ----------- |
| journal_dir | string | Tail systemd journal DIRECTORY; can override with command line options `-J` or `--journal-dir `|

### Log file options

The `logfiles` directive sets the source to be a set of text files.

| Directive | Type   | Description |
| --------- | ------ | ----------- |
| logfiles  | list   | Set of log files to read; can override with comand line options `-f` or `--tail-file` or directive `tail_file` [default: 0] |
| onelog    | int    | Treat all log files for a service as one log; the default is to parse and output each log file individually. [default: 0] |


### Custom log parsers

Text log files structured as JSON text are parsed by default.
Custom parsers parsers can be implemented for traditional text log files or if you want to customize the field set for JSON logs beyond current capabilities.
A custom parser is defined in a `source_parser.py` in the source directory.
The custom parser is used to convert each log line into a dictionary of fields and values.
You can see examples of this in a few services in `contrib-config.d`.


## Services

Each subdirectory of a log source defines a service.
If a source only has one service, the service can be defined in the source directory itself.
A service directory must contain a `service.yaml` configuration file that define the options for the service.
Each source must have at least one service.
Service configuration options inherit and override options from their source and the main configuration.
(Relevant command line arguments override all options.)
Services can define and override the directives defined in its source and the main configuration file.
All enabled services for enabled sources are processed by default.
Specific services for a source can be enabled with the `--service` command line option and the `services` configuration file directive.

### Claiming log entries

Each log line is passed to each service until the line is claimed by a service.
Services are iterated alphabetically.
Service that don't define any select or drop rules (a so called "catchall" service) will be iterated last for its source.

| Name        | Directive         | Entries matching rules will be... |
| ----        | ----------        | ----------- |
| select.yaml | select_rules_path | ...claimed by the service; select takes precedence over drop and pass rules. |
| pass.yaml   | pass_rules_path   | ...passed to further services; takes precedence over drop rules. |
| drop.yaml   | drop_rules_path   | ...claimed by the service but dropped, with no further processing. |

You can see the configuration options for sources and services with `--print-rules`.

	jsonlogalert --print-rules

### Rules

Rule sets are a series of fields and conditions.
Rules can be defined as YAML or JSON files.

Field operators and values can be specified as strings or lists. The default operator ("OP") is equality (`=`).

	"FIELD": "value"
	"FIELD": "OPvalue"
	"FIELD": [value[, value, ...]]
	"FIELD": ["OP", value[, value, ...]]

A group of fields together define AND conditions and must all match.

YAML:

	FIELDA: "value"
	FIELDB: "value"

	FIELDA:
	  - "OP"
	  - "value"
	  - ...
	FIELDB: "value"

JSON:

	{
	  "FIELDA": "value"
	  "FIELDB": "value"
	}

A list of groups define OR conditions and any group must match.

YAML:

	- FIELDA:
	  - "OP"
	  - "value"
	  - ...
	- FIELDB:
	  - ...
	- ...

JSON:

	[
	  {
	    "FIELDA":...,
	    ...
	  },
	  {
	    "FIELDB":...,
	    ...
	  }
	]

### Rule operators

| Operator | Comparison                   |
| -------- | ----------                   |
| =        | Equals                       |
| !        | Not equal                    |
| >        | Greater than                 |
| >=       | Greater than or equal        |
| <        | Less than                    |
| <=       | Less than or equal           |
| ~        | Regular expression match     |
| !~       | Not regular expression match |


## Templates

Templates are used to compose content using log entries claimed by the service.
Templates are Python [Jinja2 templates](http://jinja.pocoo.org/docs/templates/).
You can see example templates for services in `contrib-config.d`.
Templates can create any type of text content.

	{%- set ns = namespace() -%}
	{%- set ns.tlasttimestamp = None -%}
	{%- set ns.tlastdate = None -%}
	{%- set ns.tlasttime = None -%}
	{%- set ns.tlastservice = None -%}

	<!DOCTYPE html>
	<html>
	<head>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<style>
		...
		</style>
	</head>
	<body>
		<table width="100%">
			<tbody>

			{%- for e in logentries -%}

				{%- set ttimestamp = e.timestamp|format_iso(timespec="seconds") -%}
				{%- set tdate = e.timestamp|format_date -%}
				{%- set ttime = e.timestamp|format_time -%}

				{%- if e._SYSTEMD_UNIT and e.SYSLOG_IDENTIFIER -%}
					{%- set tservice = e.SYSLOG_IDENTIFIER ~ " [" ~ e._SYSTEMD_UNIT ~ "]" -%}
				{%- else -%}
					{%- set tservice = e._SYSTEMD_UNIT or e.SYSLOG_IDENTIFIER-%}
				{%- endif -%}

				{%- if e.PRIORITY is none or e.PRIORITY > 5 -%}
					{%- set tpriorityclass = "" -%}
				{%- elif e.PRIORITY > 3 -%}
					{%- set tpriorityclass = "warn" -%}
				{%- else -%}
					{%- set tpriorityclass = "error" -%}
				{%- endif -%}

				{# Print header line for each new date #}
				{%- if tdate != ns.tlastdate -%}
				<tr>
					<td colspan="3" class="date">{{ e.timestamp|format_date('%b %-d') }}</td>
				</tr>
				{%- endif -%}

				<tr>
					<td class="time">
					{%- if ns.tlasttimestamp is none or ttimestamp != ns.tlasttimestamp -%}
						{{ ttime }}
					{%- endif -%}
					</td>

					{%- if tservice != ns.tlastservice -%}
					<td class="service">
						{{ tservice|e }}
					{%- else -%}
					<td class="service ditto">
						...
					{%- endif -%}
					</td>

					{%- if tpriorityclass|length -%}
					<td class="message {{ tpriorityclass }}">
					{%- else -%}
					<td class="message">
					{%- endif -%}
						{{ e.message|e|nl2br }}
					</td>
				</tr>

				{%- set ns.tlasttimestamp = ttimestamp -%}
				{%- set ns.tlastdate = tdate -%}
				{%- set ns.tlasttime = ttime -%}
				{%- set ns.tlastservice = tservice -%}

			{%- endfor -%}

			</tbody>
		</table>
	</body>
	</html>

### Template variables

Templates access details about log entries, their source and service using template variables.

| Variable   | Description |
| -------    | ----------- |
| logentries | List of log entries. |
| logservice | The service. |
| logsource  | The source. |

#### Log entry properties

Each log entry uses properties to access log entry fields.
The fields depend on those the source defines.

Standard properties include:

| Property  | Description |
| -------   | ----------- |
| fields    | Dictionary of fields, sorted by field name. Does not include concealed fields. |
| rawfields | Dictionary of all fields that were captured. |
| timestamp | The entry timestamp. |
| message   | The entry message. |

Others depend on the source. The systemd journal and the services that log to it include dozens of
fields such as `_SYSTEMD_UNIT`, `SYSLOG_IDENTIFIER`, and `PRIORITY`.


## SMTP Messages

The SMTP configuration options define who and how to send mail.
The output template defines the message content.
The sender, recipient and subject options can contain placeholders to be replaced at runtime.

| Placeholder    | Value                    |
| -----------    | -----                    |
| %HOSTNAME%     | Host name.               |
| %SOURCENAME%   | Log source name.         |
| %SERVICENAME%  | Log service name.        |
| %SERVICEDESC%  | Log service description. |


## Run periodically or on demand

Jsonlogalert can be run on a scheduled interval or when a log file is modified.
This can be managed with systemd timer and/or path units.
Examples are included in the `systemd` directory of the distribution.

## Python systemd package

Jsonlogalert requires the Python package `systemd` be installed.
Depending your operating system, this may be installed and hard-coded to the base distribution Python version.
We create our virtual environment with `--system-site-packages` and do not include as a `pyproject.toml` `dependencies` so we reference the system installed module.

You can see that `python3-systemd` is hard-coded to Python 3.9 for Red Hat Enterprise Linux 9.4:

	$ dnf repoquery -l python3-systemd

If your installation does not have the package, you can review installation instructions
on the [systemd GitHub repo](https://github.com/systemd/python-systemd).
(Be aware there are variations of 'python-systemd' that are not from the official 'systemd'.)
