# Email alerts for systemd journal and log files

This tool is a modern take on the log monitoring tradition most widely implemented by [Logcheck](https://packages.debian.org/unstable/logcheck) and my take on that,
[Logalert](https://github.com/lovette/logalert).


## What does it do?

This tool scans server logs and emails interesting activity to a server administrator.
It takes advantage of structured logging to give you flexibility in how logs are filtered and uses templates to customize how alerts are formatted.
Logs can be sourced from the [systemd journal service](https://www.freedesktop.org/software/systemd/man/latest/systemd-journald.service.html), structured text files (JSON) and plain text files (using custom parsers that convert them into JSON.)

This tool is best suited for those managing a small number of servers with a moderate level of activity.
For everyone else, conventional wisdom says you should ship your logs off to a log analysis service using
a data collector such as [Vector](https://vector.dev/), [Filebeat](https://www.elastic.co/beats/filebeat),
or [Fluentd](https://docs.fluentd.org/). Maybe even something that focuses solely on *systemd journal*
such as [journalpump](https://github.com/Aiven-Open/journalpump).

Other tools that help you monitor *systemd journal* include [journal-brief](https://github.com/twaugh/journal-brief)
and [jouno](https://github.com/digitaltrails/jouno), a Freedesktop notifications forwarder.

(For the record, Debian Logcheck gained support for scanning journal messages in 2021. It uses `journalctl` to follow the systemd journal with a timestamp instead of a cursor and filters log lines the same way it always has.)


## How does it work?

*jsonlogalert* reads log file entries line by line and applies filter rules to determine entries that are interesting or unusual.
Typically, expected entries are filtered out. Those remaining are composed in an email message and sent to a server administrator.

The general process:

1. Iterate through each [log source](#sources) (systemd journal, log files, log streams) and tail log entries starting where the last scan ended.
2. For each log entry, iterate through the source [services](#services) to see if any want to [claim the entry.](#claiming-log-entries).
3. Compose content with log entries for each service using a [template](#templates).
4. Send the content to one or more [outputs](#outputs) (/dev/null, stdout, file, SMTP.)

Services can rewrite fields to create new fields and conceal fields from templates.


## Requirements

- Python 3
- Perl - The Perl script `logtail2` from the Logcheck distribution is included and used by default. You can use [alternatives](https://github.com/search?q=logtail2&type=repositories) written in other languages.


## Installation

### Bash script

	sudo -v; curl -sSf https://raw.githubusercontent.com/lovette/jsonlogalert/main/install.sh | sudo bash

### Repo

	git clone https://github.com/lovette/jsonlogalert.git
	./install.sh -s jsonlogalert/

Installing from source will:

- Copy README and LICENSE to `/opt/jsonlogalert`.
- Create a Python virtual environment in `/opt/jsonlogalert/.venv`.
- Copy a few scripts to `/usr/local/bin`.
- Copy default configuration file and directory to `/etc`.
- Copy logtail2 rotation rules to `/usr/share/logtail`.
- Copy man pages to `/usr/share/man`.

Adding the directory `/usr/local/bin` to your `$PATH` will simplify running jsonlogalert.

## Command line

There are two sets of command line options. The options below control main operations. There are also command line options
for a lot of the configuration directives that apply to [sources](#sources) and [services](#services).
Options specified on the command line override those in configuration files.

| Option              | Description |
| ------              | ----------- |
| -c, --config-file   | Read options from configuration FILE. [default: /etc/jsonlogalert.conf] |
| -d, --config-dir    | Set path to directory containing source and service definitions.  [default: /etc/jsonlogalert.d] |
| --print-conf        | Print source and service configurations and exit. |
| --print-field-types | Print source field types and exit. |
| --print-rules       | Print rules and exit. |
| --dry-run           | Run without using or updating tail offset/cursor; suppress output with `--output-devnull` |
| --tail-reset        | Delete offset/cursor state files and exit. |
| -v, --verbose       | Be more verbose; can specify more than once. [warnings:`-v`, info:`-vv`, debug:`-vvv`] |
| --version           | Show the version and exit. |
| --help              | Show usage and exit. |

A complete listing of command line options is shown with `--help`.

	jsonlogalert --help

## Configuration file

Default configuration options can be set in a main configuration file (the default is `/etc/jsonlogalert.conf`).
There are options to control main operations, sources and services, and outputs.
Options that are specified in source `source.yaml` and service `service.yaml` configuration files override those in the main configuration file.
Options specified on the command line override those in configuration files.

### Sources and services

| Directive | Command line | Description |
| --------- | ------------ | ----------- |
| sources   | -s, --source | Enable only SOURCE; can specify more than once; prefix with `!` to negate; use `*` to enable all sources; valid for main configuration only. |
| services  | --service    | Enable only SERVICE for a SOURCE; can specify more than once; prefix with `!` to negate; valid for main configuration only. |

### General tail options

| Directive      | Command line     | Description |
| ---------      | ------------     | ----------- |
| tail_state_dir | --tail-state-dir | Set path of DIRECTORY to save tail offset/cursor state. [default: /var/lib/misc] |
| tail_dryrun    | --tail-dryrun    | Use but not update tail offset/cursor. |
| tail_ignore    | --tail-ignore    | Ignore and do not update tail offset/cursor; implies `--tail-journal-since today`. |

### Journal options

| Directive          | Command line          | Description |
| ---------          | ------------          | ----------- |
| tail_journal_bin   | --tail-journal-bin    | Set path of executable to tail systemd journal. [default: logtail-journal] |
| tail_journal_since | --tail-journal-since  | Ignore and do not update tail offset/cursor and read all systemd journal entries, since last boot or today's events; [choices: today, boot, all] |

### Log file options

| Directive     | Command line    | Description |
| ---------     | ------------    | ----------- |
| tail_file_bin | --tail-file-bin | Set path of executable to tail log files. [default: logtail2] |


## jsonlogalert.d

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

Sources define the logs to scan and how to parse them.
Each top level directory defines a log source: either one or more log files or a systemd journal.
If a source only has one service, the service can be defined in the source directory.
All enabled sources are scanned by default.
Specific sources can be enabled with the `--source` command line option and the `sources` configuration file directive.

### Source options

A source directory must contain a `source.yaml` configuration file that define the options for the source.
Source configurations inherit and override main configuration options.
Options defined in the source apply to all services.
(Relevant command line arguments override all options.)

Sources can set options described below. These options also apply to [services](#services).

| Directive                   | Type   | Description |
| -------                     | ----   | ----------- |
| description                 | string | Service description; can reference in SMTP subject as `%SERVICEDESC%` [default: none] |
| enabled                     | int    | Whether the source should be scanned by default. [default: 1] |
| capture_fields              | list   | Set of fields to capture and made available to templates; takes precedence over `ignore_fields`; merged with service directive. [default: none] |
| ignore_fields               | list   | Set of fields to not capture, all others are available to templates; merged with service directive. [default: none] |
| conceal_fields              | list   | Set of fields to "conceal" from templates when iterating fields; merged with service directive; always includes 'timestamp_field' and 'message_field' fields. [default: none] |
| rewrite_fields              | list   | Set of regular expressions to create new fields from log entry field values using [named groups](https://docs.python.org/3/howto/regex.html#non-capturing-and-named-groups); regular expressions are matched from beginning of the field value; a single field can be rewritten multiple times; applied after `rstrip_fields`. [default: none] |
| rstrip_fields               | list   | Set of fields to trim trailing whitespace from values. [default: none] |
| field_types                 | list   | Define the type conversion for a field; applied after 'rewrite_fields'. [choices: int, bool] [default: none] |
| select_rules_path           | string | Path to select rules. [default: select.yaml] |
| pass_rules_path             | string | Path to pass rules. [default: pass.yaml] |
| drop_rules_path             | string | Path to drop rules. [default: drop.yaml] |
| max_logentries              | int    | Maximum number of entries to report, everything else will be discarded; set to 0 to disable limit; can override with command line option `--max-logentries` [default: 250] |
| output_content_type         | string | Output content type; used as the extension for output file names. [default: 'output_template_file' file extension] |
| output_max_bytes            | int    | Maximum bytes allowed to output. [default: depends on output type] |
| output_template_file        | string | Output template file name. Must be in the service, source or source parent directory; can override with command line option `--output-template-file`. [default: none] |
| output_template_minify_html | int    | True if template content is HTML and should be minified. [default: 1] |
| timestamp_field             | string | Log entry field that is the event timestamp. [default: "TIMESTAMP"] |
| timestamp_field_format      | string | Parse `timestamp_field` field values according to this format; see [datetime.strptime](https://docs.python.org/3/library/datetime.html#strftime-and-strptime-format-codes) for format codes. [default: none] |
| message_field               | string | Log entry field that is the event message. [default: "MESSAGE"] |

### Journal options

The `journal_dir` directive defines the source to be a systemd journal.
It can be set to `default` to scan the default systemd journal or another directory containing the journal.

| Directive   | Type   | Description |
| ---------   | ------ | ----------- |
| journal_dir | string | Tail systemd journal DIRECTORY; can override with command line options `-J` or `--journal-dir `|
| blob_fields | list   | Set of fields that 'journalctl' may emit as blobs and should be decoded [default: ["MESSAGE"]] |

### Log file options

The `logfiles` directive defines the source to be a set of text files.

| Directive | Type   | Description |
| --------- | ------ | ----------- |
| logfiles  | list   | Set of log files to read; can override with comand line options `-f` or `--tail-file` or directive `tail_file` [default: 0] |
| onelog    | int    | Scan all log files for a service as a single log; the default is to scan and output each log file individually. [default: 0] |


### Custom log parsers

Text log files structured as JSON text are parsable by default.
Custom parsers parsers can be implemented for traditional text log files or if you want to customize the field set for JSON logs beyond current capabilities.
A custom parser is defined in a `source_parser.py` in the source directory.
The custom parser is used to convert each log line into a dictionary of fields and values.
You can see examples of this in a few services in `contrib-config.d`.


## Services

Services define how log entries should be grouped together and which entries are interesting.
Each subdirectory of a log source defines a service.
Each source must have at least one service.
If a source only has one service, the service can be defined in the source directory itself.
All enabled services for enabled sources are scanned by default.
Specific services for a source can be enabled with the `--service` command line option and the `services` configuration file directive.

### Service options

A service directory must contain a `service.yaml` configuration file that define the options for the service.
Service configuration options inherit and override options from their source and the main configuration file.
(Relevant command line arguments override all options.)

Services can set options described in [source options](#source-options) as well as those below.

| Directive          | Type   | Description |
| -------            | ----   | ----------- |
| json_field         | string | Field to parse as a JSON dictionary and merge with log entry fields; only entries that match [select](#claiming-log-entries) rules will be parsed; fields can be used in pass and drop rules; `rewrite_fields`, `rstrip_fields` and `field_types` will be applied. [default: none] |
| json_field_prefix  | string | Prefix to apply to dictionary field names before merging. [default: none] |
| json_field_unset   | bool   | Unset log entry field `json_field` after merging. [default: True] |
| json_field_promote | string | Overwrite log entry field `json_field` with the value of this field after merging. [default: none] |
| json_field_warn    | bool   | Warn if log entry value cannot be parsed as JSON dictionary. [default: True] |

### Claiming log entries

Each log entry is passed to each service until the entry is claimed by a service.
Services are iterated alphabetically. (Typically services begin with a numerical "NN-" prefix to define the order.)
Services contain a set of files that define [rules](#rules) that determine the log entries associated with the service.
Service that don't define any rules (a so called "catchall" service) will claim all unclaimed entries and will be iterated last for its source.

| Rule file   | Directive         | Matching log entries will be... |
| ----        | ----------        | ----------- |
| select.yaml | select_rules_path | ...claimed by the service; select takes precedence over drop and pass rules. |
| pass.yaml   | pass_rules_path   | ...passed to further services; takes precedence over drop rules. |
| drop.yaml   | drop_rules_path   | ...claimed by the service but dropped and not available to templates. |

## Rules

Rule sets are a series of fields and conditions applied to each log entry to determine what action to take.
Rule files can be defined as YAML or JSON files.

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

| Operator | Comparison |
| -------- | ---------- |
| =        | Equals (default) |
| >        | Greater than (scalar value) |
| >=       | Greater than or equal (scalar value) |
| <        | Less than (scalar value) |
| <=       | Less than or equal (scalar value) |
| ^        | Regular expression match from beginning of string |
| ~        | Regular expression search |
| *        | Field is set (to any value) |

Prefix with `!` to negate an equality, regular expression, or field is set operator.

### Testing rules

Use `--print-rules` to review the rules and the order they are applied.

	jsonlogalert --print-rules

Use `--dry-run` to scan logs without updating offset/cursors and monitor which services claim log entries.
Use different output options to review generated content.

	jsonlogalert -vv --dry-run --output-devnull
	jsonlogalert -vv --dry-run --output-stdout
	jsonlogalert -vv --dry-run --output-file-dir .


## Outputs

Outputs determine what happens to the content after a service has gathered intersting log entries and composed content using a template.
If an output is specified on the command line, all other outputs are disabled.
If the "devnull" output is enabled, all outputs are disabled and nothing will be output.

### Console

| Directive            | Command line           | Description |
| ---------            | ------------           | ----------- |
| output_stdout        | --output-stdout        | Output results to stdout; if used with SMTP output; no email will be sent. |
| output_devnull       | --output-devnull       | Output results to /dev/null; that is, output nothing!  |

### File

Set either of these options to save output to file.
File output can be combined with the `output_stdout` and SMTP outputs.

| Directive        | Command line       | Description |
| ---------        | ------------       | ----------- |
| output_file_dir  | --output-file-dir  | Output results to file in DIRECTORY; file names will be based on source and service; default is current working directory. |
| output_file_name | --output-file-name | Output results to FILENAME in `output_file_dir` when a single SERVICE is specified. |

### SMTP

Set `output_smtp_rcpt` to compose a message and send via SMTP.
If `output_stdout` is enabled, the SMTP message will be output to stdout, which is mostly helpful for debugging.

| Directive                 | Command line                | Description |
| ---------                 | ------------                | ----------- |
| output_smtp_rcpt          | --output-smtp-rcpt          | Email recipient address. Required. |
| output_smtp_sender        | --output-smtp-sender        | Email sender address. [default: recipient address] |
| output_smtp_rcpt_name     | --output-smtp-rcpt-name     | Email recipient name. [default: none] |
| output_smtp_sender_name   | --output-smtp-sender-name   | Email sender name. [default: recipient name] |
| output_smtp_subject       | --output-smtp-subject       | Email subject line. [default: "Unusual activity for %SERVICEDESC%"] |
| output_smtp_host          | --output-smtp-host          | Mail server hostname or address. [default: localhost] |
| output_smtp_port          | --output-smtp-port          | Mail server port. [default: 25] |
| output_smtp_auth_ssl      | --output-smtp-auth-ssl      | Mail server uses SSL connection. [default: no] |
| output_smtp_auth_tls      | --output-smtp-auth-tls      | Mail server uses TLS. [default: no] |
| output_smtp_auth_username | --output-smtp-auth-username | Mail server authentication username. [default: none] |
| output_smtp_auth_password | --output-smtp-auth-password | Mail server authentication password. [default: none] |

The sender, recipient and subject options can contain placeholders to be replaced when each message is composed.

| Placeholder    | Value                    |
| -----------    | -----                    |
| %HOSTNAME%     | Host name.               |
| %SOURCENAME%   | Log source name.         |
| %SERVICENAME%  | Log service name.        |
| %SERVICEDESC%  | Log service description. |

## Templates

Templates are used to compose content using log entries claimed by the service.
Templates are Python [Jinja2 templates](http://jinja.pocoo.org/docs/templates/).
You can see example templates for services in `contrib-config.d`.
Templates can create any type of text content.

The general structure of a template is to iterate log entries and show fields of interest.

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

### Template functions

&bull; `logentries_groupby` - Group `logentries` by one or more field values.

	```
	def logentries_groupby(
		fields: str | Sequence,
		default_group: str | Sequence | None = None,
		default_last: bool = True,
	) -> ItemsView[str | tuple[str], list[LogEntry]]:

	Args:
		fields (str | Sequence): Field name or sequence of fields (list or tuple).
		default_group (str | Sequence | None, optional): Default group value or sequence of values. Defaults to 'fields'.
		default_last (bool): Sort default group first or last. Defaults to last.

	Returns:
		ItemsView: ItemsView[(group, logentries)] where `group` is a field value or tuple of field values.

	Example:
		{%- for (systemd_unit, syslog_id), group_entries in logentries_groupby(("_SYSTEMD_UNIT", "SYSLOG_IDENTIFIER")) -%}
	```

#### Log entry properties

Fields for each log entry element in `logentries` are accessed as properties.
Fields available depend on those the source defines and those [captured](#source-options) by the service.

Standard properties include:

| Property  | Description |
| -------   | ----------- |
| fields    | Dictionary of captured fields, sorted by field name; does not include concealed fields. |
| rawfields | Dictionary of all captured fields. |
| timestamp | Log entry timestamp. |
| message   | Log entry message. |

Each log source defines it's own set of fields.
The systemd journal and the services that log to it include dozens of
fields such as `_SYSTEMD_UNIT`, `SYSLOG_IDENTIFIER`, and `PRIORITY`.


## Run periodically or on demand

Logs can be scanned on a scheduled interval or when a log file is modified.
This can be managed with systemd timer and/or path units.
Examples are included in the `systemd` directory of the distribution.

## Python systemd package

Jsonlogalert requires the `systemd` Python package be installed.
Depending your operating system, this may be installed and hard-coded to the base distribution Python version.
We create our virtual environment with `--system-site-packages` and do not include
in `pyproject.toml` `dependencies` the system installed module is referenced.

You can see that `python3-systemd` is hard-coded to Python 3.9 for Red Hat Enterprise Linux 9.4:

	$ dnf repoquery -l python3-systemd

If your installation does not have the package, you can review installation instructions
on the [systemd GitHub repo](https://github.com/systemd/python-systemd).
(Be aware there are variations of 'python-systemd' that are not from the official 'systemd'.)

## Install for development

	git clone https://github.com/lovette/jsonlogalert.git
	cd jsonlogalert/
	make virtualenv
	make install-dev
