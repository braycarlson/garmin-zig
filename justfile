set shell := ["sh", "-c"]
set windows-shell := ["powershell.exe", "-c"]

[doc('List activities: just activities [start] [limit]')]
activities start="0" limit="20":
    zig build run -- activities {{ start }} {{ limit }}

[doc('Compile every artifact without running it')]
check:
    zig build check

[doc('Run the continuous integration pipeline')]
ci:
    zig build ci
    zig build test:unit -Doptimize=safe

[doc('Print the built-in consumer credentials')]
consumer:
    zig build run -- consumer

[doc('Download one activity: just download <id> <path>')]
download id path:
    zig build run -- download {{ id }} {{ path }}

[doc('Download every activity into a directory: just download-all [directory]')]
download-all directory="activities":
    zig build run -- download-all {{ directory }}

[doc('Format build.zig and every source file')]
fmt:
    zig fmt build.zig src

[doc('Run a fuzzer: just fuzz <fuzzer> [seed] [events]')]
fuzz *arguments:
    zig build fuzz -- {{ arguments }}

[default]
[doc('List every recipe')]
list:
    @just --list

[doc('Authenticate against Garmin Connect and cache the tokens')]
login:
    zig build run -- login

[doc('Run the CLI: just run <arguments>')]
run *arguments:
    zig build run -- {{ arguments }}

[doc('Run every test suite and the format check')]
test:
    zig build test

[doc('Run the unit tests and the tidy check: just unit [filter]')]
unit filter="":
    zig build test:unit {{ if filter == "" { "" } else { "-Dtest-filter=" + filter } }}
