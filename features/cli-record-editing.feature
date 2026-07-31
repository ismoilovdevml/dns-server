Feature: Editing zone records from the command line
  # WHY THIS MATTERS
  # This is the write path to production DNS, and its callers are increasingly
  # not humans — configuration management, deploy scripts, and agents run these
  # commands unattended. That imposes three obligations. Edits must be idempotent
  # and must say honestly what they changed, because a script that cannot tell
  # "already correct" from "just changed it" will either loop forever or bump a
  # serial on every run. Invalid input must be rejected *before* anything is
  # written, because a config file that fails to parse is a name server that will
  # not restart. And the operator's comments and layout must survive, because a
  # tool that reformats the file on every edit makes every diff unreviewable and
  # trains people to stop reading them.
  #
  # Implementation: src/editor.rs (toml_edit document, atomic write)
  #                 src/commands/record.rs (add/delete/list/get, JSON shapes)

  # ------------------------------------------------------------------- ADD

  @happy @enforced src/editor.rs:521
  Scenario: Adding a new record set reports it as created
    Given a config file containing one A record for "www"
    When "api" A "203.0.113.20" is added
    Then the change is reported as created

  @happy @enforced src/commands/record.rs:388
  Scenario: A created record set is persisted to disk
    Given a config file containing one A record for "www"
    When "api" A "203.0.113.20" is added
    Then reopening the file shows 2 record sets

  @happy @enforced src/editor.rs:536
  Scenario: Adding a new value to an existing set reports it as extended
    Given a config file containing "www" A "203.0.113.10"
    When "www" A "203.0.113.11" is added
    Then the change is reported as extended
    And the set holds both values in order

  @happy @enforced tests/cli.rs:120
  Scenario: The CLI reports created, extended and unchanged in sequence
    Given an initialised workspace
    When "www" A "203.0.113.10" is added
    Then the JSON change is "created"
    When "www" A "203.0.113.11" is added
    Then the JSON change is "extended"
    When "www" A "203.0.113.11" is added again
    Then the JSON change is "unchanged"

  @happy @enforced tests/cli.rs:255
  Scenario: An apex record is accepted and recorded under "@"
    Given an initialised workspace
    When "@" A "203.0.113.1" is added
    Then the process exits zero
    And the JSON record name is "@"

  @happy @enforced tests/cli.rs:255
  Scenario: A wildcard owner name is accepted
    Given an initialised workspace
    When "*.apps" A "203.0.113.30" is added
    Then the process exits zero
    And the JSON record name is "*.apps"

  @happy @enforced tests/cli.rs:255
  Scenario: An MX value in presentation format is accepted
    Given an initialised workspace
    When "@" MX "10 mail.example.com." is added
    Then the process exits zero

  # -------------------------------------------------------------- REPLACE

  @happy @enforced src/editor.rs:557
  Scenario: Replacing overwrites the whole value list
    Given a config file containing "www" A "203.0.113.10"
    When "www" A "198.51.100.1" is added with replace
    Then the change is reported as replaced
    And the set holds only "198.51.100.1"

  @happy @enforced tests/cli.rs:120
  Scenario: The CLI reports a replace and returns the new value list
    Given a workspace where "www" A holds "203.0.113.10" and "203.0.113.11"
    When "www" A "198.51.100.1" is added with replace
    Then the JSON change is "replaced"
    And the JSON values are exactly "198.51.100.1"

  @boundary @gap
  Scenario: Replacing with a TTL where none was set records the TTL
    # The `replace` branch calls set_ttl(table, ttl) with Some. Untested.
    Given a config file containing "www" A "203.0.113.10" with no TTL
    When "www" A "203.0.113.10" is added with replace and TTL 60
    Then the change is reported as replaced
    And the set records a TTL of 60

  @boundary @gap
  Scenario: Replacing without a TTL removes an existing TTL
    # src/editor.rs:438-440 (the None arm of set_ttl) is uncovered. An operator
    # replacing values would silently lose their TTL override, and nothing warns
    # or tests for it.
    Given a config file containing "www" A "203.0.113.10" with TTL 60
    When "www" A "198.51.100.1" is added with replace and no TTL
    Then the set records no TTL

  @boundary @enforced src/editor.rs:604
  Scenario: Adding a TTL to an existing set without replace reports it as extended
    Given a config file containing "www" A "203.0.113.10" with no TTL
    When "www" A "203.0.113.10" is added with TTL 30
    Then the change is reported as extended

  # ------------------------------------------------------------ IDEMPOTENCY

  @happy @enforced src/editor.rs:536
  Scenario: Adding a value that is already present is unchanged and not duplicated
    Given a config file containing "www" A "203.0.113.10" and "203.0.113.11"
    When "www" A "203.0.113.11" is added
    Then the change is reported as unchanged
    And the set still holds 2 values

  @happy @enforced src/editor.rs:567
  Scenario: Replacing with content identical to what is there is unchanged
    Given a config file containing "www" A "203.0.113.10"
    When "www" A "203.0.113.10" is added with replace
    Then the change is reported as unchanged

  @happy @enforced tests/cli.rs:120
  Scenario: An idempotent edit exits zero
    # A script that treats "already correct" as a failure will thrash.
    Given a workspace where "www" A already holds "203.0.113.11"
    When "www" A "203.0.113.11" is added
    Then the process exits zero

  @happy @enforced src/commands/record.rs:431
  Scenario: A serial bump only fires when something actually changed
    Given a config file with SOA serial 7
    When "api" A "203.0.113.20" is added with bump-serial
    Then a new serial is reported
    When the same record is added again with bump-serial
    Then the change is reported as unchanged
    And no new serial is reported
    And the file still carries the earlier serial

  @happy @enforced tests/cli.rs:298
  Scenario: Repeated serial bumps never move the serial backwards
    Given an initialised workspace
    When the serial is bumped twice
    Then the second serial is greater than or equal to the first

  @boundary @enforced src/commands/mod.rs:134
  Scenario: A second bump on the same day increments the counter
    Given a previous serial of 2026073001 and today is 2026-07-30
    When the next serial is computed
    Then the serial is 2026073002

  @boundary @enforced src/commands/mod.rs:127
  Scenario: The first bump of a day starts the counter at 01
    Given a previous serial from yesterday and today is 2026-07-30
    When the next serial is computed
    Then the serial is 2026073001

  @boundary @enforced src/commands/mod.rs:140
  Scenario: The 100th bump in one day holds steady rather than rolling into tomorrow
    Given a previous serial of 2026073099 and today is 2026-07-30
    When the next serial is computed
    Then the serial is unchanged at 2026073099

  @boundary @enforced src/commands/mod.rs:148
  Scenario: A serial already in the future is left alone
    Given a previous serial of 2027010105 and today is 2026-07-30
    When the next serial is computed
    Then the serial is unchanged

  @empty @enforced src/commands/mod.rs:127
  Scenario: A file with no serial at all gets today's first serial
    Given no previous serial and today is 2026-07-30
    When the next serial is computed
    Then the serial is 2026073001

  @boundary @enforced src/editor.rs:693
  Scenario: Setting a serial creates the SOA table when the file has none
    Given a config file with a zone table but no SOA table
    When the serial is set to 5
    Then the file declares serial 5

  # ------------------------------------------------------------------ DELETE

  @happy @enforced src/editor.rs:623
  Scenario: Deleting one value keeps the remaining values
    Given a config file containing "www" A "203.0.113.10" and "203.0.113.11"
    When the value "203.0.113.10" is deleted from "www" A
    Then the change is reported as removed
    And the set holds only "203.0.113.11"

  @boundary @enforced src/editor.rs:637
  Scenario: Deleting the last value drops the whole record set
    Given a config file containing "www" A "203.0.113.10"
    When the value "203.0.113.10" is deleted from "www" A
    Then the change is reported as removed
    And the file contains no record sets

  @happy @enforced src/editor.rs:647
  Scenario: Deleting with no type removes every type at that name
    Given a config file containing "www" A and "www" TXT
    When "www" is deleted with no type given
    Then the change is reported as removed
    And the file contains no record sets

  @happy @enforced tests/cli.rs:217
  Scenario: The CLI deletes a single value and reports the remainder
    Given a workspace where "www" A holds two values
    When one value is deleted via the CLI
    Then the JSON change is "removed"
    And the JSON values hold only the survivor

  @empty @enforced src/editor.rs:660
  Scenario: Deleting a record that is not there is unchanged
    Given a config file containing "www" A
    When "ghost" A is deleted
    Then the change is reported as unchanged
    And the file still contains 1 record set

  @empty @enforced tests/cli.rs:217
  Scenario: Deleting something absent exits zero
    Given an initialised workspace
    When "ghost" A is deleted
    Then the process exits zero
    And the JSON change is "unchanged"

  @empty @enforced src/editor.rs:668
  Scenario: Deleting from a file with no records table is unchanged
    Given a config file with a zone table and no records
    When "www" A is deleted
    Then the change is reported as unchanged

  # ------------------------------------------------- COMMENT PRESERVATION

  @happy @enforced src/editor.rs:521
  Scenario: Adding a record preserves a leading file comment
    Given a config file whose first line is a comment
    When a new record set is added
    Then the rendered document still contains that comment

  @happy @enforced src/editor.rs:521
  Scenario: Adding a record preserves a trailing inline comment
    Given a config file with an inline comment after a value
    When a new record set is added
    Then the rendered document still contains that inline comment

  @happy @enforced tests/cli.rs:280
  Scenario: An edit through the CLI preserves comments on disk
    Given an initialised workspace whose config starts with a comment
    When a record is added via the CLI
    Then the file on disk still contains that comment

  @happy @enforced src/editor.rs:701
  Scenario: A save round trip through the filesystem preserves comments
    Given a config file whose first line is a comment
    When a record is added and the file is saved and reopened
    Then the reopened document still contains that comment

  @boundary @enforced src/editor.rs:701
  Scenario: A save leaves no temporary file behind
    # write_atomically renders to a sibling ".tmp" and renames. A leftover temp
    # file in /etc would be picked up by nothing but would confuse every operator
    # who ever looked.
    Given a config file
    When a record is added and saved
    Then no .tmp files remain in the directory

  @boundary @gap
  Scenario: A crash between write and rename leaves the original file intact
    # The whole point of the atomic write. There is no test that the *original*
    # file is untouched while the temp file exists, only that the temp file is
    # gone afterwards.
    Given a config file
    When the temporary file has been written but not yet renamed
    Then the original file still holds its previous contents

  # ------------------------------------------------------------ NORMALISATION

  @boundary @enforced src/editor.rs:576
  Scenario: An empty owner name is normalised to the apex
    Given a config file
    When "" TXT is added
    Then the stored record name is "@"

  @boundary @enforced src/editor.rs:576
  Scenario: An empty name and "@" address the same record set
    Given a config file where "" TXT was already added
    When "@" TXT is added with the same value
    Then the change is reported as unchanged

  @boundary @enforced src/editor.rs:591
  Scenario: Owner name and record type matching are case-insensitive
    Given a config file containing "www" A "203.0.113.10"
    When "WWW" a "203.0.113.10" is added with replace
    Then the change is reported as unchanged

  @boundary @enforced src/commands/record.rs:520
  Scenario: A trailing dot and surrounding whitespace are stripped from a name filter
    When the name " WWW. " is normalised
    Then the result is "www"

  @boundary @enforced src/commands/record.rs:527
  Scenario: The apex is rendered as the bare origin in output
    When the apex name is rendered against origin "example.com"
    Then the result is "example.com."

  # --------------------------------------------------------------- FILTERS

  @happy @enforced tests/cli.rs:187
  Scenario: Listing with no filter returns every record set
    Given a workspace with 3 record sets
    When records are listed
    Then the JSON count is 3

  @happy @enforced tests/cli.rs:187
  Scenario: A type filter is case-insensitive
    Given a workspace with 2 A record sets and 1 TXT record set
    When records are listed with type "a"
    Then the JSON count is 2

  @happy @enforced tests/cli.rs:187
  Scenario: A name filter returns every type at that name
    Given a workspace where "www" has both A and TXT records
    When records are listed with name "www"
    Then the JSON count is 2

  @happy @enforced tests/cli.rs:187
  Scenario: Getting an existing record exits zero and reports found
    Given a workspace containing "www" A
    When "www" A is fetched
    Then the process exits zero
    And the JSON reports found true

  @empty @enforced tests/cli.rs:187
  Scenario: Getting a missing record exits non-zero so shell conditionals work
    Given an initialised workspace
    When "ghost" is fetched
    Then the process exits non-zero
    And the JSON reports found false

  @empty @gap
  Scenario: Listing a config file with no records reports a count of zero
    # The empty-table print path (src/commands/record.rs:271-277) is uncovered in
    # text mode, and no test asserts the JSON count is 0 rather than absent.
    Given a config file with no record sets
    When records are listed
    Then the JSON count is 0

  # -------------------------------------------------------------- MALFORMED

  @malformed @enforced src/editor.rs:604
  Scenario: An invalid record value is rejected before anything is written
    Given a config file containing one record set
    When "bad" A "not-an-ip" is added
    Then the edit fails with an error mentioning "invalid A value"
    And the file still contains 1 record set

  @malformed @enforced src/commands/record.rs:483
  Scenario: A rejected edit leaves the file byte-for-byte unchanged
    Given a config file
    When "bad" A "definitely-not-an-ip" is added
    Then the edit fails
    And the file contents are identical to before

  @malformed @enforced tests/cli.rs:163
  Scenario: The CLI rejects a bad value without writing and exits non-zero
    Given an initialised workspace
    When "www" A "not-an-ip" is added via the CLI
    Then the process exits non-zero
    And stderr mentions "invalid A value"
    And the file contents are identical to before

  @boundary @enforced src/rdata.rs:106
  Scenario: A record value of exactly the maximum length is accepted
    # 4090 characters. The bound is inclusive, and `record add` must be willing
    # to write anything the zone loader is willing to load.
    Given an initialised workspace
    When a 4090-character TXT value is added via the CLI
    Then the process exits zero
    And the config still passes "vega check"

  @malformed @enforced src/rdata.rs:116
  Scenario: A record value one character over the maximum is rejected
    Given a config file containing one record set
    When a 4091-character TXT value is added
    Then the edit fails with an error mentioning "the maximum is 4090"
    And the file still contains 1 record set

  @hostile @enforced tests/record_limits.rs:97
  Scenario: An oversized record value exits 1 rather than aborting the process
    # hickory's zone-file lexer asserts at 4095 characters within one token, and
    # the release profile sets panic = "abort", so an unguarded path exits 134
    # on SIGABRT with no diagnostic an operator can act on.
    Given an initialised workspace
    When a 4200-character TXT value is added via the CLI
    Then the process exits with code 1
    And stderr mentions "is 4200 characters; the maximum is 4090"
    And stderr does not mention "assertion failed"
    And the value is not written to the config

  @malformed @enforced src/editor.rs:614
  Scenario: An unknown record type is rejected
    Given a config file
    When "x" NOPE "y" is added
    Then the edit fails with an error mentioning "unknown record type"

  @malformed @enforced src/editor.rs:746
  Scenario: Opening a file with broken TOML reports a parse error
    Given a file containing "[zone\norigin ="
    When the editor opens it
    Then the error mentions "parsing"

  @empty @enforced src/editor.rs:740
  Scenario: Opening a file that does not exist reports a read error
    When the editor opens "/nonexistent/vega.toml"
    Then the error mentions "reading"

  @empty @enforced tests/cli.rs:110
  Scenario: A command run with no config file anywhere explains where it looked
    Given a directory with no config file
    When records are listed via the CLI
    Then the process exits non-zero
    And stderr mentions "no config file found"
    And stderr suggests "vega init"

  @empty @enforced src/commands/mod.rs:154
  Scenario: The missing-config error names the whole search path
    When the config path is required and none was found
    Then the error names "vega.toml"
    And the error names "--config"

  @empty @gap
  Scenario: Adding with an empty value list is rejected
    # src/editor.rs:176 bails with "no values given". Clap enforces at least one
    # value at the CLI, so this guard is only reachable through the library API —
    # and it is uncovered.
    Given a config file
    When "www" A is added with no values
    Then the edit fails with an error mentioning "no values given"

  @malformed @gap
  Scenario: A records key that is not an array of tables is reported, not overwritten
    # src/editor.rs:348 contexts "[[zone.records]] is not an array of tables".
    # Untested: a hand-edited file with `records = "oops"` must not be silently
    # clobbered.
    Given a config file where zone.records is a string
    When a record is added
    Then the edit fails with an error mentioning "array of tables"

  @malformed @gap
  Scenario: A zone key that is not a table is reported
    # src/editor.rs:339 contexts "[zone] is not a table". Untested.
    Given a config file where zone is a string
    When a record is added
    Then the edit fails with an error mentioning "not a table"

  @malformed @gap
  Scenario: A values key that is not an array is reported
    # src/editor.rs:454 contexts "`values` is not an array". Untested.
    Given a config file where a record's values key is a string
    When a value is deleted from that record
    Then the edit fails with an error mentioning "not an array"

  # ---------------------------------------------------------------- INIT

  @happy @enforced tests/cli.rs:83
  Scenario: Init writes a config file and reports it as created
    Given an empty directory
    When `vega init --origin example.com --json` runs
    Then the JSON reports created true
    And vega.toml exists

  @boundary @enforced tests/cli.rs:83
  Scenario: Init never clobbers an existing config
    Given a directory where init has already run for "example.com"
    When init runs again for "other.test"
    Then the JSON reports created false
    And the origin is still "example.com"

  @boundary @enforced src/editor.rs:723
  Scenario: Init creates missing parent directories
    Given a target path inside a directory that does not exist
    When init runs
    Then the file is created
    And its origin matches the requested origin

  @happy @enforced src/commands/zone.rs:369
  Scenario: The generated config parses as a valid config with no records
    Given a freshly initialised config
    When the file is reopened
    Then the origin matches
    And there are no record sets

  @happy @enforced tests/cli.rs:327
  Scenario: Check validates a real zone and reports what it would serve
    Given a workspace with one A record
    When `vega check --json` runs
    Then the JSON reports ok true
    And the JSON reports 1 record
    And the JSON reports an SOA is present

  @malformed @enforced tests/cli.rs:341
  Scenario: Check fails on a zone that cannot be built
    Given a config file with an invalid A value
    When `vega check` runs
    Then the process exits non-zero
    And stderr mentions "invalid A record value"

  # ------------------------------------------------------------- EXPORT

  @happy @enforced tests/cli.rs:359
  Scenario: Export emits BIND zone-file syntax
    Given a workspace with a TTL-bearing A record and an apex MX record
    When `vega zone export` runs
    Then stdout contains "$ORIGIN example.com."
    And stdout contains "www\t60\tIN\tA\t203.0.113.10"
    And stdout contains "@\tIN\tMX\t10 mail.example.com."

  @empty @gap
  Scenario: Exporting a zone with no records still emits the origin header
    # The record loop is simply skipped. Untested.
    Given a freshly initialised config
    When `vega zone export` runs
    Then stdout contains "$ORIGIN"
    And no record lines are emitted

  # ------------------------------------------------------------- OUTPUT

  @hostile @enforced tests/cli.rs:460
  Scenario: JSON output is never coloured even when colour is forced
    # A stray escape sequence makes the output unparseable for every caller.
    Given CLICOLOR_FORCE is set
    When `vega zone show --json` runs
    Then stdout contains no ANSI escape sequences
    And stdout parses as JSON

  @happy @enforced tests/cli.rs:480
  Scenario: Text output is plain when NO_COLOR is set
    Given NO_COLOR is set
    When `vega zone show` runs
    Then stdout contains no ANSI escape sequences

  @boundary @enforced src/ui.rs:382
  Scenario: Column width is measured by visible width, ignoring escape sequences
    When a styled cell is measured
    Then the escape sequences are not counted toward its width

  @happy @enforced tests/cli.rs:379
  Scenario: Shell completions are generated for the common shells
    When completions are generated for bash, zsh and fish
    Then each exits zero
    And each mentions "vega"
