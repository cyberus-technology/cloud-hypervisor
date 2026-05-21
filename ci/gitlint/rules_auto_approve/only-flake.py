# Copyright © 2026 Cyberus Technology GmbH
#
# SPDX-License-Identifier: Apache-2.0
#
from gitlint.options import ListOption, StrOption
from gitlint.rules import CommitRule, RuleViolation

class SingleSpecificFile(CommitRule):
    """Reject commits which modifies files other than those specified"""
    id = "UC-flake"
    name = "body-require-single-specific-file"
    description = "Commit must change exactly one specific file"
    target = None  # Applies to entire commit
    options_spec = [
        StrOption(
            "filepath",
            "flake.lock",
            "The file path to check"
        )
    ]

    def validate(self, commit):
        changed_files = getattr(commit, "changed_files", None)
        if changed_files is None:
            # Newer gitlint commit objects expose the touched paths directly via
            # `changed_files`. Older variants may only expose
            # `changed_files_stats`, a mapping keyed by changed path, so we fall
            # back to its keys when `changed_files` is unavailable.
            changed_files_stats = getattr(commit, "changed_files_stats", {})
            changed_files = list(changed_files_stats.keys())

        if len(changed_files) != 1:
            return [RuleViolation("commit-changes-multiple-files-or-none", f"Commit changes {len(changed_files)} files, expected exactly 1: {', '.join(changed_files)}")]

        filepath = self.options["filepath"].value
        if changed_files[0] != filepath:
            return [RuleViolation("commit-wrong-file", f"Commit changes '{changed_files[0]}', expected only '{filepath}'")]

####################
# Usage of this rule
####################
#
# .gitlint_auto_approve file
# [general]
# extra-path=ci/gitlint/rules_auto_approve
# regex-style-search=true
# ignore=body-is-missing,body-max-line-length

# # default 72
# [title-max-length]
# line-length=72

# # Empty bodies are fine
# [body-min-length]
# min-length=0

# [UC-flake]
# filepath=flake.lock

## run with
# nix run nixpkgs#gitlint -- --commits origin/main.. -C .gitlint_auto_approve
