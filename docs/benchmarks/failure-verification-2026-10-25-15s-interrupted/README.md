# Interrupted 15-second verification

This series was stopped after the user requested a 30-second JavaScript worker timeout. It completed 44 main receipts (36 protocol success, 8 failure) of 110 planned main, inventory and PE-resource receipts. The in-progress workflow was interrupted and is excluded from those counts. This is not a completed five-round comparison.

The runner received SIGINT and completed its owned-process cleanup. Its root and observed REA child were no longer alive when their process identities were checked. This observation does not rule out descendants missed between samples.

The frozen binary provenance and interruption record are in [execution.json](execution.json). [Completed receipts](main-raw.json) retain the costs and errors measured before interruption. The original work directory remains available locally for detailed responses.

A separate series uses the same binaries with a caller-selected 30-second worker budget. The prior published 15-second results remain unchanged.
