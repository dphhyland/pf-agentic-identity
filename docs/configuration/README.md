# Configuration reference

Every setting each component reads - its type, default, range, what it does, what happens when it is wrong,
and which deployment profile allows it - generated from the settings catalogue by `tools/docs-generator`
(plan item ST-4, Phase 2). Nothing is written here by hand: a page here is regenerated, and CI checks it is
current.

Until the generator exists, the settings are documented by hand where they are read:
[docs/federation/configuration.md](../federation/configuration.md) for the federation (a test keeps it
complete), and the "Configuration" section of each module's README for the rest. The house style for a
settings row is in the [style guide](../development/style-guide.md#settings).
