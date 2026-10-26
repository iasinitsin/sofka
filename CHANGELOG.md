# Changelog

## v0.32.0 - 2026-10-22

This release changes how keys look in status bar and popup hints. It also adds a way to set a HelmRelease chart version and fixes log scrolling.

### New features

- Keys in the status bar and popup footers now appear in bold, in the key color. You can see each key more easily.
- Press `i` on a Flux `HelmRelease` to set `spec.chart.spec.version`. You no longer need to open the editor to change one field.

### Fixes

- Long log lines now scroll sideways with the arrow keys, or with `h` and `l`. You can read the end of a long line without turning on wrap.
- The namespaces header now shows `R resources`. You can find the `R` key in the view itself.

## v0.31.14 - 2026-10-20

This release fixes owner navigation in Shift-J and `:bundle`. A pod owned by a custom resource now opens the correct kind.

### Fixes

- Shift-J and `:bundle` now find the owner of a pod in the correct API group. Before this fix, a custom resource with the same kind name as a built-in kind opened the wrong kind. If the cluster does not serve the owner group, sofka reports the owner as unresolved.
