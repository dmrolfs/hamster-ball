<!-- ABOUTME: License and provenance notice for the vendored data files in this directory. -->
<!-- ABOUTME: data files are vendored and never hand-edited; see scripts/update-psl.sh to refresh. -->

# Vendored data

## `public_suffix_list.dat`

Source: <https://publicsuffix.org/list/public_suffix_list.dat>
License: Mozilla Public License 2.0 (header retained in the file).
Vendored unmodified, byte for byte. Refresh with `scripts/update-psl.sh`.

## `extra_protected_suffixes.txt`

Hand-maintained by this project. Lists tenant-hosting namespaces that the Public Suffix List
does not (yet) cover, so that a config wildcard such as `*.storage.googleapis.com` is still
rejected. See the file's own header for sources and the date each entry was verified.

This project does not control these domains and cannot submit them to the Public Suffix List
(submission requires the domain's own administrator); see
<https://github.com/publicsuffix/list/issues/1137> for an example of a tracked, acknowledged gap
of this kind (`cloudapp.azure.com`).
