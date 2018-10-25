# Faster public suffix domain parsing.

Goals:
- provide (mostly) compliant public suffix domain parsing.
- avoid allocations during parsing.
- offload as much work as possible to parsing stage.
- avoid depedencies that might themselves bring unwanted baggage
- inputs are not mutated, outputs are slices of inputs

Caveats:
- still rely on idna crate for punycode parsing
- we don't lower-case anything (for performance we ignore this)

Use example:

```
//TODO
```
