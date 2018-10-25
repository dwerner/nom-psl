# Faster public suffix domain parsing.
The scope of this library is limited to finding the tld+1 of a given domain from the public suffix list.

### Approach:
- Load public suffix list entries into memory
- Match immutable, owned values of domains to be parsed

### Goals:
- provide (mostly) compliant public suffix domain parsing.
- avoid allocations during domain parsing.
- offload as much work as possible to parsing stage.
- avoid depedencies that might themselves bring unwanted baggage
- inputs are not mutated, outputs are slices of inputs

### Caveats:
- still rely on idna crate for punycode parsing
- we don't lower-case anything (for performance we ignore this)

### Environment Variables
`PUBLIC_SUFFIX_LIST_FILE=somefile` - override which file will be loaded in place of `public_suffix_list.dat`

## Example:
```
lazy_static! {
    static ref LIST: List = {
        let list = List::parse_source_file("public_suffix_list.dat");
        list.expect("unable to parse PSL file")
    };
}

...

fn foo() {
    let domain = "abc.one.two.example.co.uk";
    let tldp1 = LIST.parse_domain(domain);
    
    assert_eq!(tldp1, Some("example.co.uk"));
}
```

#### TODO:
- benchmarks
