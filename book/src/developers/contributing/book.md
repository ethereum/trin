# Book

## Using the book

The book can be built and served locally.
```sh
cargo install mdbook
```
Install support for `mermaid` diagrams:
```sh
cd book
cargo install mdbook-mermaid
mdbook-mermaid install
```
This will create `mermaid.min.js` and `mermaid-init.js` files.

Then run the book from the book crate:
```sh
mdbook serve --open
```
Or the project root:
```sh
mdbook serve --open ./book
```

## Adding new pages

Add a new entry to `./book/SUMMARY.md`. Follow the style there, which
follows strict formatting. There are two kinds of additions:

- New single section
    - Tab to the appropriate depth
    - Add a `[Section name](section_name.md)`
- New nested section
    - Tab to the appropriate depth
    - Add a `[Section name](section_name/README.md)`
        - Add `[Subsection one](section_name/subsection_one.md)`
        - Add `[Subsection two](section_name/subsection_two.md)`

Don't ceate these pages, the `./book/SUMMARY.md` file is parsed and any missing
pages are generated when `mdbook serve` is run. Content can then be added to the
generated pages.

Then run serve:
```sh
mdbook serve --open
```

## Test

To test the code within the book run:
```sh
mdbook test
```

## Links

To keep the book easy to manage, avoid:
- External links likely to change
- Internal links to other pages or sections

Relative links to locations outside the `./book` directory are not possible.

## Diagrams

Diagrams can be added using mermaid annotations on a normal code block:

```sh
    ```mermaid
    graph TD;
        A-->B;
        A-->C;
        B-->D;
        C-->D;
    ```
```
The above be converted to the following during book-building:
```mermaid
graph TD;
    A-->B;
    A-->C;
    B-->D;
    C-->D;
```

### Installation

Installation is required to enable diagram generation

```sh
cd book
cargo install mdbook-mermaid
mdbook-mermaid install
```

## Crate documentation location

Workspace crates are published to crates.io and include the `README.md` in the root of the crate.
This is valuable to have when using the crates outside of the context of Trin
E.g., `ethportal-api`.

Any documentation of workspace crates in the book should therefore be limited to explaining
how the crate interacts with the other workspaces in the context of Trin. Rather than moving
the workspace `README.md`'s to the book.