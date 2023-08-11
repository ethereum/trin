# Contribute to trin Book

## Using the book

The book can be built and served locally.

### Installing book tools

The first time you work on the book, you need to install mdbook and the mermaid
tool to generate diagrams:
```sh
cargo install mdbook mdbook-mermaid
cd book/
mdbook-mermaid install
cd ..
```
This will create `mermaid.min.js` and `mermaid-init.js` files.

### Running the book server

Then run the book from the book crate:
```sh
cd book/
mdbook serve --open
```
Or, from the project root:
```sh
mdbook serve --open ./book
```

## Adding new pages

Add a new entry to `./book/src/SUMMARY.md`. Follow the style there, which
follows strict formatting. There are two kinds of additions:

- New single section
    - Tab to the appropriate depth
    - Add a `[Section name](section_name.md)`
- New nested section
    - Tab to the appropriate depth
    - Add a `[Section name](section_name/README.md)`
        - Add `[Subsection one](section_name/subsection_one.md)`
        - Add `[Subsection two](section_name/subsection_two.md)`

Don't create these pages, the `./book/src/SUMMARY.md` file is parsed and any missing
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

## Crate documentation location

Workspace crates are published to crates.io and include the `README.md` in the root of the crate.
This is valuable to have when using the crates outside of the context of Trin
E.g., `ethportal-api`.

Any documentation of workspace crates in the book should therefore be limited to explaining
how the crate interacts with the other workspaces in the context of Trin. Rather than moving
the workspace `README.md`'s to the book.
