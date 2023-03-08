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
