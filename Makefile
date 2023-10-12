help:
		@echo "lint - run clippy and rustfmt"
		@echo "lint-unstable - run clippy, rustfmt and rustc lints with unstable features. expect errors, which cannot be resolved, so the user must step through and evaluate each one manually."
		@echo "notes - generate release notes"
		@echo "release - publish a new release"
		@echo "create-docker-image - create docker image"
		@echo "push-docker-image - push docker image"

lint:	
		cargo clippy --all --all-targets --all-features --no-deps -- --deny warnings
		cargo fmt --all -- --check

lint-unstable:
		cargo clippy --all --all-targets --all-features --no-deps -- -Wclippy::cargo
		cargo fmt --all -- --check
		RUSTFLAGS="-W unused_crate_dependencies" cargo build

create-docker-image:
		docker build -t ethpm/trin:latest -t ethpm/trin:$(version) -f ./Dockerfile .
	
push-docker-image:
		docker push ethpm/trin:latest ethpm/trin:$(version)
