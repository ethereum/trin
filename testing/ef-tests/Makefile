TARGET = mainnet.tar.gz
EXTRACT_DIR = mainnet
LATEST_RELEASE_URL = https://api.github.com/repos/ethereum/consensus-spec-tests/releases/latest

.PHONY: all clean

all: test

$(EXTRACT_DIR): $(TARGET)
	@if [ -d $(EXTRACT_DIR) ]; then \
		echo "$(EXTRACT_DIR) already exists. Skipping extraction."; \
	else \
		echo "Extracting $(TARGET) into $(EXTRACT_DIR)..."; \
		mkdir -p $(EXTRACT_DIR); \
		tar -xzf $(TARGET) -C $(EXTRACT_DIR); \
		echo "Extraction complete."; \
	fi

$(TARGET):
	@if [ -f $(TARGET) ]; then \
		echo "$(TARGET) already downloaded. Skipping download."; \
	else \
		echo "Fetching the latest release URL for $(TARGET)..."; \
		curl -s $(LATEST_RELEASE_URL) \
		| grep "browser_download_url.*$(TARGET)" \
		| cut -d : -f 2,3 \
		| tr -d \" \
		| wget -qi -; \
		echo "$(TARGET) downloaded successfully."; \
	fi

test: $(EXTRACT_DIR)
	@echo "Running tests..."
	@cargo test --features ef-tests
	@echo "Tests complete."

clean:
	@echo "Cleaning up downloaded and extracted files..."
	@rm -f $(TARGET)
	@rm -rf $(EXTRACT_DIR)
	@echo "Clean up complete."
