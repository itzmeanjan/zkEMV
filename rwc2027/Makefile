.DEFAULT_GOAL := help

.PHONY: help
help: ## Shows available recipes
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: proposal
proposal: ## Compiles LaTeX, generates RWC 2027 talk proposal as PDF
	@echo "Compiling LaTeX, producing PDF proposal..."
	latexmk -pdf -silent -auxdir=build -outdir=. zkemv.tex

.PHONY: clean
clean: ## Removes LaTeX build directory
	rm -rf build
