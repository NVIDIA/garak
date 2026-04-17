outdir := html

doc:
	@echo "Building docs to '`pwd`/$(outdir)'"
	python -m sphinx -T -E -b html -d _build/doctrees -D language=en ./ $(outdir)

clean:
	@echo "Clearing docs output"
	rm -rf $(outdir) generated _build

cliref:
	@echo "Building CLI reference"
	@echo "CLI reference for garak" > cliref.rst
	@echo "=======================" >> cliref.rst
	@echo >> cliref.rst
	@echo "::" >> cliref.rst
	@echo >> cliref.rst
	@cd ../.. ; python3 -m garak --help | sed 's/^/  /' >> docs/source/cliref.rst

all: clean cliref doc
