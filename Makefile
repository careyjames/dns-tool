VERSION = 1.0.0

.PHONY: build clean

build: .venv
	. .venv/bin/activate && pyinstaller --onefile dnstool.py --name dnstool-$(VERSION)

clean:
	rm -rf build dist __pycache__

.venv:
	python3 -m venv .venv
	. .venv/bin/activate && pip install -r requirements.txt
	touch .venv
