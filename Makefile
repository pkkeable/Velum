PYTHON ?= python3
.PHONY: run test check demo
run:
	$(PYTHON) -m privacy_cleanup
test:
	$(PYTHON) -m scripts.run_tests
	node --test tests/private_ui.test.cjs
check:
	$(PYTHON) -m scripts.check_public_tree --history
	$(PYTHON) -m scripts.check_release
	node --check privacy_cleanup/static/app.js
	node --check privacy_cleanup/static/private.js
demo:
	$(PYTHON) -m scripts.demo
