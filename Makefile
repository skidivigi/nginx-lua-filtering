up:
	docker compose up -d --build

down:
	docker compose down

restart:
	docker compose down
	docker compose up -d --build

logs:
	docker compose logs -f

logs-nginx:
	docker compose logs -f nginx

logs-scanner:
	docker compose logs -f scanner

logs-clamav:
	docker compose logs -f clamav

generate-pdfs:
	python3 scripts/make_test_pdfs.py

test-clean-pdf:
	curl -i \
		-F "file=@samples/clean.pdf;type=application/pdf" \
		http://localhost:8080/some/random/path

test-js-pdf:
	curl -i \
		-F "file=@samples/js_action.pdf;type=application/pdf" \
		http://localhost:8080/some/random/path

test-eicar-txt:
	printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$$H+H*' > samples/eicar.txt
	curl -i \
		-F "file=@samples/eicar.txt;type=text/plain" \
		http://localhost:8080/some/random/path

test-eicar-pdf:
	curl -i \
		-F "file=@samples/eicar.pdf;type=application/pdf" \
		http://localhost:8080/some/random/path