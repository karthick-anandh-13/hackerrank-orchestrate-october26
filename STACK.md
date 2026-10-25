# Stack

- Python 3, standard library
- CSV and JSON inputs/outputs
- SQLite-compatible SQL snapshot parsing via Python `sqlite3`
- Optional local `pdftotext` and `tesseract` utilities for document/image text extraction
- `unittest` regression suite
- `zipfile` packaging; no hosted model API calls are made by the final pipeline

Run from the repository root on Linux:

```sh
python3 -m unittest discover -s tests -v
python3 -m code.main
python3 -m code.validate_output
python3 -m code.evaluation.main
```
