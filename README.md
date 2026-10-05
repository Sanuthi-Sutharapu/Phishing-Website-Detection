# Phishing Website Detection (built from scratch)

Stages 1-3 of the build: setup, data collection, URL feature extraction.

## Stage 1: Setup on Windows

1. Install Python 3.11 or newer from python.org. Tick **"Add python.exe to PATH"** in the installer.
2. Extract this folder, then open it in VS Code (File > Open Folder).
3. Open a terminal in VS Code (Ctrl + `) and run:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

If PowerShell blocks the activate script, run this once and try again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

4. In VS Code press Ctrl+Shift+P, choose **Python: Select Interpreter**, and pick the `.venv` one.

## Check everything works

```powershell
python -m unittest discover -s tests -v
```

You should see 10 tests pass.

## Stage 2: Collect data

```powershell
python src/collect_data.py --n-sites 3000
```

- Downloads a list of phishing URLs (OpenPhish). It only saves the text of the list and **never opens those URLs**.
- Downloads the Tranco top-sites list and visits ordinary popular sites to collect real links (takes a few minutes).

If a download fails, put files in `data/raw/` by hand:
- `openphish.txt`: one phishing URL per line (from openphish.com/feed.txt)
- `phishtank.csv`: optional, with a `url` column (from phishtank.org)
- `legit_urls.txt`: one legitimate URL per line

## Stage 3: Build the feature table

```powershell
python src/build_dataset.py
```

Creates `data/processed/dataset.csv` (URL, host, label where 1 = phishing, and 32 features).
Add `--balance` to downsample to equal class sizes.

## Safety

Never open URLs from the phishing list in your normal browser. Everything in this project works on the URL text only.

## Layout

```
src/features.py        URL -> features (used in training AND live prediction)
src/collect_data.py    downloads/collects raw URLs
src/build_dataset.py   raw URLs -> data/processed/dataset.csv
tests/                 unit tests
models/  app/          used in the next stages
```

## Full workflow (run from this folder, venv active)

```powershell
python -m unittest discover -s tests          # 10 tests should pass
python src/collect_data.py --n-sites 3000     # phishing list + legit links (run again daily, phishing lists accumulate)
python src/build_dataset.py                   # raw URLs -> data/processed/dataset.csv
python src/train.py                           # trains 4 models, saves models/model.joblib
python src/analyze.py                         # optional: threshold table and the model's mistakes
python app/server.py                          # then open http://127.0.0.1:5000
```

Optional, for page-content features (run right after refreshing the phishing list, pages die fast):

```powershell
python src/fetch_pages.py --source phishing
python src/fetch_pages.py --source legit --limit 1500
```

Optional, for brand-new phishing in the web app (key from Google Cloud, Safe Browsing API):

```powershell
$env:GOOGLE_SAFE_BROWSING_KEY="your-key"
python app/server.py
```
