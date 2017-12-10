## BOOTSTRAP

```bash
sudo apt install python3-virtualenv virtualenv
```

```bash
cd cryptopals_challange_python
virtualenv -p python3 venv
pip install -r requirements.txt
```

## USAGE

### Requirement
Activate virtual environment every time you want to run a test.
```bash
source venv/bin/activate
```

## Run test
Tests contain actual code that passes matasano cryptochallange.
```bash
python set01_unittest.py
```
