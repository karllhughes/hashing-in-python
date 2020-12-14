# Hashing in Python
This repo includes code samples for Okta's Ultimate Guide to Password Hashing in Python.

This repo is just a testing/placeholder repo. The real content will be in the guide.

That said, if you want to run any of the hashing algorithms, you can use your Python env or Docker. Just uncomment 
the appropriate lines in `main.py` and run it:

```bash
docker build -t hashing-py .
docker run -it -v $(pwd):/app --rm hashing-py
```
