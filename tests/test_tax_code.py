from tests import test_classification as stubs

app = stubs.app

def test_tax_code_accepts_valid_code():
    assert app.tax_code_is_valid("rssmra85t10a562s")

def test_tax_code_rejects_invalid_month():
    assert not app.tax_code_is_valid("RSSMRA85Z10A562S")

def test_tax_code_rejects_invalid_day():
    assert not app.tax_code_is_valid("RSSMRA85T99A562S")

def test_tax_code_rejects_wrong_checksum():
    assert not app.tax_code_is_valid("RSSMRA85T10A562A")
