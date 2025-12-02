import json
import sys
import types


class _DummyFlask:
    def __init__(self, *args, **kwargs):
        pass

    def route(self, *args, **kwargs):
        def decorator(func):
            return func

        return decorator

    def before_request(self, func):
        return func


class _DummyMetadata:
    def create_all(self, engine):
        return None


class _DummySelect:
    def where(self, *args, **kwargs):
        return self

    def scalar_one_or_none(self):
        return None

    def scalars(self):
        return []


class _DummySession:
    def __call__(self, *args, **kwargs):
        return self

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def begin(self):
        return self

    def add(self, *args, **kwargs):
        return None

    def delete(self, *args, **kwargs):
        return None

    def execute(self, *args, **kwargs):
        return types.SimpleNamespace(
            scalars=lambda: [], scalar_one_or_none=lambda: None
        )


# Install lightweight stubs so the module can load without external dependencies
flask_stub = types.SimpleNamespace(
    Flask=_DummyFlask,
    flash=lambda *args, **kwargs: None,
    redirect=lambda *args, **kwargs: None,
    render_template=lambda *args, **kwargs: None,
    request=types.SimpleNamespace(endpoint=None, method=None, form={}, files={}, args={},
                                  get_json=lambda: {}),
    session={},
    url_for=lambda *args, **kwargs: "",
)


def _dummy_type(*args, **kwargs):
    return None


def _dummy_column(*args, **kwargs):
    return None


def _dummy_select(*args, **kwargs):
    return _DummySelect()


def _dummy_relationship(*args, **kwargs):
    return None


def _dummy_create_engine(*args, **kwargs):
    return types.SimpleNamespace()


def _dummy_sessionmaker(**kwargs):
    return _DummySession()


def _dummy_declarative_base():
    base = type("DummyBase", (), {})
    base.metadata = _DummyMetadata()
    return base


sqlalchemy_stub = types.SimpleNamespace(
    Column=_dummy_column,
    DateTime=_dummy_type,
    ForeignKey=_dummy_type,
    Integer=_dummy_type,
    String=_dummy_type,
    create_engine=_dummy_create_engine,
    select=_dummy_select,
)
sqlalchemy_orm_stub = types.SimpleNamespace(
    declarative_base=_dummy_declarative_base,
    relationship=_dummy_relationship,
    sessionmaker=_dummy_sessionmaker,
)

requests_stub = types.SimpleNamespace(get=lambda *args, **kwargs: types.SimpleNamespace(status_code=404))
openai_stub = types.SimpleNamespace(OpenAI=lambda api_key=None: types.SimpleNamespace())

sys.modules.setdefault("flask", flask_stub)
sys.modules.setdefault("sqlalchemy", sqlalchemy_stub)
sys.modules.setdefault("sqlalchemy.orm", sqlalchemy_orm_stub)
sys.modules.setdefault("requests", requests_stub)
sys.modules.setdefault("openai", openai_stub)

import app


class DummyResponses:
    def __init__(self, capture):
        self.capture = capture

    def create(self, **kwargs):
        self.capture.update(kwargs)
        return types.SimpleNamespace(output_text="{}")


def test_classify_with_agent_passes_agent_and_prompt(monkeypatch):
    captured: dict = {}
    fake_client = types.SimpleNamespace(responses=DummyResponses(captured))

    monkeypatch.setattr(app, "openai_client", fake_client)
    monkeypatch.setattr(app, "OPENAI_AGENT_ID", "agent_123")

    result = app.classify_with_agent("prompt di prova")

    assert captured["agent_id"] == "agent_123"
    user_message = captured["input"][0]
    assert user_message["content"][0]["text"] == "prompt di prova"
    assert result.output_text == "{}"


def test_parse_classification_response_supports_output_text():
    response = types.SimpleNamespace(
        output_text=json.dumps(
            {
                "category_2_id": "123",
                "category_2_name": "Spesa",
                "category_1_name": "Alimentari",
                "reason": "Test output text",
            }
        )
    )

    parsed = app.parse_classification_response(response)

    assert parsed == {
        "category_2_id": "123",
        "category_2_name": "Spesa",
        "category_1_name": "Alimentari",
        "reason": "Test output text",
    }


def test_parse_classification_response_supports_nested_output():
    nested_response = types.SimpleNamespace(
        output=[
            types.SimpleNamespace(
                content=[
                    types.SimpleNamespace(
                        text=json.dumps(
                            {
                                "category_2_id": "456",
                                "category_2_name": "Generi",
                                "category_1_name": "Casa",
                                "reason": "Test nested output",
                            }
                        )
                    )
                ]
            )
        ]
    )

    parsed = app.parse_classification_response(nested_response)

    assert parsed == {
        "category_2_id": "456",
        "category_2_name": "Generi",
        "category_1_name": "Casa",
        "reason": "Test nested output",
    }


def test_classify_product_category_uses_agent(monkeypatch):
    prompt_holder = {}

    def fake_classify_with_agent(prompt: str):
        prompt_holder["prompt"] = prompt
        return types.SimpleNamespace(
            output_text=json.dumps(
                {
                    "category_2_id": "999",
                    "category_2_name": "Ortaggi",
                    "category_1_name": "Verdura",
                    "reason": "Test integrazione",
                }
            )
        )

    monkeypatch.setattr(app, "classify_with_agent", fake_classify_with_agent)
    monkeypatch.setattr(app, "openai_client", object())

    product = {
        "code": "ABC",
        "codice_ean": "EAN",
        "denominazione_vendita": "Prodotto di prova",
        "descrizione_marketing": "Descrizione di prova",
        "price": 1.99,
    }

    parsed = app.classify_product_category(product)

    assert json.loads(prompt_holder["prompt"]) == {
        "code": "ABC",
        "codice_ean": "EAN",
        "denominazione_vendita": "Prodotto di prova",
        "descrizione_marketing": "Descrizione di prova",
        "price": 1.99,
    }
    assert parsed == {
        "category_2_id": "999",
        "category_2_name": "Ortaggi",
        "category_1_name": "Verdura",
        "reason": "Test integrazione",
    }
