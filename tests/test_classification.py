import json
import os
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

    def context_processor(self, func):
        return func

    def post(self, *args, **kwargs):
        return self.route(*args, **kwargs)


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


class _DummyConnection:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, *args, **kwargs):
        return None


class _DummyEngine:
    def begin(self):
        return _DummyConnection()


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
    return _DummyEngine()


def _dummy_inspect(*args, **kwargs):
    return types.SimpleNamespace(get_columns=lambda name: [])


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
    inspect=_dummy_inspect,
)
sqlalchemy_orm_stub = types.SimpleNamespace(
    declarative_base=_dummy_declarative_base,
    relationship=_dummy_relationship,
    sessionmaker=_dummy_sessionmaker,
)

requests_stub = types.SimpleNamespace(get=lambda *args, **kwargs: types.SimpleNamespace(status_code=404))
openai_stub = types.SimpleNamespace(OpenAI=lambda api_key=None: types.SimpleNamespace())
csrf_stub = types.SimpleNamespace(
    CSRFProtect=lambda app=None: None,
)
werkzeug_security_stub = types.SimpleNamespace(
    generate_password_hash=lambda password, method=None, salt_length=None: password,
    check_password_hash=lambda pwhash, password: pwhash == password,
)


class _DummyLimiter:
    def __init__(self, *args, **kwargs):
        pass

    def limit(self, *args, **kwargs):
        def decorator(func):
            return func

        return decorator

    def __call__(self, *args, **kwargs):
        return self


limiter_stub = types.SimpleNamespace(
    Limiter=_DummyLimiter, util=types.SimpleNamespace(get_remote_address=lambda: "127.0.0.1")
)
csrf_csrf_stub = types.SimpleNamespace(generate_csrf=lambda: "token")
defusedxml_stub = types.SimpleNamespace(ElementTree=types.SimpleNamespace(fromstring=lambda x: None))

sys.modules.setdefault("flask", flask_stub)
sys.modules.setdefault("sqlalchemy", sqlalchemy_stub)
sys.modules.setdefault("sqlalchemy.orm", sqlalchemy_orm_stub)
sys.modules.setdefault("requests", requests_stub)
sys.modules.setdefault("openai", openai_stub)
sys.modules.setdefault("flask_wtf", csrf_stub)
sys.modules.setdefault("flask_wtf.csrf", csrf_csrf_stub)
sys.modules.setdefault("flask_limiter", limiter_stub)
sys.modules.setdefault("flask_limiter.util", limiter_stub.util)
sys.modules.setdefault("defusedxml", defusedxml_stub)
sys.modules.setdefault("werkzeug.security", werkzeug_security_stub)

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import app


class DummyMessages:
    def __init__(self, capture):
        self.capture = capture
        self.data = [
            types.SimpleNamespace(
                content=[
                    types.SimpleNamespace(
                        type="text",
                        text=types.SimpleNamespace(value="{}"),
                    )
                ]
            )
        ]

    def create(self, **kwargs):
        self.capture["message_create"] = kwargs

    def list(self, **kwargs):
        self.capture["messages_list"] = kwargs
        return types.SimpleNamespace(data=self.data)


class DummyRuns:
    def __init__(self, capture):
        self.capture = capture
        self.run = types.SimpleNamespace(id="run_1", status="completed")

    def create(self, **kwargs):
        self.capture["run_create"] = kwargs
        return self.run

    def retrieve(self, **kwargs):
        self.capture.setdefault("run_retrieve", []).append(kwargs)
        return self.run


class DummyThreads:
    def __init__(self, capture):
        self.capture = capture
        self.messages = DummyMessages(capture)
        self.runs = DummyRuns(capture)

    def create(self):
        self.capture["thread_create"] = True
        return types.SimpleNamespace(id="thread_1")


class DummyBeta:
    def __init__(self, capture):
        self.threads = DummyThreads(capture)


def test_classify_with_agent_passes_agent_and_prompt(monkeypatch):
    captured: dict = {}
    fake_client = types.SimpleNamespace(beta=DummyBeta(captured))

    monkeypatch.setattr(app, "openai_client", fake_client)
    monkeypatch.setattr(app, "OPENAI_AGENT_ID", "agent_123")

    result = app.classify_with_agent("prompt di prova")

    assert captured["run_create"]["assistant_id"] == "agent_123"
    assert captured["message_create"]["content"] == "prompt di prova"
    assert captured["message_create"]["thread_id"] == "thread_1"
    assert captured["messages_list"]["thread_id"] == "thread_1"
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
