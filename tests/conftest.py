import os
import tempfile

_tmp = tempfile.mkdtemp()
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_tmp}/test.db")
os.environ["LLM_PROVIDER"] = "offline"
os.environ["MEMORY_BACKEND"] = "local"
os.environ["SEED_ON_START"] = "60"
os.environ["READONLY"] = "false"
