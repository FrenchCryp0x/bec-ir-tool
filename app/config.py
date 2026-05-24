import os
from pathlib import Path
from typing import Optional

CASES_DIR = Path(os.environ.get("BEC_IR_DATA", str(Path.home() / ".bec-ir" / "cases")))


class Config:
    def __init__(self):
        self.cases_dir = CASES_DIR
        self.cases_dir.mkdir(parents=True, exist_ok=True)

    def case_path(self, case_name: str) -> Path:
        safe = "".join(c for c in case_name if c.isalnum() or c in ("-", "_"))
        return self.cases_dir / f"{safe}.duckdb"

    def list_cases(self) -> list[str]:
        return sorted(p.stem for p in self.cases_dir.glob("*.duckdb"))

    def get_anthropic_key(self) -> Optional[str]:
        key = os.environ.get("ANTHROPIC_API_KEY")
        if key:
            return key
        try:
            import keyring
            return keyring.get_password("bec-ir", "anthropic_api_key")
        except Exception:
            return None

    def set_anthropic_key(self, key: str) -> bool:
        try:
            import keyring
            keyring.set_password("bec-ir", "anthropic_api_key", key)
            return True
        except Exception:
            return False


config = Config()
