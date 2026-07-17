import argparse
import hashlib
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("nettoyeur")


@dataclass
class ScanResult:
    empty_files_removed: List[str] = field(default_factory=list)
    infected_files: List[str] = field(default_factory=list)
    clean_files: List[str] = field(default_factory=list)
    unknown_files: List[str] = field(default_factory=list)


class EmptyFileCleaner:
    """Detecte et supprime les fichiers de taille 0 dans un dossier."""

    def __init__(self, root: Path, dry_run: bool = False):
        self.root = root
        self.dry_run = dry_run

    def find_empty_files(self) -> List[Path]:
        return [
            p for p in self.root.rglob("*")
            if p.is_file() and p.stat().st_size == 0
        ]

    def clean(self) -> List[str]:
        removed = []
        for f in self.find_empty_files():
            logger.info("Fichier vide detecte: %s", f)
            if not self.dry_run:
                try:
                    f.unlink()
                    removed.append(str(f))
                except OSError as e:
                    logger.error("Impossible de supprimer %s: %s", f, e)
            else:
                removed.append(str(f))
        return removed


class HashCalculator:
    """Calcule le hash SHA-256 d'un fichier."""

    @staticmethod
    def sha256(file_path: Path, chunk_size: int = 8192) -> str:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                sha256.update(chunk)
        return sha256.hexdigest()


class VirusTotalClient:
    """Client minimal pour interroger l'API publique VirusTotal (v3)."""

    BASE_URL = "https://www.virustotal.com/api/v3/files/{hash}"

    def __init__(self, api_key: str, requests_per_min: int = 4):
        self.api_key = api_key
        self.delay = 60 / requests_per_min  # respecte la limite API gratuite

    def check_hash(self, file_hash: str) -> str:
        """Retourne 'infected', 'clean' ou 'unknown'."""
        headers = {"x-apikey": self.api_key}
        url = self.BASE_URL.format(hash=file_hash)
        try:
            resp = requests.get(url, headers=headers, timeout=15)
        except requests.RequestException as e:
            logger.error("Erreur reseau VirusTotal: %s", e)
            return "unknown"

        if resp.status_code == 404:
            return "unknown"  # jamais vu par VirusTotal
        if resp.status_code != 200:
            logger.warning("Reponse VirusTotal inattendue: %s", resp.status_code)
            return "unknown"

        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0) + stats.get("suspicious", 0)
        time.sleep(self.delay)
        return "infected" if malicious > 0 else "clean"


class FileScanner:
    """Orchestre le nettoyage des fichiers vides et le controle antivirus."""

    def __init__(self, root: str, api_key: str = "", dry_run: bool = False):
        self.root = Path(root)
        self.dry_run = dry_run
        self.cleaner = EmptyFileCleaner(self.root, dry_run)
        self.vt_client = VirusTotalClient(api_key) if api_key else None

    def run(self) -> ScanResult:
        result = ScanResult()
        result.empty_files_removed = self.cleaner.clean()

        if self.vt_client:
            for f in self.root.rglob("*"):
                if not f.is_file():
                    continue
                file_hash = HashCalculator.sha256(f)
                status = self.vt_client.check_hash(file_hash)
                if status == "infected":
                    result.infected_files.append(str(f))
                    logger.warning("MENACE DETECTEE: %s", f)
                elif status == "clean":
                    result.clean_files.append(str(f))
                else:
                    result.unknown_files.append(str(f))
        return result


def main():
    parser = argparse.ArgumentParser(description="Nettoyeur de fichiers vides + verification VirusTotal")
    parser.add_argument("folder", help="Dossier a scanner")
    parser.add_argument("--api-key", default="", help="Cle API VirusTotal (optionnel)")
    parser.add_argument("--dry-run", action="store_true", help="Simuler sans supprimer/uploader")
    args = parser.parse_args()

    if not os.path.isdir(args.folder):
        logger.error("Dossier introuvable: %s", args.folder)
        return

    scanner = FileScanner(args.folder, api_key=args.api_key, dry_run=args.dry_run)
    result = scanner.run()

    print("\n===== RESUME =====")
    print(f"Fichiers vides supprimes: {len(result.empty_files_removed)}")
    if scanner.vt_client:
        print(f"Fichiers infectes:        {len(result.infected_files)}")
        print(f"Fichiers propres:         {len(result.clean_files)}")
        print(f"Fichiers inconnus:        {len(result.unknown_files)}")


if __name__ == "__main__":
    main()
